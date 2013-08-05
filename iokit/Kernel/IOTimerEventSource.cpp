/*
 * Copyright (c) 1998-2000, 2009-2010 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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
#include <IOKit/IOKitDebug.h>

#if CONFIG_DTRACE
#include <mach/sdt.h>
#endif

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

#if IOKITSTATS

#define IOStatisticsInitializeCounter() \
do { \
	IOStatistics::setCounterType(IOEventSource::reserved->counter, kIOStatisticsTimerEventSourceCounter); \
} while (0)

#define IOStatisticsOpenGate() \
do { \
	IOStatistics::countOpenGate(me->IOEventSource::reserved->counter); \
} while (0)

#define IOStatisticsCloseGate() \
do { \
	IOStatistics::countCloseGate(me->IOEventSource::reserved->counter); \
} while (0)

#define IOStatisticsTimeout() \
do { \
	IOStatistics::countTimerTimeout(me->IOEventSource::reserved->counter); \
} while (0)

#else

#define IOStatisticsInitializeCounter()
#define IOStatisticsOpenGate()
#define IOStatisticsCloseGate()
#define IOStatisticsTimeout()

#endif /* IOKITSTATS */

// 
// reserved != 0 means IOTimerEventSource::timeoutAndRelease is being used,
// not a subclassed implementation. 
//

// Timeout handler function. This function is called by the kernel when
// the timeout interval expires.
//
void IOTimerEventSource::timeout(void *self)
{
    IOTimerEventSource *me = (IOTimerEventSource *) self;

    IOStatisticsTimeout();

    if (me->enabled && me->action)
    {
        IOWorkLoop *
        wl = me->workLoop;
        if (wl)
        {
            Action doit;
            wl->closeGate();
            IOStatisticsCloseGate();
            doit = (Action) me->action;
            if (doit && me->enabled && AbsoluteTime_to_scalar(&me->abstime))
            {
            	bool    trace = (gIOKitTrace & kIOTraceTimers) ? true : false;
            	
            	if (trace)
                	IOTimeStampStartConstant(IODBG_TIMES(IOTIMES_ACTION),
											 (uintptr_t) doit, (uintptr_t) me->owner);
				
                (*doit)(me->owner, me);
#if CONFIG_DTRACE
		DTRACE_TMR3(iotescallout__expire, Action, doit, OSObject, me->owner, void, me->workLoop);
#endif
                
				if (trace)
                	IOTimeStampEndConstant(IODBG_TIMES(IOTIMES_ACTION),
										   (uintptr_t) doit, (uintptr_t) me->owner);
            }
            IOStatisticsOpenGate();
            wl->openGate();
        }
    }
}

void IOTimerEventSource::timeoutAndRelease(void * self, void * c)
{
    IOTimerEventSource *me = (IOTimerEventSource *) self;
	/* The second parameter (a pointer) gets abused to carry an SInt32, so on LP64, "count"
	   must be cast to "long" before, in order to tell GCC we're not truncating a pointer. */
	SInt32 count = (SInt32) (long) c;

    IOStatisticsTimeout();
	
    if (me->enabled && me->action)
    {
        IOWorkLoop *
        wl = me->reserved->workLoop;
        if (wl)
        {
            Action doit;
            wl->closeGate();
            IOStatisticsCloseGate();
            doit = (Action) me->action;
            if (doit && (me->reserved->calloutGeneration == count))
            {
            	bool    trace = (gIOKitTrace & kIOTraceTimers) ? true : false;
            	
            	if (trace)
                	IOTimeStampStartConstant(IODBG_TIMES(IOTIMES_ACTION),
											 (uintptr_t) doit, (uintptr_t) me->owner);
				
                (*doit)(me->owner, me);
#if CONFIG_DTRACE
		DTRACE_TMR3(iotescallout__expire, Action, doit, OSObject, me->owner, void, me->workLoop);
#endif
                
				if (trace)
                	IOTimeStampEndConstant(IODBG_TIMES(IOTIMES_ACTION),
										   (uintptr_t) doit, (uintptr_t) me->owner);
            }
            IOStatisticsOpenGate();
            wl->openGate();
        }
    }

    me->reserved->workLoop->release();
    me->release();
}

void IOTimerEventSource::setTimeoutFunc()
{
    // reserved != 0 means IOTimerEventSource::timeoutAndRelease is being used,
    // not a subclassed implementation
    reserved = IONew(ExpansionData, 1);
    calloutEntry = (void *) thread_call_allocate((thread_call_func_t) &IOTimerEventSource::timeoutAndRelease,
                                                 (thread_call_param_t) this);
}

bool IOTimerEventSource::init(OSObject *inOwner, Action inAction)
{
    if (!super::init(inOwner, (IOEventSource::Action) inAction) )
        return false;

    setTimeoutFunc();
    if (!calloutEntry)
        return false;

    IOStatisticsInitializeCounter();

    return true;
}

IOTimerEventSource *
IOTimerEventSource::timerEventSource(OSObject *inOwner, Action inAction)
{
    IOTimerEventSource *me = new IOTimerEventSource;

    if (me && !me->init(inOwner, inAction)) {
        me->release();
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

    if (reserved)
        IODelete(reserved, ExpansionData, 1);

    super::free();
}

void IOTimerEventSource::cancelTimeout()
{
    if (reserved)
        reserved->calloutGeneration++;
    bool active = thread_call_cancel((thread_call_t) calloutEntry);
    AbsoluteTime_to_scalar(&abstime) = 0;
    if (active && reserved)
    {
        release();
        workLoop->release();
    }
}

void IOTimerEventSource::enable()
{
    super::enable();
    if (kIOReturnSuccess != wakeAtTime(abstime))
        super::disable(); // Problem re-scheduling timeout ignore enable
}

void IOTimerEventSource::disable()
{
    if (reserved)
        reserved->calloutGeneration++;
    bool active = thread_call_cancel((thread_call_t) calloutEntry);
    super::disable();
    if (active && reserved)
    {
        release();
        workLoop->release();
    }
}

IOReturn IOTimerEventSource::setTimeoutTicks(UInt32 ticks)
{
    return setTimeout(ticks, kTickScale);
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

#if !defined(__LP64__)
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
#endif

IOReturn IOTimerEventSource::setTimeout(AbsoluteTime interval)
{
    AbsoluteTime end;

    clock_get_uptime(&end);
    ADD_ABSOLUTETIME(&end, &interval);

    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::wakeAtTimeTicks(UInt32 ticks)
{
    return wakeAtTime(ticks, kTickScale);
}

IOReturn IOTimerEventSource::wakeAtTimeMS(UInt32 ms)
{
    return wakeAtTime(ms, kMillisecondScale);
}

IOReturn IOTimerEventSource::wakeAtTimeUS(UInt32 us)
{
    return wakeAtTime(us, kMicrosecondScale);
}

IOReturn IOTimerEventSource::wakeAtTime(UInt32 inAbstime, UInt32 scale_factor)
{
    AbsoluteTime end;
    clock_interval_to_absolutetime_interval(inAbstime, scale_factor, &end);

    return wakeAtTime(end);
}

#if !defined(__LP64__)
IOReturn IOTimerEventSource::wakeAtTime(mach_timespec_t inAbstime)
{
    AbsoluteTime end, nsecs;

    clock_interval_to_absolutetime_interval
        (inAbstime.tv_nsec, kNanosecondScale, &nsecs);
    clock_interval_to_absolutetime_interval
        (inAbstime.tv_sec, kSecondScale, &end);
    ADD_ABSOLUTETIME(&end, &nsecs);

    return wakeAtTime(end);
}
#endif

void IOTimerEventSource::setWorkLoop(IOWorkLoop *inWorkLoop)
{
    super::setWorkLoop(inWorkLoop);
    if ( enabled && AbsoluteTime_to_scalar(&abstime) && workLoop )
        wakeAtTime(abstime);
}

IOReturn IOTimerEventSource::wakeAtTime(AbsoluteTime inAbstime)
{
    if (!action)
        return kIOReturnNoResources;

    abstime = inAbstime;
    if ( enabled && AbsoluteTime_to_scalar(&inAbstime) && AbsoluteTime_to_scalar(&abstime) && workLoop )
    {
        if (reserved)
        {
            retain();
            workLoop->retain();
            reserved->workLoop = workLoop;
            reserved->calloutGeneration++;
            if (thread_call_enter1_delayed((thread_call_t) calloutEntry, 
                    (void *) reserved->calloutGeneration, inAbstime))
            {
                release();
                workLoop->release();
            }
        }
        else
            thread_call_enter_delayed((thread_call_t) calloutEntry, inAbstime);
    }

    return kIOReturnSuccess;
}
