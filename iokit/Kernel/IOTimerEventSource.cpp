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

#include <libkern/Block.h>


#define super IOEventSource
OSDefineMetaClassAndStructors(IOTimerEventSource, IOEventSource)
OSMetaClassDefineReservedUsed(IOTimerEventSource, 0);
OSMetaClassDefineReservedUsed(IOTimerEventSource, 1);
OSMetaClassDefineReservedUsed(IOTimerEventSource, 2);
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

__inline__ void
IOTimerEventSource::invokeAction(IOTimerEventSource::Action action, IOTimerEventSource * ts,
	     OSObject * owner, IOWorkLoop * workLoop)
{
    bool    trace = (gIOKitTrace & kIOTraceTimers) ? true : false;

    if (trace)
	IOTimeStampStartConstant(IODBG_TIMES(IOTIMES_ACTION),
				 VM_KERNEL_ADDRHIDE(action), VM_KERNEL_ADDRHIDE(owner));

    if (kActionBlock & flags) ((IOTimerEventSource::ActionBlock) actionBlock)(ts);
    else                      (*action)(owner, ts);

#if CONFIG_DTRACE
    DTRACE_TMR3(iotescallout__expire, Action, action, OSObject, owner, void, workLoop);
#endif

    if (trace)
	IOTimeStampEndConstant(IODBG_TIMES(IOTIMES_ACTION),
			       VM_KERNEL_UNSLIDE(action), VM_KERNEL_ADDRHIDE(owner));
}

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
                me->invokeAction(doit, me, me->owner, me->workLoop);
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
                me->invokeAction(doit, me, me->owner, me->workLoop);
            }
            IOStatisticsOpenGate();
            wl->openGate();
        }
    }

    me->reserved->workLoop->release();
    me->release();
}

// -- work loop delivery

bool IOTimerEventSource::checkForWork()
{
    Action doit;

    if (reserved
     && (reserved->calloutGenerationSignaled == reserved->calloutGeneration)
     && enabled && (doit = (Action) action))
    {
	reserved->calloutGenerationSignaled = ~reserved->calloutGeneration;
	invokeAction(doit, this, owner, workLoop);
    }

    return false;
}

void IOTimerEventSource::timeoutSignaled(void * self, void * c)
{
    IOTimerEventSource *me = (IOTimerEventSource *) self;

    me->reserved->calloutGenerationSignaled = (SInt32)(long) c;
    if (me->enabled) me->signalWorkAvailable();
}

// --

void IOTimerEventSource::setTimeoutFunc()
{
    thread_call_priority_t pri;
    uint32_t options;

    if (reserved) panic("setTimeoutFunc already %p, %p", this, reserved);

    // reserved != 0 means IOTimerEventSource::timeoutAndRelease is being used,
    // not a subclassed implementation
    reserved = IONew(ExpansionData, 1);
    reserved->calloutGenerationSignaled = ~reserved->calloutGeneration;
    options = abstime;
    abstime = 0;

    thread_call_options_t tcoptions = 0;
    thread_call_func_t    func      = NULL;

    switch (kIOTimerEventSourceOptionsPriorityMask & options)
    {
      case kIOTimerEventSourceOptionsPriorityHigh:
        pri = THREAD_CALL_PRIORITY_HIGH;
        func = &IOTimerEventSource::timeoutAndRelease;
        break;

      case kIOTimerEventSourceOptionsPriorityKernel:
        pri = THREAD_CALL_PRIORITY_KERNEL;
        func = &IOTimerEventSource::timeoutAndRelease;
        break;

      case kIOTimerEventSourceOptionsPriorityKernelHigh:
        pri = THREAD_CALL_PRIORITY_KERNEL_HIGH;
        func = &IOTimerEventSource::timeoutAndRelease;
        break;

      case kIOTimerEventSourceOptionsPriorityUser:
        pri = THREAD_CALL_PRIORITY_USER;
        func = &IOTimerEventSource::timeoutAndRelease;
        break;

      case kIOTimerEventSourceOptionsPriorityLow:
        pri = THREAD_CALL_PRIORITY_LOW;
        func = &IOTimerEventSource::timeoutAndRelease;
        break;

      case kIOTimerEventSourceOptionsPriorityWorkLoop:
        pri = THREAD_CALL_PRIORITY_KERNEL;
        tcoptions |= THREAD_CALL_OPTIONS_SIGNAL;
        if (kIOTimerEventSourceOptionsAllowReenter & options) break;
        func = &IOTimerEventSource::timeoutSignaled;
        break;

      default:
        break;
    }

    assertf(func, "IOTimerEventSource options 0x%x", options);
    if (!func) return;		                                     // init will fail

    if (THREAD_CALL_OPTIONS_SIGNAL & tcoptions) flags |= kActive;
    else                                        flags |= kPassive;

    if (!(kIOTimerEventSourceOptionsAllowReenter & options)) tcoptions |= THREAD_CALL_OPTIONS_ONCE;

    calloutEntry = (void *) thread_call_allocate_with_options(func,
        (thread_call_param_t) this, pri, tcoptions);
    assert(calloutEntry);
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

bool IOTimerEventSource::init(uint32_t options, OSObject *inOwner, Action inAction)
{
    abstime = options;
    return (init(inOwner, inAction));
}

IOTimerEventSource *
IOTimerEventSource::timerEventSource(uint32_t inOptions, OSObject *inOwner, Action inAction)
{
    IOTimerEventSource *me = new IOTimerEventSource;

    if (me && !me->init(inOptions, inOwner, inAction)) {
        me->release();
        return 0;
    }

    return me;
}

IOTimerEventSource *
IOTimerEventSource::timerEventSource(uint32_t options, OSObject *inOwner, ActionBlock action)
{
    IOTimerEventSource * tes;
    tes = IOTimerEventSource::timerEventSource(options, inOwner, (Action) NULL);
    if (tes) tes->setActionBlock((IOEventSource::ActionBlock) action);

    return tes;
}

#define _thread_call_cancel(tc)   ((kActive & flags) ? thread_call_cancel_wait((tc)) : thread_call_cancel((tc)))

IOTimerEventSource *
IOTimerEventSource::timerEventSource(OSObject *inOwner, Action inAction)
{
    return (IOTimerEventSource::timerEventSource(
                kIOTimerEventSourceOptionsPriorityKernelHigh,
                inOwner, inAction));
}

void IOTimerEventSource::free()
{
    if (calloutEntry) {
        __assert_only bool freed;

        cancelTimeout();

        freed = thread_call_free((thread_call_t) calloutEntry);
        assert(freed);
    }

    if (reserved)
        IODelete(reserved, ExpansionData, 1);

    super::free();
}

void IOTimerEventSource::cancelTimeout()
{
    if (reserved)
        reserved->calloutGeneration++;
    bool active = _thread_call_cancel((thread_call_t) calloutEntry);
    AbsoluteTime_to_scalar(&abstime) = 0;
    if (active && reserved && (kPassive & flags))
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
    bool active = _thread_call_cancel((thread_call_t) calloutEntry);
    super::disable();
    if (active && reserved && (kPassive & flags))
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
    clock_absolutetime_interval_to_deadline(interval, &end);
    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::setTimeout(uint32_t options,
					AbsoluteTime abstime, AbsoluteTime leeway)
{
    AbsoluteTime end;
    if (options & kIOTimeOptionsContinuous)
        clock_continuoustime_interval_to_deadline(abstime, &end);
    else
        clock_absolutetime_interval_to_deadline(abstime, &end);

    return wakeAtTime(options, end, leeway);
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
    return wakeAtTime(0, inAbstime, 0);
}

IOReturn IOTimerEventSource::wakeAtTime(uint32_t options, AbsoluteTime inAbstime, AbsoluteTime leeway)
{
    if (!action)
        return kIOReturnNoResources;

    abstime = inAbstime;
    if ( enabled && AbsoluteTime_to_scalar(&inAbstime) && AbsoluteTime_to_scalar(&abstime) && workLoop )
    {
        uint32_t tcoptions = 0;

        if (kIOTimeOptionsWithLeeway & options) tcoptions |= THREAD_CALL_DELAY_LEEWAY;
        if (kIOTimeOptionsContinuous & options) tcoptions |= THREAD_CALL_CONTINUOUS;

        if (reserved)
        {
	    if (kPassive & flags)
	    {
		retain();
		workLoop->retain();
	    }
            reserved->workLoop = workLoop;
            reserved->calloutGeneration++;
            if (thread_call_enter_delayed_with_leeway((thread_call_t) calloutEntry,
                    (void *)(uintptr_t) reserved->calloutGeneration, inAbstime, leeway, tcoptions)
              && (kPassive & flags))
            {
                release();
                workLoop->release();
            }
        }
        else
        {
            thread_call_enter_delayed_with_leeway((thread_call_t) calloutEntry,
                    NULL, inAbstime, leeway, tcoptions);
        }
    }

    return kIOReturnSuccess;
}
