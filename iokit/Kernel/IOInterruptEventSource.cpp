/*
 * Copyright (c) 1998-2010 Apple Inc. All rights reserved.
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

#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOInterrupts.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOWorkLoop.h>

#if IOKITSTATS

#define IOStatisticsInitializeCounter() \
do { \
	IOStatistics::setCounterType(IOEventSource::reserved->counter, kIOStatisticsInterruptEventSourceCounter); \
} while (0)

#define IOStatisticsCheckForWork() \
do { \
	IOStatistics::countInterruptCheckForWork(IOEventSource::reserved->counter); \
} while (0)

#define IOStatisticsInterrupt() \
do { \
	IOStatistics::countInterrupt(IOEventSource::reserved->counter); \
} while (0)

#else

#define IOStatisticsInitializeCounter()
#define IOStatisticsCheckForWork()
#define IOStatisticsInterrupt()

#endif // IOKITSTATS

#define super IOEventSource

OSDefineMetaClassAndStructors(IOInterruptEventSource, IOEventSource)
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 0);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 1);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 2);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 3);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 4);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 5);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 6);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 7);

bool IOInterruptEventSource::init(OSObject *inOwner,
				  Action inAction,
				  IOService *inProvider,
				  int inIntIndex)
{
    bool res = true;

    if ( !super::init(inOwner, (IOEventSourceAction) inAction) )
        return false;

    provider = inProvider;
    producerCount = consumerCount = 0;
    autoDisable = explicitDisable = false;
    intIndex = ~inIntIndex;

    // Assumes inOwner holds a reference(retain) on the provider
    if (inProvider) {
        res = (kIOReturnSuccess == registerInterruptHandler(inProvider, inIntIndex));
	if (res)
	    intIndex = inIntIndex;
    }

    IOStatisticsInitializeCounter();

    return res;
}

IOReturn IOInterruptEventSource::registerInterruptHandler(IOService *inProvider,
				  int inIntIndex)
{
    IOReturn ret;
    int intType;
    IOInterruptAction intHandler;

    ret = inProvider->getInterruptType(inIntIndex, &intType);
    if (kIOReturnSuccess != ret)
	return (ret);

    autoDisable = (intType == kIOInterruptTypeLevel);
    if (autoDisable) {
	intHandler = OSMemberFunctionCast(IOInterruptAction,
	    this, &IOInterruptEventSource::disableInterruptOccurred);
    }
    else
	intHandler = OSMemberFunctionCast(IOInterruptAction,
	    this, &IOInterruptEventSource::normalInterruptOccurred);

    ret = provider->registerInterrupt(inIntIndex, this, intHandler);

    return (ret);
}

IOInterruptEventSource *
IOInterruptEventSource::interruptEventSource(OSObject *inOwner,
					     Action inAction,
					     IOService *inProvider,
					     int inIntIndex)
{
    IOInterruptEventSource *me = new IOInterruptEventSource;

    if (me && !me->init(inOwner, inAction, inProvider, inIntIndex)) {
        me->release();
        return 0;
    }

    return me;
}

void IOInterruptEventSource::free()
{
    if (provider && intIndex >= 0)
        provider->unregisterInterrupt(intIndex);

    super::free();
}

void IOInterruptEventSource::enable()
{
    if (provider && intIndex >= 0) {
        provider->enableInterrupt(intIndex);
        explicitDisable = false;
        enabled = true;
    }
}

void IOInterruptEventSource::disable()
{
    if (provider && intIndex >= 0) {
        provider->disableInterrupt(intIndex);
        explicitDisable = true;
        enabled = false;
    }
}

void IOInterruptEventSource::setWorkLoop(IOWorkLoop *inWorkLoop)
{
    super::setWorkLoop(inWorkLoop);

    if (!provider)
    	return;

    if ( !inWorkLoop ) {
	if (intIndex >= 0) {
	    provider->unregisterInterrupt(intIndex);
	    intIndex = ~intIndex;
	}
    } else if ((intIndex < 0) && (kIOReturnSuccess == registerInterruptHandler(provider, ~intIndex))) {
	intIndex = ~intIndex;
    }
}

const IOService *IOInterruptEventSource::getProvider() const
{
    return provider;
}

int IOInterruptEventSource::getIntIndex() const
{
    return intIndex;
}

bool IOInterruptEventSource::getAutoDisable() const
{
    return autoDisable;
}

bool IOInterruptEventSource::checkForWork()
{
    unsigned int cacheProdCount = producerCount;
    int numInts = cacheProdCount - consumerCount;
    IOInterruptEventAction intAction = (IOInterruptEventAction) action;
	bool trace = (gIOKitTrace & kIOTraceIntEventSource) ? true : false;
	
    IOStatisticsCheckForWork();
	
	if ( numInts > 0 )
	{
		if (trace)
			IOTimeStampStartConstant(IODBG_INTES(IOINTES_ACTION),
									 (uintptr_t) intAction, (uintptr_t) owner, (uintptr_t) this, (uintptr_t) workLoop);
		
		// Call the handler
		(*intAction)(owner, this, numInts);
		
		if (trace)
			IOTimeStampEndConstant(IODBG_INTES(IOINTES_ACTION),
								   (uintptr_t) intAction, (uintptr_t) owner, (uintptr_t) this, (uintptr_t) workLoop);
		
		consumerCount = cacheProdCount;
		if (autoDisable && !explicitDisable)
			enable();
	}
	
	else if ( numInts < 0 )
	{
		if (trace)
			IOTimeStampStartConstant(IODBG_INTES(IOINTES_ACTION),
									 (uintptr_t) intAction, (uintptr_t) owner, (uintptr_t) this, (uintptr_t) workLoop);
		
		// Call the handler
		(*intAction)(owner, this, -numInts);
		
		if (trace)
			IOTimeStampEndConstant(IODBG_INTES(IOINTES_ACTION),
								   (uintptr_t) intAction, (uintptr_t) owner, (uintptr_t) this, (uintptr_t) workLoop);
		
		consumerCount = cacheProdCount;
		if (autoDisable && !explicitDisable)
			enable();
	}
	
    return false;
}

void IOInterruptEventSource::normalInterruptOccurred
    (void */*refcon*/, IOService */*prov*/, int /*source*/)
{
	bool trace = (gIOKitTrace & kIOTraceIntEventSource) ? true : false;
	
    IOStatisticsInterrupt();
    producerCount++;
	
	if (trace)
	    IOTimeStampStartConstant(IODBG_INTES(IOINTES_SEMA), (uintptr_t) this, (uintptr_t) owner);
	
    signalWorkAvailable();
	
	if (trace)
	    IOTimeStampEndConstant(IODBG_INTES(IOINTES_SEMA), (uintptr_t) this, (uintptr_t) owner);
}

void IOInterruptEventSource::disableInterruptOccurred
    (void */*refcon*/, IOService *prov, int source)
{
	bool trace = (gIOKitTrace & kIOTraceIntEventSource) ? true : false;
	
    prov->disableInterrupt(source);	/* disable the interrupt */
	
    IOStatisticsInterrupt();
    producerCount++;
	
	if (trace)
	    IOTimeStampStartConstant(IODBG_INTES(IOINTES_SEMA), (uintptr_t) this, (uintptr_t) owner);
    
    signalWorkAvailable();
	
	if (trace)
	    IOTimeStampEndConstant(IODBG_INTES(IOINTES_SEMA), (uintptr_t) this, (uintptr_t) owner);
}

void IOInterruptEventSource::interruptOccurred
    (void *refcon, IOService *prov, int source)
{
    if (autoDisable && prov)
        disableInterruptOccurred(refcon, prov, source);
    else
        normalInterruptOccurred(refcon, prov, source);
}

IOReturn IOInterruptEventSource::warmCPU
    (uint64_t abstime)
{

	return ml_interrupt_prewarm(abstime);
}
