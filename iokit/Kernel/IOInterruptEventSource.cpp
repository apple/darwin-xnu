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
Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.

HISTORY
    1998-7-13	Godfrey van der Linden(gvdl)
        Created.
*/
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOInterrupts.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOWorkLoop.h>

#if KDEBUG

#define IOTimeTypeStampS(t)						\
do {									\
    IOTimeStampStart(IODBG_INTES(t),					\
                     (unsigned int) this, (unsigned int) owner);	\
} while(0)

#define IOTimeTypeStampE(t)						\
do {									\
    IOTimeStampEnd(IODBG_INTES(t),					\
                   (unsigned int) this, (unsigned int) owner);		\
} while(0)

#define IOTimeStampLatency()						\
do {									\
    IOTimeStampEnd(IODBG_INTES(IOINTES_LAT),				\
                   (unsigned int) this, (unsigned int) owner);		\
} while(0)

#else /* !KDEBUG */
#define IOTimeTypeStampS(t)
#define IOTimeTypeStampE(t)
#define IOTimeStampLatency()
#endif /* KDEBUG */

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
				  Action inAction = 0,
				  IOService *inProvider = 0,
				  int inIntIndex = 0)
{
    bool res = true;

    if ( !super::init(inOwner, (IOEventSourceAction) inAction) )
        return false;

    provider = inProvider;
    producerCount = consumerCount = 0;
    autoDisable = explicitDisable = false;
    intIndex = -1;

    // Assumes inOwner holds a reference(retain) on the provider
    if (inProvider) {
        int intType;

        res = (kIOReturnSuccess
                    == inProvider->getInterruptType(inIntIndex, &intType));
        if (res) {
            IOInterruptAction intHandler;

            autoDisable = (intType == kIOInterruptTypeLevel);
            if (autoDisable) {
                intHandler = (IOInterruptAction)
                &IOInterruptEventSource::disableInterruptOccurred;
            }
            else
                intHandler = (IOInterruptAction)
                    &IOInterruptEventSource::normalInterruptOccurred;

            res = (kIOReturnSuccess == inProvider->registerInterrupt
                                        (inIntIndex, this, intHandler));
            if (res)
                intIndex = inIntIndex;
        }
    }

    return res;
}

IOInterruptEventSource *
IOInterruptEventSource::interruptEventSource(OSObject *inOwner,
					     Action inAction,
					     IOService *inProvider,
					     int inIntIndex)
{
    IOInterruptEventSource *me = new IOInterruptEventSource;

    if (me && !me->init(inOwner, inAction, inProvider, inIntIndex)) {
        me->free();
        return 0;
    }

    return me;
}

void IOInterruptEventSource::free()
{
    if (provider && intIndex != -1)
        provider->unregisterInterrupt(intIndex);

    super::free();
}

void IOInterruptEventSource::enable()
{
    if (provider && intIndex != -1) {
        provider->enableInterrupt(intIndex);
        explicitDisable = false;
    }
}

void IOInterruptEventSource::disable()
{
    if (provider && intIndex != -1) {
        provider->disableInterrupt(intIndex);
        explicitDisable = true;
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

    if (numInts > 0) {

        IOTimeStampLatency();
        IOTimeTypeStampS(IOINTES_CLIENT);
            IOTimeStampConstant(IODBG_INTES(IOINTES_ACTION),
                                (unsigned int) intAction, (unsigned int) owner);
            (*intAction)(owner, this,  numInts);
        IOTimeTypeStampE(IOINTES_CLIENT);

        consumerCount = cacheProdCount;
        if (autoDisable && !explicitDisable)
            enable();
    }
    else if (numInts < 0) {
        IOTimeStampLatency();
        IOTimeTypeStampS(IOINTES_CLIENT);
            IOTimeStampConstant(IODBG_INTES(IOINTES_ACTION),
                                (unsigned int) intAction, (unsigned int) owner);
             (*intAction)(owner, this, -numInts);
        IOTimeTypeStampE(IOINTES_CLIENT);
    
        consumerCount = cacheProdCount;
        if (autoDisable && !explicitDisable)
            enable();
    }

    return false;
}

void IOInterruptEventSource::normalInterruptOccurred
    (void */*refcon*/, IOService */*prov*/, int /*source*/)
{
IOTimeTypeStampS(IOINTES_INTCTXT);
IOTimeStampLatency();

    producerCount++;

IOTimeTypeStampS(IOINTES_SEMA);
    signalWorkAvailable();
IOTimeTypeStampE(IOINTES_SEMA);

IOTimeTypeStampE(IOINTES_INTCTXT);
}

void IOInterruptEventSource::disableInterruptOccurred
    (void */*refcon*/, IOService *prov, int source)
{
IOTimeTypeStampS(IOINTES_INTCTXT);
IOTimeStampLatency();

    prov->disableInterrupt(source);	/* disable the interrupt */

    producerCount++;

IOTimeTypeStampS(IOINTES_SEMA);
    signalWorkAvailable();
IOTimeTypeStampE(IOINTES_SEMA);

IOTimeTypeStampE(IOINTES_INTCTXT);
}

void IOInterruptEventSource::interruptOccurred
    (void *refcon, IOService *prov, int source)
{
    if (autoDisable && prov)
        disableInterruptOccurred(refcon, prov, source);
    else
        normalInterruptOccurred(refcon, prov, source);
}
