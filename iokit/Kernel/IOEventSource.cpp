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
]*/
#include <IOKit/IOLib.h>

#include <IOKit/IOEventSource.h>
#include <IOKit/IOWorkLoop.h>

#define super OSObject

OSDefineMetaClassAndAbstractStructors(IOEventSource, OSObject)
OSMetaClassDefineReservedUnused(IOEventSource, 0);
OSMetaClassDefineReservedUnused(IOEventSource, 1);
OSMetaClassDefineReservedUnused(IOEventSource, 2);
OSMetaClassDefineReservedUnused(IOEventSource, 3);
OSMetaClassDefineReservedUnused(IOEventSource, 4);
OSMetaClassDefineReservedUnused(IOEventSource, 5);
OSMetaClassDefineReservedUnused(IOEventSource, 6);
OSMetaClassDefineReservedUnused(IOEventSource, 7);

/* inline function implementations */
void IOEventSource::signalWorkAvailable()	{ workLoop->signalWorkAvailable(); }
void IOEventSource::openGate()			{ workLoop->openGate(); }
void IOEventSource::closeGate()			{ workLoop->closeGate(); }
bool IOEventSource::tryCloseGate()		{ return workLoop->tryCloseGate(); }
int IOEventSource::sleepGate(void *event, UInt32 type)
        { return workLoop->sleepGate(event, type); }
void IOEventSource::wakeupGate(void *event, bool oneThread)
        { workLoop->wakeupGate(event, oneThread); }

bool IOEventSource::init(OSObject *inOwner,
                         Action inAction = 0)
{
    if (!inOwner)
        return false;

    owner = inOwner;

    if ( !super::init() )
        return false;

    (void) setAction(inAction);
    enabled = true;

    return true;
}

IOEventSource::Action IOEventSource::getAction () const { return action; };

void IOEventSource::setAction(Action inAction)
{
    action = inAction;
}

IOEventSource *IOEventSource::getNext() const { return eventChainNext; };

void IOEventSource::setNext(IOEventSource *inNext)
{
    eventChainNext = inNext;
}

void IOEventSource::enable()
{
    enabled = true;
    if (workLoop)
        return signalWorkAvailable();
}

void IOEventSource::disable()
{
    enabled = false;
}

bool IOEventSource::isEnabled() const
{
    return enabled;
}

void IOEventSource::setWorkLoop(IOWorkLoop *inWorkLoop)
{
    if ( !inWorkLoop )
        disable();
    workLoop = inWorkLoop;
}

IOWorkLoop *IOEventSource::getWorkLoop() const
{
    return workLoop;
}

bool IOEventSource::onThread() const
{
    return (workLoop != 0) && workLoop->onThread();
}
