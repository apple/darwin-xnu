/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/hidsystem/IOHITablet.h>
#include <IOKit/hidsystem/IOHITabletPointer.h>

OSDefineMetaClassAndStructors(IOHITablet, IOHIPointing);

UInt16 IOHITablet::generateTabletID()
{
    static UInt16 _nextTabletID = 0;
    return _nextTabletID++;
}

bool IOHITablet::init(OSDictionary *propTable)
{
    if (!IOHIPointing::init(propTable)) {
        return false;
    }

    _systemTabletID = generateTabletID();
    setProperty(kIOHISystemTabletID, (unsigned long long)_systemTabletID, 16);

    return true;
}

bool IOHITablet::open(IOService *client,
                      IOOptionBits options,
                      RelativePointerEventAction	rpeAction,
                      AbsolutePointerEventAction	apeAction,
                      ScrollWheelEventAction		sweAction,
                      TabletEventAction				tabletAction,
                      ProximityEventAction			proximityAction)
{
    if (!IOHIPointing::open(client, options, rpeAction, apeAction, sweAction)) {
        return false;
    }

    _tabletEventTarget = client;
    _tabletEventAction = tabletAction;
    _proximityEventTarget = client;
    _proximityEventAction = proximityAction;

    return true;
}

void IOHITablet::dispatchTabletEvent(NXEventData *tabletEvent,
                                     AbsoluteTime ts)
{
    if (_tabletEventAction) {
        (*_tabletEventAction)(_tabletEventTarget,
                            tabletEvent,
                            ts);
    }
}

void IOHITablet::dispatchProximityEvent(NXEventData *proximityEvent,
                                        AbsoluteTime ts)
{
    if (_proximityEventAction) {
        (*_proximityEventAction)(_proximityEventTarget,
                               proximityEvent,
                               ts);
    }
}

bool IOHITablet::startTabletPointer(IOHITabletPointer *pointer, OSDictionary *properties)
{
    bool result = false;

    do {
        if (!pointer)
            break;

        if (!pointer->init(properties))
            break;

        if (!pointer->attach(this))
            break;

        if (!pointer->start(this))
            break;

        result = true;
    } while (false);

    return result;
}

