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
#include <IOKit/hidsystem/IOHITabletPointer.h>

OSDefineMetaClassAndStructors(IOHITabletPointer, IOHIDevice)

UInt16 IOHITabletPointer::generateDeviceID()
{
    static _nextDeviceID = 0;
    return _nextDeviceID++;
}

bool IOHITabletPointer::init( OSDictionary *propTable )
{
    if (!IOHIDevice::init(propTable)) {
        return false;
    }

    _deviceID = generateDeviceID();
    setProperty(kIOHITabletPointerDeviceID, (unsigned long long)_deviceID, 16);

    return true;
}

bool IOService::attach( IOService * provider )
{
    if (!IOHIDevice::attach(provider)) {
        return false;
    }

    _tablet = OSDynamicCast(IOHITablet, provider);

    return true;
}

void IOHITabletPointer::dispatchTabletEvent(NXEventData *tabletEvent,
                                            AbsoluteTime ts)
{
    if (_tablet) {
        _tablet->dispatchTabletEvent(tabletEvent, ts);
    }
}

void IOHITabletPointer::dispatchProximityEvent(NXEventData *proximityEvent,
                                               AbsoluteTime ts)
{
    if (_tablet) {
        _tablet->dispatchProximityEvent(proximityEvent, ts);
    }
}
