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
#ifndef _IOHITABLET_H
#define _IOHITABLET_H

#include <IOKit/hidsystem/IOHIPointing.h>
#include <IOKit/hidsystem/IOLLEvent.h>

class IOHITabletPointer;

#define kIOHIVendorID		"VendorID"
#define kIOHISystemTabletID	"SystemTabletID"
#define kIOHIVendorTabletID	"VendorTabletID"

typedef void (*TabletEventAction)(OSObject		*target,
                                  NXEventData	*tabletData,	// Do we want to parameterize this?
                                  AbsoluteTime ts);

typedef void (*ProximityEventAction)(OSObject		*target,
                                     NXEventData	*proximityData,	// or this?
                                     AbsoluteTime ts);
                                  
class IOHITablet : public IOHIPointing
{
    OSDeclareDefaultStructors(IOHITablet);

public:
    UInt16		_systemTabletID;

private:
    OSObject *				_tabletEventTarget;
    TabletEventAction		_tabletEventAction;
    OSObject *				_proximityEventTarget;
    ProximityEventAction	_proximityEventAction;

protected:
    virtual void dispatchTabletEvent(NXEventData *tabletEvent,
                                     AbsoluteTime ts);

    virtual void dispatchProximityEvent(NXEventData *proximityEvent,
                                        AbsoluteTime ts);

    virtual bool startTabletPointer(IOHITabletPointer *pointer, OSDictionary *properties);

public:
    static UInt16 generateTabletID();

    virtual bool init(OSDictionary * propTable);
    virtual bool open(IOService *	client,
                      IOOptionBits	options,
                      RelativePointerEventAction	rpeAction,
                      AbsolutePointerEventAction	apeAction,
                      ScrollWheelEventAction		sweAction,
                      TabletEventAction			tabletAction,
                      ProximityEventAction		proximityAction);

};

#endif /* !_IOHITABLET_H */
