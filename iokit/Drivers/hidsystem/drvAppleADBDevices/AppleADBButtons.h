#ifndef _APPLEADBBUTTONS_H
#define _APPLEADBBUTTONS_H

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

#include <IOKit/hidsystem/IOHIKeyboard.h>
#include <IOKit/adb/IOADBDevice.h>

#define kVolume_up	0x06
#define kVolume_down	0x07
#define kMute		0x08
#define kVolume_up_AV	0x03  //Apple ADB AV monitors have different button codes
#define kVolume_down_AV	0x02
#define kMute_AV	0x01
#define kBrightness_up	0x09
#define kBrightness_down	0x0a
#define kEject		0x0b
#define kNum_lock_on_laptops	0x7f

#define kMax_registrations 10
#define	kMax_keycode	0x0a
#define kNullKey	0xFF

typedef void (*button_handler)(void * );

class AppleADBButtons :  public IOHIKeyboard
{
    OSDeclareDefaultStructors(AppleADBButtons)

private:

    unsigned int	keycodes[kMax_registrations];
    void *		registrants[kMax_registrations];
    button_handler	downHandlers[kMax_registrations];

    void dispatchButtonEvent (unsigned int, bool );
    UInt32		_initial_handler_id;

public:

    const unsigned char * defaultKeymapOfLength (UInt32 * length );
    UInt32 interfaceID();
    UInt32 deviceType();
    UInt64 getGUID();

public:

     IOService * displayManager;			// points to display manager
    IOADBDevice *	adbDevice;

    bool start ( IOService * theNub );
    IOReturn packet (UInt8 * data, IOByteCount length, UInt8 adbCommand );
    IOReturn registerForButton ( unsigned int, IOService *, button_handler, bool );

    IOReturn setParamProperties(OSDictionary *dict);
};

#endif /* _APPLEADBBUTTONS_H */
