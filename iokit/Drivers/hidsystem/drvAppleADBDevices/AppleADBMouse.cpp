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
 * 18 June 1998 	  Start IOKit version.
 * 18 Nov  1998 suurballe port to C++
 *  4 Oct  1999 decesare  Revised for Type 4 support and sub-classed drivers.
 *  1 Feb  2000 tsherman  Added extended mouse functionality (implemented in setParamProperties)
 */

#include "AppleADBMouse.h"
#include <IOKit/hidsystem/IOHIDTypes.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>

// Globals to remember enhanced trackpad values @ sleep and restore @ wake.
UInt8 glob_clicking = 0x19;			    
UInt8 glob_dragging = 0x14;
UInt8 glob_draglock = 0xB2;

// ****************************************************************************
// NewMouseData
//
// ****************************************************************************
static void NewMouseData(IOService * target, UInt8 adbCommand, IOByteCount length, UInt8 * data)
{
  ((AppleADBMouse *)target)->packet(adbCommand, length, data);
}


// ****************************************************************************

#undef super
#define super IOHIPointing

OSDefineMetaClassAndStructors(AppleADBMouse, IOHIPointing);


// ****************************************************************************
// probe
//
// ****************************************************************************
IOService * AppleADBMouse::probe(IOService * provider, SInt32 * score)
{
  adbDevice = (IOADBDevice *)provider;
  
  return this;
}


// ****************************************************************************
// start
//
// ****************************************************************************
bool AppleADBMouse::start(IOService * provider)
{
  if(!super::start(provider)) return false;
  
  if(!adbDevice->seizeForClient(this, NewMouseData)) {
    IOLog("%s: Seize failed\n", getName());
    return false;
  }
  
  return true;
}


// ****************************************************************************
// interfaceID
//
// ****************************************************************************
UInt32 AppleADBMouse::interfaceID(void)
{
  return NX_EVS_DEVICE_INTERFACE_ADB;
}


// ****************************************************************************
// deviceType
//
// ****************************************************************************
UInt32 AppleADBMouse::deviceType ( void )
{
  return adbDevice->handlerID();
}


// ****************************************************************************
// resolution
//
// ****************************************************************************
IOFixed AppleADBMouse::resolution(void)
{
  return _resolution;
}


// ****************************************************************************
// buttonCount
//
// ****************************************************************************
IOItemCount AppleADBMouse::buttonCount(void)
{
  return _buttonCount;
}


// ****************************************************************************
// packet
//
// ****************************************************************************
void AppleADBMouse::packet(UInt8 /*adbCommand*/,
			   IOByteCount /*length*/, UInt8 * data)
{
  int		  dx, dy;
  UInt32          buttonState = 0;
  AbsoluteTime    now;
  
  dy = data[0] & 0x7f;
  dx = data[1] & 0x7f;
  
  if (dy & 0x40) dy |= 0xffffffc0;
  if (dx & 0x40) dx |= 0xffffffc0;
  
  if ((data[0] & 0x80) == 0) buttonState |= 1;
  
  clock_get_uptime(&now);
  dispatchRelativePointerEvent(dx, dy, buttonState, now);
}


// ****************************************************************************

#undef super
#define super AppleADBMouse

OSDefineMetaClassAndStructors(AppleADBMouseType1, AppleADBMouse);

IOService * AppleADBMouseType1::probe(IOService * provider, SInt32 * score)
{
  if (!super::probe(provider, score)) return 0;
  
  return this;
}

bool AppleADBMouseType1::start(IOService * provider)
{
  if (adbDevice->setHandlerID(1) != kIOReturnSuccess) return false;
  
  _resolution = 100 << 16;
  _buttonCount = 1;
  
  return super::start(provider);
}


// ****************************************************************************

#undef super
#define super AppleADBMouse

OSDefineMetaClassAndStructors(AppleADBMouseType2, AppleADBMouse);

IOService * AppleADBMouseType2::probe(IOService * provider, SInt32 * score)
{
  if (!super::probe(provider, score)) return 0;
  
  if (adbDevice->setHandlerID(2) != kIOReturnSuccess) return 0;
  
  return this;
}

bool AppleADBMouseType2::start(IOService * provider)
{
  if (adbDevice->setHandlerID(2) != kIOReturnSuccess) return false;
  
  _resolution = 200 << 16;
  _buttonCount = 1;
  
  return super::start(provider);
}


// ****************************************************************************

#undef super
#define super AppleADBMouse

OSDefineMetaClassAndStructors(AppleADBMouseType4, AppleADBMouse);

IOService * AppleADBMouseType4::probe(IOService * provider, SInt32 * score)
{
  UInt8       data[8];
  IOByteCount length = 8;
  
  if (!super::probe(provider, score)) return 0;
  
  if (adbDevice->setHandlerID(4) != kIOReturnSuccess) {
    adbDevice->setHandlerID(adbDevice->defaultHandlerID());
    return 0;
  }
  
  // To be a Type 4 Extended Mouse, register 1 must return 8 bytes.
  if (adbDevice->readRegister(1, data, &length) != kIOReturnSuccess) return 0;
  if (length != 8) return 0;
  
  // Save the device's Extended Mouse Info.
  deviceSignature  = ((UInt32 *)data)[0];
  deviceResolution = ((UInt16 *)data)[2];
  deviceClass      = data[6];
  deviceNumButtons = data[7];
  
  return this;
}

bool AppleADBMouseType4::start(IOService * provider)
{
  UInt8       adbdata[8];
  IOByteCount adblength = 8;
  typeTrackpad = FALSE;
  
  if (adbDevice->setHandlerID(4) != kIOReturnSuccess) return false;

  _resolution = deviceResolution << 16;
  _buttonCount = deviceNumButtons;

  adbDevice->readRegister(1, adbdata, &adblength);
  if( (adbdata[0] == 't') && (adbdata[1] = 'p') && (adbdata[2] == 'a') && (adbdata[3] == 'd') )
  {
    IOLog("Trackpad detected, ");
    typeTrackpad = TRUE;
    enableEnhancedMode();
  }
  
  return super::start(provider);
}

void AppleADBMouseType4::packet(UInt8 /*adbCommand*/, IOByteCount length, UInt8 * data)
{
  int		  dx, dy, cnt, numExtraBytes;
  UInt32          buttonState = 0;
  AbsoluteTime	  now;
  
  numExtraBytes = length - 2;
  
  dy = data[0] & 0x7f;
  dx = data[1] & 0x7f;
  
  if ((data[0] & 0x80) == 0) buttonState |= 1;
  if ((deviceNumButtons > 1) && ((data[1] & 0x80) == 0))
  {
    if(typeTrackpad == TRUE)
        buttonState |= 1;
    else
        buttonState |= 2;
  }

  for (cnt = 0; cnt < numExtraBytes; cnt++) {
    dy |= ((data[2 + cnt] >> 4) & 7) << (7 + (cnt * 3));
    dx |= ((data[2 + cnt])      & 7) << (7 + (cnt * 3));
    
    if ((deviceNumButtons > (cnt + 2)) && ((data[2 + cnt] & 0x80) == 0))
      buttonState |= 4 << (cnt * 2);
    if ((deviceNumButtons > (cnt + 2 + 1)) && ((data[2 + cnt] & 0x08) == 0))
      buttonState |= 4 << (cnt * 2 + 1);
  }
  
  if (dy & (0x40 << (numExtraBytes * 3)))
    dy |= (0xffffffc0 << (numExtraBytes * 3));
  if (dx & (0x40 << (numExtraBytes * 3)))
    dx |= (0xffffffc0 << (numExtraBytes * 3));
  
  clock_get_uptime(&now);
  dispatchRelativePointerEvent(dx, dy, buttonState, now);
}

OSData * AppleADBMouseType4::copyAccelerationTable()
{
    char keyName[10];

    strcpy( keyName, "accl" );
    keyName[4] = (deviceSignature >> 24);
    keyName[5] = (deviceSignature >> 16);
    keyName[6] = (deviceSignature >> 8);
    keyName[7] = (deviceSignature >> 0);
    keyName[8] = 0;

    OSData * data = OSDynamicCast( OSData,
                getProperty( keyName ));
    if( data)
        data->retain();
    else
        data = super::copyAccelerationTable();
        
    return( data );
}

// ****************************************************************************
// enableEnhancedMode
//
// ****************************************************************************

bool AppleADBMouseType4::enableEnhancedMode()
{
    UInt8       adbdata[8];
    IOByteCount adblength = 8;
    
    IOLog("enableEnhancedMode called.\n");
    adbDevice->readRegister(1, adbdata, &adblength);

    if((adbdata[6] != 0x0D))
    {
        adbdata[6] = 0xD;
        if (adbDevice->writeRegister(1, adbdata, &adblength) != 0)
            return FALSE;
        if (adbDevice->readRegister(1, adbdata, &adblength) != 0)
            return FALSE;
        if (adbdata[6] != 0x0D)
        {
            IOLog("AppleADBMouseType4 deviceClass = %d (non-Extended Mode)\n", adbdata[6]);
            return FALSE;
        }
        IOLog("AppleADBMouseType4 deviceClass = %d (Extended Mode)\n", adbdata[6]);

        // Set ADB Extended Features to default values.
        //adbdata[0] = 0x19;
        adbdata[0] = glob_clicking;
        //adbdata[1] = 0x14;
        adbdata[1] = glob_dragging;
        adbdata[2] = 0x19;
        //adbdata[3] = 0xB2;
        adbdata[3] = glob_draglock;
        adbdata[4] = 0xB2;
        adbdata[5] = 0x8A;
        adbdata[6] = 0x1B;
        adbdata[7] = 0x50;
        adblength = 8;

        adbDevice->writeRegister(2, adbdata, &adblength);

        /* Add IORegistry entries for Enhanced mode */
        Clicking = FALSE;
        Dragging = FALSE;
        DragLock = FALSE;
        
        setProperty("Clicking", (unsigned long long)Clicking, sizeof(Clicking)*8);
        setProperty("Dragging", (unsigned long long)Dragging, sizeof(Dragging)*8);
        setProperty("DragLock", (unsigned long long)DragLock, sizeof(DragLock)*8);

        return TRUE;
    }

    return FALSE;
}

// ****************************************************************************
// setParamProperties
//
// ****************************************************************************
IOReturn AppleADBMouseType4::setParamProperties( OSDictionary * dict )
{
    OSData *	data;
    IOReturn	err = kIOReturnSuccess;
    UInt8       adbdata[8];
    IOByteCount adblength;

    //IOLog("AppleADBMouseType4::setParamProperties starting here\n");
    
    if( (data = OSDynamicCast(OSData, dict->getObject("Clicking"))) && (typeTrackpad == TRUE) )
    {
        adblength = sizeof(adbdata);
        adbDevice->readRegister(2, adbdata, &adblength);
        glob_clicking = (adbdata[0] & 0x7F) | (*( (UInt8 *) data->getBytesNoCopy() ))<<7;
        adbdata[0] = glob_clicking;
        setProperty("Clicking", (unsigned long long)((adbdata[0]&0x80)>>7), sizeof(adbdata[0])*8);
        adbDevice->writeRegister(2, adbdata, &adblength);
    }

    if( (data = OSDynamicCast(OSData, dict->getObject("Dragging"))) && (typeTrackpad == TRUE) )
    {
        adblength = sizeof(adbdata);
        adbDevice->readRegister(2, adbdata, &adblength);
        glob_dragging = (adbdata[1] & 0x7F) | (*( (UInt8 *) data->getBytesNoCopy() ))<<7;
        adbdata[1] = glob_dragging;
        setProperty("Dragging", (unsigned long long)((adbdata[1]&0x80)>>7), sizeof(adbdata[1])*8);
        adbDevice->writeRegister(2, adbdata, &adblength);
    }

    if( (data = OSDynamicCast(OSData, dict->getObject("DragLock"))) && (typeTrackpad == TRUE) )
    {
        adblength = sizeof(adbdata);
        adbDevice->readRegister(2, adbdata, &adblength);
        adbdata[3] = *((UInt8 *) data->getBytesNoCopy());

        if(adbdata[3])
        {
            setProperty("DragLock", (unsigned long long)adbdata[3], sizeof(adbdata[3])*8);
            glob_draglock = 0xFF;
            adbdata[3] = glob_draglock;
            adblength = sizeof(adbdata);
            adbDevice->writeRegister(2, adbdata, &adblength);
        }
        else
        {
            setProperty("DragLock", (unsigned long long)adbdata[3], sizeof(adbdata[3])*8);
            glob_draglock = 0xB2;
            adbdata[3] = glob_draglock;
            adblength = sizeof(adbdata);
            adbDevice->writeRegister(2, adbdata, &adblength);
        }
    }

#if 0
    // For debugging purposes
    adblength = 8;
    adbDevice->readRegister(2, adbdata, &adblength);
    IOLog("adbdata[0] = 0x%x\n", adbdata[0]);
    IOLog("adbdata[1] = 0x%x\n", adbdata[1]);
    IOLog("adbdata[2] = 0x%x\n", adbdata[2]);
    IOLog("adbdata[3] = 0x%x\n", adbdata[3]);
    IOLog("adbdata[4] = 0x%x\n", adbdata[4]);
    IOLog("adbdata[5] = 0x%x\n", adbdata[5]);
    IOLog("adbdata[6] = 0x%x\n", adbdata[6]);
    IOLog("adbdata[7] = 0x%x\n", adbdata[7]);
#endif

    if (err == kIOReturnSuccess)
    {
        //IOLog("AppleADBMouseType4::setParamProperties ending here\n");
        return super::setParamProperties(dict);
    }

    IOLog("AppleADBMouseType4::setParamProperties failing here\n");
    return( err );
}

