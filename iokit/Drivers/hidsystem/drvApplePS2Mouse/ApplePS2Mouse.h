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

#ifndef _APPLEPS2MOUSE_H
#define _APPLEPS2MOUSE_H

#include <IOKit/ps2/ApplePS2MouseDevice.h>
#include <IOKit/hidsystem/IOHIPointing.h>

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Local Declarations
//

#define kPacketLengthMax          4
#define kPacketLengthStandard     3
#define kPacketLengthIntellimouse 4

typedef enum
{
  kMouseTypeStandard     = 0x00,
  kMouseTypeIntellimouse = 0x03
} PS2MouseId;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// ApplePS2Mouse Class Declaration
//

class ApplePS2Mouse : public IOHIPointing 
{
  OSDeclareDefaultStructors(ApplePS2Mouse);

private:
  ApplePS2MouseDevice * _device;
  unsigned              _interruptHandlerInstalled:1;
  UInt8                 _packetBuffer[kPacketLengthMax];
  UInt32                _packetByteCount;
  UInt32                _packetLength;
  IOFixed               _resolution;                // (dots per inch)
  PS2MouseId            _type;

  virtual void   dispatchRelativePointerEventWithPacket(UInt8 * packet);
  virtual UInt8  getMouseID();
  virtual UInt32 getMouseInformation();
  virtual void   setCommandByte(UInt8 setBits, UInt8 clearBits);
  virtual bool   setIntellimouseMode();
  virtual void   setMouseEnable(bool enable);
  virtual void   setMouseSampleRate(UInt8 sampleRate);

protected:
  virtual IOItemCount buttonCount();
  virtual IOFixed     resolution();

public:
  virtual bool init(OSDictionary * properties);
  virtual ApplePS2Mouse * probe(IOService * provider, SInt32 * score);

  virtual bool start(IOService * provider);
  virtual void stop(IOService * provider);

  virtual void interruptOccurred(UInt8 data);

  virtual UInt32 deviceType();
  virtual UInt32 interfaceID();
};

#endif /* _APPLEPS2MOUSE_H */
