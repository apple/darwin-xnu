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

#ifndef _APPLEPS2KEYBOARD_H
#define _APPLEPS2KEYBOARD_H

#include <IOKit/ps2/ApplePS2KeyboardDevice.h>
#include <IOKit/hidsystem/IOHIKeyboard.h>

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Definitions used to keep track of key state.   Key up/down state is tracked
// in a bit list.  Bits are set for key-down, and cleared for key-up.  The bit
// vector and macros for it's manipulation are defined here.
//

#define KBV_NUM_KEYCODES        128
#define KBV_BITS_PER_UNIT       32     // for UInt32
#define KBV_BITS_MASK           31
#define KBV_BITS_SHIFT          5      // 1<<5 == 32, for cheap divide
#define KBV_NUNITS ((KBV_NUM_KEYCODES + \
                                      (KBV_BITS_PER_UNIT-1))/KBV_BITS_PER_UNIT)

#define KBV_KEYDOWN(n, bits) \
      (bits)[((n)>>KBV_BITS_SHIFT)] |= (1 << ((n) & KBV_BITS_MASK))

#define KBV_KEYUP(n, bits) \
      (bits)[((n)>>KBV_BITS_SHIFT)] &= ~(1 << ((n) & KBV_BITS_MASK))

#define KBV_IS_KEYDOWN(n, bits) \
      (((bits)[((n)>>KBV_BITS_SHIFT)] & (1 << ((n) & KBV_BITS_MASK))) != 0)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// ApplePS2Keyboard Class Declaration
//

class ApplePS2Keyboard : public IOHIKeyboard
{
  OSDeclareDefaultStructors(ApplePS2Keyboard);

private:
  ApplePS2KeyboardDevice * _device;
  UInt32                   _keyBitVector[KBV_NUNITS];
  UInt8                    _extendCount;
  UInt8                    _interruptHandlerInstalled:1;
  UInt8                    _ledState;

  virtual bool dispatchKeyboardEventWithScancode(UInt8 scanCode);
  virtual void setCommandByte(UInt8 setBits, UInt8 clearBits);
  virtual void setLEDs(UInt8 ledState);
  virtual void setKeyboardEnable(bool enable);

protected:
  virtual const unsigned char * defaultKeymapOfLength(UInt32 * length);
  virtual void setAlphaLockFeedback(bool locked);
  virtual UInt32 maxKeyCodes();

public:
  virtual bool init(OSDictionary * properties);
  virtual ApplePS2Keyboard * probe(IOService * provider, SInt32 * score);

  virtual bool start(IOService * provider);
  virtual void stop(IOService * provider);

  virtual void interruptOccurred(UInt8 scanCode);

  virtual UInt32 deviceType();
  virtual UInt32 interfaceID();
};

#endif /* _APPLEPS2KEYBOARD_H */
