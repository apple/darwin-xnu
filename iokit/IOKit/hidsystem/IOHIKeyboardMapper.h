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
#ifndef _IOHIKEYBOARDMAPPER_H
#define _IOHIKEYBOARDMAPPER_H

#include <IOKit/hidsystem/ev_keymap.h>

class IOHIKeyboard;

/*
 * Key ip/down state is tracked in a bit list.  Bits are set
 * for key-down, and cleared for key-up.  The bit vector and macros
 * for it's manipulation are defined here.
 */

typedef	UInt32 * kbdBitVector;

#define EVK_BITS_PER_UNIT	32
#define EVK_BITS_MASK		31
#define EVK_BITS_SHIFT		5	// 1<<5 == 32, for cheap divide

#define EVK_KEYDOWN(n, bits) \
	(bits)[((n)>>EVK_BITS_SHIFT)] |= (1 << ((n) & EVK_BITS_MASK))

#define EVK_KEYUP(n, bits) \
	(bits)[((n)>>EVK_BITS_SHIFT)] &= ~(1 << ((n) & EVK_BITS_MASK))

#define EVK_IS_KEYDOWN(n, bits) \
	(((bits)[((n)>>EVK_BITS_SHIFT)] & (1 << ((n) & EVK_BITS_MASK))) != 0)

class IOHIKeyboardMapper : public OSObject
{
  OSDeclareDefaultStructors(IOHIKeyboardMapper);

private:
  IOHIKeyboard *     _delegate;                 // KeyMap delegate
  bool               _mappingShouldBeFreed;     // true if map can be IOFree'd
  NXParsedKeyMapping _parsedMapping;            // current system-wide keymap

public:
  static IOHIKeyboardMapper * keyboardMapper(
                                        IOHIKeyboard * delegate,
                                        const UInt8 *  mapping,
                                        UInt32         mappingLength,
                                        bool           mappingShouldBeFreed );

  virtual bool init(IOHIKeyboard * delegate,
                    const UInt8 *  mapping,
                    UInt32         mappingLength,
                    bool           mappingShouldBeFreed);
  virtual void free();

  virtual const UInt8 *   mapping();
  virtual UInt32          mappingLength();
  virtual bool 		  serialize(OSSerialize *s) const;

  virtual void translateKeyCode(UInt8 key, bool keyDown, kbdBitVector keyBits);
  virtual UInt8  getParsedSpecialKey(UInt8 logical);   //retrieve a key from _parsedMapping


private:
  virtual bool parseKeyMapping(const UInt8 *        mapping,
                               UInt32               mappingLength,
	                       NXParsedKeyMapping * parsedMapping) const;

  virtual void calcModBit(int bit, kbdBitVector keyBits);
  virtual void doModCalc(int key, kbdBitVector keyBits);
  virtual void doCharGen(int keyCode, bool down);
};

#endif _IOHIKEYBOARDMAPPER_H

/*
 * HISTORICAL NOTE:
 *   The "delegate" object had to respond to the following protocol;
 *   this protocol has since been merged into the IOHIKeyboard class.
 *
 * @protocol KeyMapDelegate
 *
 * - keyboardEvent	:(unsigned)eventType
 * 	flags	:(unsigned)flags
 *	keyCode	:(unsigned)keyCode
 *	charCode:(unsigned)charCode
 *	charSet	:(unsigned)charSet
 *	originalCharCode:(unsigned)origCharCode
 *	originalCharSet:(unsigned)origCharSet;
 * 
 * - keyboardSpecialEvent:(unsigned)eventType
 *	flags	 :(unsigned)flags
 *	keyCode	:(unsigned)keyCode
 *	specialty:(unsigned)flavor;
 *
 * - updateEventFlags:(unsigned)flags;	// Does not generate events
 *
 * - (unsigned)eventFlags;		// Global event flags
 * - (unsigned)deviceFlags;		// per-device event flags
 * - setDeviceFlags:(unsigned)flags;	// Set device event flags
 * - (bool)alphaLock;			// current alpha-lock state
 * - setAlphaLock:(bool)val;		// Set current alpha-lock state
 * - (bool)charKeyActive;		// Is a character gen. key down?
 * - setCharKeyActive:(bool)val;	// Note that a char gen key is down.
 *
 * @end
 */
