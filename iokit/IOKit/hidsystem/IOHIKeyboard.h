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
/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * EventSrcPCKeyboard.h - PC Keyboard EventSrc subclass definition
 *
 * HISTORY
 * 28 Aug 1992    Joe Pasqua
 *      Created. 
 */

#ifndef _IOHIKEYBOARD_H
#define _IOHIKEYBOARD_H

#include <IOKit/hidsystem/IOHIDevice.h>
#include <IOKit/hidsystem/IOHIKeyboardMapper.h>

/* Start Action Definitions */

/*
 * HISTORICAL NOTE:
 *   The following entry points were part of the IOHIKeyboardEvents
 *   protocol.
 */

typedef void (*KeyboardEventAction)(       OSObject * target,
                    /* eventFlags  */      unsigned   eventType,
                    /* flags */            unsigned   flags,
                    /* keyCode */          unsigned   key,
                    /* charCode */         unsigned   charCode,
                    /* charSet */          unsigned   charSet,
                    /* originalCharCode */ unsigned   origCharCode,
                    /* originalCharSet */  unsigned   origCharSet,
                    /* keyboardType */     unsigned   keyboardType,
                    /* repeat */           bool       repeat,
                    /* atTime */           AbsoluteTime ts);

typedef void (*KeyboardSpecialEventAction)(OSObject * target,
                    /* eventType */        unsigned   eventType,
                    /* flags */            unsigned   flags,
                    /* keyCode */          unsigned   key,
                    /* specialty */        unsigned   flavor,
                    /* source id */        UInt64     guid,
                    /* repeat */           bool       repeat,
                    /* atTime */           AbsoluteTime ts);

typedef void (*UpdateEventFlagsAction)(    OSObject * target,
                     /* flags */           unsigned   flags);

/* End Action Definitions */



/* Default key repeat parameters */
#define EV_DEFAULTINITIALREPEAT 500000000ULL    // 1/2 sec in nanoseconds
#define EV_DEFAULTKEYREPEAT     83333333ULL     // 1/12 sec in nanoseconds
#define EV_MINKEYREPEAT         16700000ULL     // 1/60 sec

class IOHIKeyboard : public IOHIDevice
{
  OSDeclareDefaultStructors(IOHIKeyboard);

protected:
    IOLock *	         _deviceLock;	// Lock for all device access
    IOHIKeyboardMapper * _keyMap;	// KeyMap instance

    // The following fields describe the kind of keyboard
    UInt32		_interfaceType;
    UInt32		_deviceType;

    // The following fields describe the state of the keyboard
    UInt32 *	_keyState;		// kbdBitVector
    IOByteCount _keyStateSize;		// kbdBitVector allocated size
    unsigned	_eventFlags;		// Current eventFlags
    bool	_alphaLock;		// true means alpha lock is on
    bool	_numLock;		// true means num lock is on
    bool	_charKeyActive;		// true means char gen. key active

    // The following fields are used in performing key repeats
    bool 	_isRepeat;		// true means we're generating repeat
    unsigned	_codeToRepeat;		// What we are repeating
    bool	_calloutPending;	// true means we've sched. a callout
    AbsoluteTime	_lastEventTime;		// Time last event was dispatched
    AbsoluteTime	_downRepeatTime;	// Time when we should next repeat
    AbsoluteTime	_keyRepeat;		// Delay between key repeats
    AbsoluteTime	_initialKeyRepeat;	// Delay before initial key repeat
    UInt64		_guid;

    OSObject *                 _keyboardEventTarget;
    KeyboardEventAction        _keyboardEventAction;
    OSObject *                 _keyboardSpecialEventTarget;
    KeyboardSpecialEventAction _keyboardSpecialEventAction;
    OSObject *                 _updateEventFlagsTarget;
    UpdateEventFlagsAction     _updateEventFlagsAction;

protected:
  virtual void dispatchKeyboardEvent(unsigned int keyCode,
		     /* direction */ bool         goingDown,
		     /* timeStamp */ AbsoluteTime time);

public:
  virtual bool init(OSDictionary * properties = 0);
  virtual bool start(IOService * provider);
  virtual void free();

  virtual bool open(IOService *                client,
		    IOOptionBits	       options,
                    KeyboardEventAction        keAction,
                    KeyboardSpecialEventAction kseAction,
                    UpdateEventFlagsAction     uefAction);
  virtual void close(IOService * client, IOOptionBits );

  virtual IOHIDKind hidKind();
  virtual bool 	    updateProperties( void );
  virtual IOReturn  setParamProperties(OSDictionary * dict);

protected: // for subclasses to implement
  virtual const unsigned char * defaultKeymapOfLength(UInt32 * length);
  virtual void setAlphaLockFeedback(bool val);
  virtual void setNumLockFeedback(bool val);
  virtual UInt32 maxKeyCodes();


private:
  virtual bool resetKeyboard();
  virtual void scheduleAutoRepeat();
  static void _autoRepeat(void * arg, void *);
  virtual void autoRepeat();
  virtual void setRepeat(unsigned eventType, unsigned keyCode);

/*
 * HISTORICAL NOTE:
 *   The following methods were part of the KeyMapDelegate protocol;
 *   the declarations have now been merged directly into this class.
 */

public:
  virtual void keyboardEvent(unsigned eventType,
      /* flags */            unsigned flags,
      /* keyCode */          unsigned keyCode,
      /* charCode */         unsigned charCode,
      /* charSet */          unsigned charSet,
      /* originalCharCode */ unsigned origCharCode,
      /* originalCharSet */  unsigned origCharSet);

  virtual void keyboardSpecialEvent(unsigned eventType,
		    /* flags */     unsigned flags,
		    /* keyCode */   unsigned keyCode,
		    /* specialty */ unsigned flavor);

  virtual void updateEventFlags(unsigned flags); // Does not generate events

  virtual unsigned eventFlags();           // Global event flags
  virtual unsigned deviceFlags();          // per-device event flags
  virtual void setDeviceFlags(unsigned flags); // Set device event flags
  virtual bool alphaLock();                // current alpha-lock state
  virtual void setAlphaLock(bool val);     // Set current alpha-lock state
  virtual bool numLock();                
  virtual void setNumLock(bool val);     
  virtual bool charKeyActive();            // Is a character gen. key down?
  virtual void setCharKeyActive(bool val); // Note that a char gen key is down.
  virtual bool doesKeyLock(unsigned key);  //does key lock physically
  virtual unsigned getLEDStatus();  //check hardware for LED status


};

#endif /* !_IOHIKEYBOARD_H */
