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
#ifndef _IOBSDCONSOLE_H
#define _IOBSDCONSOLE_H

#include <IOKit/IOService.h>

class IOHIKeyboard;

class IOBSDConsole : public IOService
{
  OSDeclareDefaultStructors(IOBSDConsole);

private:
    IOService * fAudioOut;

  static bool publishNotificationHandler(
			IOBSDConsole * self, void * ref,
			IOService * newService );

  virtual void arbitrateForKeyboard( IOHIKeyboard * kb );

public:
      IOService * displayManager;	// we send user activity tickles to the display manager

  static void keyboardEvent(OSObject * target,
     /* eventType */        unsigned   eventType,
     /* flags */            unsigned   flags,
     /* keyCode */          unsigned   key,
     /* charCode */         unsigned   charCode,
     /* charSet */          unsigned   charSet,
     /* originalCharCode */ unsigned   origCharCode,
     /* originalCharSet */  unsigned   origCharSet,
     /* keyboardType */     unsigned   keyboardType,
     /* repeat */           bool       repeat,
     /* atTime */           AbsoluteTime ts);

  static void updateEventFlags(OSObject * target, unsigned flags);

  virtual bool start(IOService * provider);

  virtual IOReturn message(UInt32 type, IOService * provider,
				void * argument);

  IOService * getAudioOut() { return fAudioOut; };
};

#endif /* _IOBSDCONSOLE_H */
