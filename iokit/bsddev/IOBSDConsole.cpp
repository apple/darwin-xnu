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
#include <IOKit/assert.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOLib.h>
#include "IOBSDConsole.h"
#include <IOKit/hidsystem/IOHIKeyboard.h>
#include <IOKit/hidsystem/IOLLEvent.h>

static IOBSDConsole * gBSDConsoleInst = 0;
bool displayWranglerPublished( OSObject *, void *, IOService * );

#define super IOService
OSDefineMetaClassAndStructors(IOBSDConsole, IOService);

//************************************************************************

bool IOBSDConsole::start(IOService * provider)
{
    OSObject *	notify;

    if (!super::start(provider))  return false;

    assert( gBSDConsoleInst == 0 );
    gBSDConsoleInst = this;

    notify = addNotification( gIOPublishNotification,
        serviceMatching("IOHIKeyboard"),
        (IOServiceNotificationHandler) &IOBSDConsole::publishNotificationHandler,
        this, 0 );
    assert( notify );

    notify = addNotification( gIOPublishNotification,
        serviceMatching("IODisplayWrangler"),
                              (IOServiceNotificationHandler)displayWranglerPublished,
         this, 0 );
    assert( notify ); 

    notify = addNotification( gIOPublishNotification,
        serviceMatching("IOAudioStream"),
        (IOServiceNotificationHandler) &IOBSDConsole::publishNotificationHandler,
        this, this );
    assert( notify );

    return( true );
}

bool IOBSDConsole::publishNotificationHandler(
			    IOBSDConsole * self,
                            void * ref,
                            IOService * newService )

{
    IOHIKeyboard *	keyboard = 0;
    IOService *		audio = 0;

    if( ref) {
        audio = OSDynamicCast(IOService, newService->metaCast("IOAudioStream"));
        if (audio != 0) {
            OSNumber *out;
            out = OSDynamicCast(OSNumber, newService->getProperty("Out"));
            if (out) {
                if (out->unsigned8BitValue() == 1) {
                    self->fAudioOut = newService;
                }
            }
        }
    } else {
	audio = 0;
        keyboard = OSDynamicCast( IOHIKeyboard, newService );

        if( keyboard && self->attach( keyboard )) {
            self->arbitrateForKeyboard( keyboard );
        }
    }

    if( !keyboard && !audio)
	IOLog("%s: strange service notify \"%s\"\n",
		self->getName(), newService->getName());

    return true;
}

// **********************************************************************************
// displayWranglerPublished
//
// The Display Wrangler has appeared.  We will be calling its
// ActivityTickle method when there is user activity.
// **********************************************************************************
bool displayWranglerPublished( OSObject * us, void * ref, IOService * yourDevice )
{
 if ( yourDevice != NULL ) {
     ((IOBSDConsole *)us)->displayManager = yourDevice;
 }
 return true;
}


//************************************************************************
// Keyboard client stuff
//************************************************************************

void IOBSDConsole::arbitrateForKeyboard( IOHIKeyboard * nub )
{
  nub->open(this, 0,
	keyboardEvent, 0, updateEventFlags);
  // failure can be expected if the HID system already has it
}

IOReturn IOBSDConsole::message(UInt32 type, IOService * provider,
				void * argument)
{
  IOReturn     status = kIOReturnSuccess;

  switch (type)
  {
    case kIOMessageServiceIsTerminated:
    case kIOMessageServiceIsRequestingClose:
      provider->close( this );
      break;

    case kIOMessageServiceWasClosed:
      arbitrateForKeyboard( (IOHIKeyboard *) provider );
      break;

    default:
      status = super::message(type, provider, argument);
      break;
  }

  return status;
}

extern "C" {
  void cons_cinput( char c);
}
#warning REMOVE cons_cinput DECLARATION FROM HERE

void IOBSDConsole::keyboardEvent(OSObject * target,
          /* eventType */        unsigned   eventType,
          /* flags */            unsigned   /* flags */,
          /* keyCode */          unsigned   /* key */,
          /* charCode */         unsigned   charCode,
          /* charSet */          unsigned   charSet,
          /* originalCharCode */ unsigned   /* origCharCode */,
          /* originalCharSet */  unsigned   /* origCharSet */,
          /* keyboardType */ 	 unsigned   /* keyboardType */,
          /* repeat */           bool       /* repeat */,
          /* atTime */           AbsoluteTime /* ts */)
{
    static const char cursorCodes[] = { 'D', 'A', 'C', 'B' };

    if ( ((IOBSDConsole *)target)->displayManager != NULL ) {				// if there is a display manager,
        ((IOBSDConsole *)target)->displayManager->activityTickle(kIOPMSuperclassPolicy1);	// tell it there is user activity
    }

    if( eventType == NX_KEYDOWN) {
        if( (charSet == NX_SYMBOLSET)
            && (charCode >= 0xac) && (charCode <= 0xaf)) {
            cons_cinput( '\033');
            cons_cinput( 'O');
            charCode = cursorCodes[ charCode - 0xac ];
        }
        cons_cinput( charCode);
    }
}

void IOBSDConsole::updateEventFlags(OSObject * /*target*/, unsigned /*flags*/)
{
  return;
}

//************************************************************************
// Utility sound making stuff, callable from C
//************************************************************************
extern "C" {
  int asc_ringbell();
}


bool (*playBeep)(IOService *outputStream) = 0;

/*
* Make some sort of noise if possible
*/

int asc_ringbell()
{
    IOService *output;

    if (gBSDConsoleInst && playBeep && (output = gBSDConsoleInst->getAudioOut())) {
        playBeep(output);
    }

    return true;
}

