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
 *
 * From EventSrcPCKeyoard.m - PC Keyboard EventSrc subclass implementation
 *	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *  20-Dec-00	bubba	Save global repeat and delay values when
 * 						devices are unplugged. Restore when device is reset.
 *  24-Jan-01	bubba	Don't auto-repeat on Power Key. This prevents infinite power key
 *						events from being generated when this key is hit on ADB keyboards.
 */

#include <IOKit/IOLib.h>
#include <IOKit/hidsystem/IOHIKeyboard.h>
#include <IOKit/hidsystem/IOHIKeyboardMapper.h>
#include <IOKit/hidsystem/IOLLEvent.h>
#include <IOKit/hidsystem/IOHIDParameter.h>

AbsoluteTime	gKeyRepeat			= { 0 };	// Delay between key repeats
AbsoluteTime	gInitialKeyRepeat	= { 0 };	// Delay before initial key repeat

#define super IOHIDevice
OSDefineMetaClassAndStructors(IOHIKeyboard, IOHIDevice);

bool IOHIKeyboard::init(OSDictionary * properties)
{
  if (!super::init(properties))  return false;

  /*
   * Initialize minimal state.
   */

  _deviceLock   = IOLockAlloc();
  _keyMap       = 0;
  _keyStateSize = 4*((maxKeyCodes()+(EVK_BITS_PER_UNIT-1))/EVK_BITS_PER_UNIT);
  _keyState     = (UInt32 *) IOMalloc(_keyStateSize);

  if (!_deviceLock || !_keyState)  return false;

  IOLockInit(_deviceLock);
  bzero(_keyState, _keyStateSize);

  return true;
}

bool IOHIKeyboard::start(IOService * provider)
{
  if (!super::start(provider))  return false;

  /*
   * IOHIKeyboard serves both as a service and a nub (we lead a double
   * life).  Register ourselves as a nub to kick off matching.
   */

  registerService();

  return true;
}

void IOHIKeyboard::free()
// Description:	Go Away. Be careful when freeing the lock.
{
    IOLock * lock = NULL;
    
	// Save repeat rate and delay, so when we are replugged we'll be ready
	// with the right values.
	//
	gKeyRepeat 			= _keyRepeat;
	gInitialKeyRepeat	= _initialKeyRepeat;

    if ( _deviceLock )
    {
      lock = _deviceLock;
      IOTakeLock( lock);
      _deviceLock = NULL;
    }
    if ( _keyMap )
	_keyMap->release();
    if( _keyState )
        IOFree( _keyState, _keyStateSize);
    if ( lock )
    {
      IOUnlock( lock);
      IOLockFree( lock);
    }
    super::free();
}

IOHIDKind IOHIKeyboard::hidKind()
{
  return kHIKeyboardDevice;
}

bool IOHIKeyboard::updateProperties( void )
{
    UInt64	keyRepeatNano;
    UInt64	initialKeyRepeatNano;
    bool	ok;
    
    absolutetime_to_nanoseconds( _keyRepeat, &keyRepeatNano);
    absolutetime_to_nanoseconds( _initialKeyRepeat, &initialKeyRepeatNano);
	
    ok = setProperty( kIOHIDKeyMappingKey, _keyMap )
    &    setProperty( kIOHIDKeyRepeatKey, &keyRepeatNano,
                      sizeof(keyRepeatNano))
    &    setProperty( kIOHIDInitialKeyRepeatKey, &initialKeyRepeatNano,
                      sizeof(initialKeyRepeatNano));

    return( ok & super::updateProperties() );
}

IOReturn IOHIKeyboard::setParamProperties( OSDictionary * dict )
{
    OSData *		data;
    IOReturn		err = kIOReturnSuccess;
    unsigned char *	map;
    IOHIKeyboardMapper * oldMap;
    bool		updated = false;
    UInt64		nano;
    IOTakeLock( _deviceLock);

    if( (data = OSDynamicCast( OSData,
		dict->getObject(kIOHIDKeyRepeatKey)))) {

        nano = *((UInt64 *)(data->getBytesNoCopy()));
        if( nano < EV_MINKEYREPEAT)
            nano = EV_MINKEYREPEAT;
        nanoseconds_to_absolutetime(nano, &_keyRepeat);
        updated = true;
    }

    if( (data = OSDynamicCast( OSData,
		dict->getObject(kIOHIDInitialKeyRepeatKey)))) {

        nano = *((UInt64 *)(data->getBytesNoCopy()));
        if( nano < EV_MINKEYREPEAT)
            nano = EV_MINKEYREPEAT;
        nanoseconds_to_absolutetime(nano, &_initialKeyRepeat);
		updated = true;
    }

    if( (data = OSDynamicCast( OSData, dict->getObject(kIOHIDKeyMappingKey)))) {

	map = (unsigned char *)IOMalloc( data->getLength() );
	bcopy( data->getBytesNoCopy(), map, data->getLength() );
	oldMap = _keyMap;
	_keyMap = IOHIKeyboardMapper::keyboardMapper(this, map, data->getLength(), true);
        if (_keyMap) {
	    if (oldMap)
		oldMap->release();
            updated = true;
	} else {
	    _keyMap = oldMap;
	    err = kIOReturnBadArgument;
	} 
    }
    IOUnlock( _deviceLock);

    if( dict->getObject(kIOHIDResetKeyboardKey))
	resetKeyboard();

    if( updated )
        updateProperties();

    return( err );
}

bool IOHIKeyboard::resetKeyboard()
// Description:	Reset the keymapping to the default value and reconfigure
//		the keyboards.
{
    const unsigned char *defaultKeymap;
    UInt32	defaultKeymapLength;

    IOTakeLock( _deviceLock);

    if ( _keyMap )
	_keyMap->release();

    // Set up default keymapping.
    defaultKeymap = defaultKeymapOfLength(&defaultKeymapLength);

    _keyMap = IOHIKeyboardMapper::keyboardMapper( this,
                                                  defaultKeymap,
                                                  defaultKeymapLength,
                                                  false );
    if (_keyMap)
    {
        clock_interval_to_absolutetime_interval( EV_DEFAULTKEYREPEAT,
                                                 kNanosecondScale, &_keyRepeat);
        clock_interval_to_absolutetime_interval( EV_DEFAULTINITIALREPEAT,
                                                 kNanosecondScale, &_initialKeyRepeat);
    }
	
	// Use our globals if valid. That way, if we are unplugged and replugged, we'll
	// have the proper values, instead of the lame default values.
	//
	if( gKeyRepeat.lo > 0 ) _keyRepeat = gKeyRepeat;
	if( gInitialKeyRepeat.lo > 0 ) _initialKeyRepeat = gInitialKeyRepeat;

    updateProperties();

    _interfaceType = interfaceID();
    _deviceType    = deviceType();
    _guid	   = getGUID();

    IOUnlock( _deviceLock);
    return (_keyMap) ? true : false;
}

void IOHIKeyboard::scheduleAutoRepeat()
// Description:	Schedule a procedure to be called when a timeout has expired
//		so that we can generate a repeated key.
// Preconditions:
// *	_deviceLock should be held on entry
{
    if ( _calloutPending == true )
    {
        thread_call_func_cancel(_autoRepeat, this, true);
	_calloutPending = false;
    }
    if ( AbsoluteTime_to_scalar(&_downRepeatTime) )
    {
        AbsoluteTime deadline;
        clock_absolutetime_interval_to_deadline(_downRepeatTime, &deadline);
        thread_call_func_delayed(_autoRepeat, this, deadline);
	_calloutPending = true;
    }
}

void IOHIKeyboard::_autoRepeat(thread_call_param_t arg,
                               thread_call_param_t)         /* thread_call_func_t */
{
    IOHIKeyboard *self = (IOHIKeyboard *) arg;
    self->autoRepeat();
}

void IOHIKeyboard::autoRepeat()
// Description:	Repeat the currently pressed key and schedule ourselves
//		to be called again after another interval elapses.
// Preconditions:
// *	Should only be executed on callout thread
// *	_deviceLock should be unlocked on entry.
{    
    IOTakeLock( _deviceLock);
    if ( _calloutPending == false )
    {
	IOUnlock( _deviceLock);
	return;
    }
    _calloutPending = false;
    _isRepeat = true;

    if ( AbsoluteTime_to_scalar(&_downRepeatTime) )
    {
	// Device is due to generate a repeat
	if (_keyMap)  _keyMap->translateKeyCode(_codeToRepeat,
                                /* direction */ true,
                                /* keyBits */   _keyState);
	_downRepeatTime = _keyRepeat;
    }

    _isRepeat = false;
    scheduleAutoRepeat();
    IOUnlock( _deviceLock);
}

void IOHIKeyboard::setRepeat(unsigned eventType, unsigned keyCode)
// Description:	Set up or tear down key repeat operations. The method
//		that locks _deviceLock is a bit higher on the call stack.
//		This method is invoked as a side effect of our own
//		invocation of _keyMap->translateKeyCode().
// Preconditions:
// *	_deviceLock should be held upon entry.
{
    if ( _isRepeat == false )  // make sure we're not already repeating
    {
	if (eventType == NX_KEYDOWN)	// Start repeat
	{
	    // Set this key to repeat (push out last key if present)
	    _downRepeatTime = _initialKeyRepeat; // + _lastEventTime; 
	    _codeToRepeat = keyCode;
	    // reschedule key repeat event here
	    scheduleAutoRepeat();
	}
	else if (eventType == NX_KEYUP)	// End repeat
	{
	    /* Remove from downKey */
	    if (_codeToRepeat == keyCode)
	    {
                AbsoluteTime_to_scalar(&_downRepeatTime) = 0;
		_codeToRepeat = (unsigned)-1;
		scheduleAutoRepeat();
	    }
	}
    }
}

//
// BEGIN:	Implementation of the methods required by IOHIKeyboardMapper.
//

void IOHIKeyboard::keyboardEvent(unsigned eventType,
	/* flags */              unsigned flags,
	/* keyCode */            unsigned keyCode,
	/* charCode */           unsigned charCode,
	/* charSet */            unsigned charSet,
	/* originalCharCode */   unsigned origCharCode,
	/* originalCharSet */    unsigned origCharSet)
// Description: We use this notification to set up our _keyRepeat timer
//		and to pass along the event to our owner. This method
//		will be called while the KeyMap object is processing
//		the key code we've sent it using deliverKey.
{

    if (_keyboardEventAction)     /* upstream call */ 
    {
      (*_keyboardEventAction)(_keyboardEventTarget,
                              eventType,
       /* flags */            flags,
       /* keyCode */          keyCode,
       /* charCode */         charCode,
       /* charSet */          charSet,
       /* originalCharCode */ origCharCode,
       /* originalCharSet */  origCharSet,
       /* keyboardType */     _deviceType,
       /* repeat */           _isRepeat,
       /* atTime */           _lastEventTime);
    }


    if( keyCode == _keyMap->getParsedSpecialKey(NX_KEYTYPE_CAPS_LOCK) ||
		keyCode == _keyMap->getParsedSpecialKey(NX_POWER_KEY)			)  
    {		
		//Don't repeat caps lock on ADB/USB.  0x39 is default ADB code.
		//    We are here because KeyCaps needs to see 0x39 as a real key,
		//    not just another modifier bit.

		if (_interfaceType == NX_EVS_DEVICE_INTERFACE_ADB)
		{
			return;
		}
    }

    // Set up key repeat operations here.
    setRepeat(eventType, keyCode);
}

void IOHIKeyboard::keyboardSpecialEvent(unsigned eventType,
	/* flags */                     unsigned flags,
	/* keyCode */                   unsigned keyCode,
	/* specialty */                 unsigned flavor)
// Description: See the description for keyboardEvent.
{

    if (_keyboardSpecialEventAction)         /* upstream call */
    {
      (*_keyboardSpecialEventAction)(_keyboardSpecialEventTarget,
                                        eventType,
                     /* flags */        flags,
                     /* keyCode */      keyCode,
                     /* specialty */    flavor,
                     /* guid */ 	_guid,
                     /* repeat */       _isRepeat,
                     /* atTime */       _lastEventTime);
    }

    // Set up key repeat operations here.
 
	//	Don't repeat caps lock, numlock or power key.
	//
	if ( (flavor != NX_KEYTYPE_CAPS_LOCK) && (flavor != NX_KEYTYPE_NUM_LOCK) &&
		 (flavor != NX_POWER_KEY) )
	{
		setRepeat(eventType, keyCode);
	}
}

void IOHIKeyboard::updateEventFlags(unsigned flags)
// Description:	Process non-event-generating flag changes. Simply pass this
//		along to our owner.
{
  if (_updateEventFlagsAction)              /* upstream call */
  {
    (*_updateEventFlagsAction)(_updateEventFlagsTarget, flags);
  }
}

unsigned IOHIKeyboard::eventFlags()
// Description:	Return global event flags In this world, there is only
//		one keyboard device so device flags == global flags.
{
    return _eventFlags;
}

unsigned IOHIKeyboard::deviceFlags()
// Description: Return per-device event flags. In this world, there is only
//		one keyboard device so device flags == global flags.
{
    return _eventFlags;
}

void IOHIKeyboard::setDeviceFlags(unsigned flags)
// Description: Set device event flags. In this world, there is only
//		one keyboard device so device flags == global flags.
{
    _eventFlags = flags;
}

bool IOHIKeyboard::alphaLock()
// Description: Return current alpha-lock state. This is a state tracking
//		callback used by the KeyMap object.
{
    return _alphaLock;
}

void IOHIKeyboard::setAlphaLock(bool val)
// Description: Set current alpha-lock state This is a state tracking
//		callback used by the KeyMap object.
{
    _alphaLock = val;
    setAlphaLockFeedback(val);
}

bool IOHIKeyboard::numLock()
{
    return _numLock;
}

void IOHIKeyboard::setNumLock(bool val)
{
    _numLock = val;
    setNumLockFeedback(val);
}

bool IOHIKeyboard::charKeyActive()
// Description: Return true If a character generating key down This is a state
//		tracking callback used by the KeyMap object.
{
    return _charKeyActive;
}

void IOHIKeyboard::setCharKeyActive(bool val)
// Description: Note whether a char generating key is down. This is a state
//		tracking callback used by the KeyMap object.
{
    _charKeyActive = val;
}
//
// END:		Implementation of the methods required by IOHIKeyboardMapper.
//

void IOHIKeyboard::dispatchKeyboardEvent(unsigned int keyCode,
			 /* direction */ bool         goingDown,
                         /* timeStamp */ AbsoluteTime time)
// Description:	This method is the heart of event dispatching. The overlying
//		subclass invokes this method with each event. We then
//		get the event xlated and dispatched using a _keyMap instance.
//		The event structure passed in by reference should not be freed.
{
    _lastEventTime = time;

    IOTakeLock( _deviceLock);

    if (_keyMap)  _keyMap->translateKeyCode(keyCode,
			  /* direction */ goingDown,
			  /* keyBits */   _keyState);
    IOUnlock( _deviceLock);
}

const unsigned char * IOHIKeyboard::defaultKeymapOfLength(UInt32 * length)
{
    *length = 0;
    return NULL;
}

void IOHIKeyboard::setAlphaLockFeedback(bool /* val */)
{
    return;
}

void IOHIKeyboard::setNumLockFeedback(bool /* val */)
{
    return;
}

UInt32 IOHIKeyboard::maxKeyCodes()
{
    return( 0x80);
}

bool IOHIKeyboard:: doesKeyLock ( unsigned key)
{
	return false;
}

unsigned IOHIKeyboard:: getLEDStatus ()
{
	return 0;
}


bool IOHIKeyboard::open(IOService *                client,
		        IOOptionBits		   options,
                        KeyboardEventAction        keAction,
                        KeyboardSpecialEventAction kseAction,
                        UpdateEventFlagsAction     uefAction)
{
  if ( (!_keyMap) && (!resetKeyboard()))  return false;

//	IOLog("***open -- gKeyRepeat.lo = %08lx\n", gKeyRepeat.lo );
//	IOLog("***open -- gInitialKeyRepeat.lo = %08lx\n", gInitialKeyRepeat.lo );

  if (super::open(client, options))
  {
    // Note: client object is already retained by superclass' open()
    _keyboardEventTarget        = client;
    _keyboardEventAction        = keAction;
    _keyboardSpecialEventTarget = client;
    _keyboardSpecialEventAction = kseAction;
    _updateEventFlagsTarget     = client;
    _updateEventFlagsAction     = uefAction;

    return true;
  }

  return false;
}

void IOHIKeyboard::close(IOService * client, IOOptionBits)
{
//	IOLog("***close -- gKeyRepeat.lo = %08lx\n", gKeyRepeat.lo );
//	IOLog("***close -- gInitialKeyRepeat.lo = %08lx\n", gInitialKeyRepeat.lo );

	// Save repeat rate and delay, so when we are replugged we'll be ready
	// with the right values.
	//
	gKeyRepeat 			= _keyRepeat;
	gInitialKeyRepeat	= _initialKeyRepeat;

	// kill autorepeat task
	AbsoluteTime_to_scalar(&_downRepeatTime) = 0;
	_codeToRepeat = (unsigned)-1;
	scheduleAutoRepeat();
	// clear modifiers to avoid stuck keys
	setAlphaLock(false);
	if (_updateEventFlagsAction)
	  (*_updateEventFlagsAction)(_updateEventFlagsTarget, 0); 	_eventFlags = 0;
	bzero(_keyState, _keyStateSize);

        _keyboardEventAction        = NULL;
        _keyboardEventTarget        = 0;
        _keyboardSpecialEventAction = NULL;
        _keyboardSpecialEventTarget = 0;
        _updateEventFlagsAction     = NULL;
        _updateEventFlagsTarget     = 0;

	super::close(client);
}

