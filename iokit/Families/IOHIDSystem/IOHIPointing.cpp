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
 * 17 July 1998 sdouglas
 * 22 Dec  2000 bubba		- save global acceleration state when device is unplugged.
 */

#include <IOKit/IOLib.h>
#include <IOKit/assert.h>
#include <IOKit/hidsystem/IOHIPointing.h>
#include <IOKit/hidsystem/IOHIDParameter.h>
#include <IOKit/pwr_mgt/RootDomain.h>


#ifndef abs
#define abs(_a)	((_a >= 0) ? _a : -_a)
#endif

#define super IOHIDevice

//  Global variable glob_accel won't get clobbered by sleep/wake code, 
//  which will re-init this driver.  The Window Server does not re-send
//  the original acceleration value, so we need to restore it on unplugs
//  and sleeps.

IOFixed	glob_accel = 0x8000;			    

bool HIPointinghasRoot( OSObject * us, void *, IOService * yourDevice );

OSDefineMetaClassAndStructors(IOHIPointing, IOHIDevice);

bool IOHIPointing::init(OSDictionary * properties)
{
  if (!super::init(properties))  return false;

  /*
   * Initialize minimal state.
   */
  
  _fractX	= 0;
  _fractY     	= 0;
  _acceleration	= -1;
  _convertAbsoluteToRelative = false;
  _contactToMove = false;
  _hadContact = false;
  _pressureThresholdToClick = 128;
  _previousLocation.x = 0;
  _previousLocation.y = 0;
  _rootDomain = 0;

  _deviceLock = IOLockAlloc();

  if (!_deviceLock)  return false;

  IOLockInit(_deviceLock);

  return true;
}

bool IOHIPointing::start(IOService * provider)
{
  if (!super::start(provider))  return false;

  /*
   * IOHIPointing serves both as a service and a nub (we lead a double
   * life).  Register ourselves as a nub to kick off matching.
   */

  registerService();
  addNotification( gIOPublishNotification,serviceMatching("IOPMrootDomain"),
                 (IOServiceNotificationHandler)HIPointinghasRoot, this, 0 );

  return true;
}

/* Here are some power management functions so we can tell when system is
    going to sleep.  We need to remember the acceleration value */
bool HIPointinghasRoot( OSObject * us, void *, IOService * yourDevice )
{
    if (( yourDevice != NULL ) && ((IOHIPointing *)us)->_rootDomain == 0) 
    {
	((IOHIPointing *)us)->_rootDomain = yourDevice;
        ((IOPMrootDomain *)yourDevice)->registerInterestedDriver((IOService *) us);
    }
    return true;
}

IOReturn IOHIPointing::powerStateWillChangeTo ( IOPMPowerFlags theFlags, unsigned long unused1, 
    IOService* unused2)
{
    if ( ! (theFlags & IOPMPowerOn) )
    {
	glob_accel = _acceleration; //Save old value before driver is torn down
    }
    return IOPMAckImplied;
}

IOReturn IOHIPointing::powerStateDidChangeTo ( IOPMPowerFlags theFlags, unsigned long unused1, 
    IOService* unused2)
{
    if (theFlags & IOPMPowerOn)
    {
	if (glob_accel > 0x10000) //Just in case saved value is out of bounds
	    glob_accel = 0x10000;
	setupForAcceleration(glob_accel);
	updateProperties();
    }
    return IOPMAckImplied;
}



void IOHIPointing::free()
// Description:	Go Away. Be careful when freeing the lock.
{
	glob_accel = _acceleration;
//	IOLog("***free -- glob_accel = %08lx\n", glob_accel );
	
    if (_deviceLock)
    {
	IOLock * lock;

	IOTakeLock(_deviceLock);

	lock = _deviceLock;
	_deviceLock = NULL;

	IOUnlock(lock);
	IOLockFree(lock);
    }
    if (_rootDomain)
    {
	_rootDomain->deRegisterInterestedDriver((IOService *) this);
	_rootDomain = 0;
    }
    super::free();
}

bool IOHIPointing::open(IOService *                client,
			IOOptionBits	           options,
                        RelativePointerEventAction rpeAction,
                        AbsolutePointerEventAction apeAction,
                        ScrollWheelEventAction     sweAction)
{
//	IOLog("***open -- glob_accel = %08lx\n", glob_accel );
	if ( (-1 == _acceleration) && (!resetPointer()))  return false;
//	IOLog("***open -- after reset is called, glob_accel = %08lx\n", glob_accel );
  if (super::open(client, options))
  {
    // Note: client object is already retained by superclass' open()
    _relativePointerEventTarget = client;
    _relativePointerEventAction = rpeAction;
    _absolutePointerEventTarget = client;
    _absolutePointerEventAction = apeAction;
    _scrollWheelEventTarget = client;
    _scrollWheelEventAction = sweAction;
    return true;
  }

  return false;
}

void IOHIPointing::close(IOService * client, IOOptionBits)
{
	glob_accel = _acceleration;
 // IOLog("***close -- glob_accel = %08lx\n", glob_accel );

  _relativePointerEventAction = NULL;
  _relativePointerEventTarget = 0;
  _absolutePointerEventAction = NULL;
  _absolutePointerEventTarget = 0;
  if (_rootDomain)
  {
    _rootDomain->deRegisterInterestedDriver((IOService *) this);
    _rootDomain = 0;
  }
  super::close(client);
} 

IOHIDKind IOHIPointing::hidKind()
{
  return kHIRelativePointingDevice;
}

struct CursorDeviceSegment {
    SInt32	devUnits;
    SInt32	slope;
    SInt32	intercept;
};
typedef struct CursorDeviceSegment CursorDeviceSegment;

void IOHIPointing::scalePointer(int * dxp, int * dyp)
// Description:	Perform pointer acceleration computations here.
//		Given the resolution, dx, dy, and time, compute the velocity
//		of the pointer over a Manhatten distance in inches/second.
//		Using this velocity, do a lookup in the pointerScaling table
//		to select a scaling factor. Scale dx and dy up as appropriate.
// Preconditions:
// *	_deviceLock should be held on entry
{

    SInt32			dx, dy;
    SInt32			absDx, absDy;
    SInt32			mag;
    IOFixed			scale;
    CursorDeviceSegment	*	segment;

    if( !_scaleSegments)
        return;

    dx = (*dxp) << 16;
    dy = (*dyp) << 16;
    absDx = (dx < 0) ? -dx : dx;
    absDy = (dy < 0) ? -dy : dy;

    if( absDx > absDy)
	mag = (absDx + (absDy / 2));
    else
	mag = (absDy + (absDx / 2));

    if( !mag)
        return;

    // scale
    for(
        segment = (CursorDeviceSegment *) _scaleSegments;
        mag > segment->devUnits;
        segment++)	{}

    scale = IOFixedDivide(
            segment->intercept + IOFixedMultiply( mag, segment->slope ),
            mag );

    dx = IOFixedMultiply( dx, scale );
    dy = IOFixedMultiply( dy, scale );

    // add fract parts
    dx += _fractX;
    dy += _fractY;

    *dxp = dx / 65536;
    *dyp = dy / 65536;

    // get fractional part with sign extend
    if( dx >= 0)
	_fractX = dx & 0xffff;
    else
	_fractX = dx | 0xffff0000;
    if( dy >= 0)
	_fractY = dy & 0xffff;
    else
	_fractY = dy | 0xffff0000;
}

/*
 Routine:    Interpolate
 This routine interpolates to find a point on the line [x1,y1] [x2,y2] which
 is intersected by the line [x3,y3] [x3,y"].  The resulting y' is calculated
 by interpolating between y3 and y", towards the higher acceleration curve.
*/

static SInt32 Interpolate(  SInt32 x1, SInt32 y1,
                            SInt32 x2, SInt32 y2,
                            SInt32 x3, SInt32 y3,
                            SInt32 scale, Boolean lower )
{

    SInt32 slope;
    SInt32 intercept;
    SInt32 resultY;
    
    slope = IOFixedDivide( y2 - y1, x2 - x1 );
    intercept = y1 - IOFixedMultiply( slope, x1 );
    resultY = intercept + IOFixedMultiply( slope, x3 );
    if( lower)
        resultY = y3 - IOFixedMultiply( scale, y3 - resultY );
    else
        resultY = resultY + IOFixedMultiply( scale, y3 - resultY );

    return( resultY );
}


static SInt32 Fetch32( const UInt16 * p )
{
    SInt32 result;

    result  = (*(p++)) << 16;
    result |= (*(p++));

    return( result );
}

void IOHIPointing::setupForAcceleration( IOFixed desired )
{
    OSData *		data;
    const UInt16 *	lowTable = 0;
    const UInt16 *	highTable;

    SInt32	x1, y1, x2, y2, x3, y3;
    SInt32	prevX1, prevY1;
    SInt32	upperX, upperY;
    SInt32	lowerX, lowerY;
    SInt32	lowAccl = 0, lowPoints = 0;
    SInt32	highAccl, highPoints;
    SInt32	scale;
    UInt32	count;
    Boolean	lower;

    SInt32	pointerResolution	= resolution();
    SInt32	frameRate		=  (67 << 16);
    SInt32	screenResolution	=  (72 << 16);
    SInt32	devScale, crsrScale;
    SInt32	scaledX1, scaledY1;
    SInt32	scaledX2, scaledY2;

    CursorDeviceSegment *	segments;
    CursorDeviceSegment *	segment;
    SInt32			segCount;

    assert(pointerResolution);    
    data = copyAccelerationTable();
    if( !data)
        return;

    if( desired < (IOFixed) 0) {
        // disabling mouse scaling
        if(_scaleSegments && _scaleSegCount)
            IODelete( _scaleSegments,
                        CursorDeviceSegment, _scaleSegCount );
        _scaleSegments = NULL;
        _scaleSegCount = 0;
        data->release();
        return;
    }
	
    highTable = (const UInt16 *) data->getBytesNoCopy();

    devScale = IOFixedDivide( pointerResolution, frameRate );
    crsrScale = IOFixedDivide( screenResolution, frameRate );

    scaledX1 = scaledY1 = 0;

    scale = Fetch32( highTable );
    highTable += 4;

    _acceleration = desired;

    // normalize table's default (scale) to 0.5
    if( desired > 0x8000) {
        desired = IOFixedMultiply( desired - 0x8000,
                                   0x10000 - scale );
        desired <<= 1;
        desired += scale;
    } else {
        desired = IOFixedMultiply( desired, scale );
        desired <<= 1;
    }
    if( desired > (1 << 16))
	desired = (1 << 16);

    count = *(highTable++);

    // find curves bracketing the desired value
    do {
        highAccl = Fetch32( highTable );
        highTable += 2;
        highPoints = *(highTable++);

        if( desired <= highAccl)
            break;
            
        lowTable	= highTable;
        lowAccl		= highAccl;
        lowPoints	= highPoints;
        highTable	+= lowPoints * 4;

    } while( true );

    // scale between the two
    if( lowTable)
        scale = IOFixedDivide( desired - lowAccl,
                        highAccl - lowAccl );
    // or take all the high one
    else {
        scale 		= (1 << 16);
        lowTable	= highTable;
        lowAccl		= highAccl;
        lowPoints	= 0;
    }

    if( lowPoints > highPoints)
        segCount = lowPoints;
    else
        segCount = highPoints;
    segCount *= 2;
/*    IOLog("lowPoints %ld, highPoints %ld, segCount %ld\n",
            lowPoints, highPoints, segCount); */
    segments = IONew( CursorDeviceSegment, segCount );
    assert( segments );
    segment = segments;

    x1 = prevX1 = y1 = prevY1 = 0;

    lowerX = Fetch32( lowTable );
    lowTable += 2;
    lowerY = Fetch32( lowTable );
    lowTable += 2;
    upperX = Fetch32( highTable );
    highTable += 2;
    upperY = Fetch32( highTable );
    highTable += 2;

    do {
        // consume next point from first X
        lower = (lowPoints && (!highPoints || (lowerX <= upperX)));

        if( lower) {
            /* highline */
            x2 = upperX;
            y2 = upperY;
            x3 = lowerX;
            y3 = lowerY;
            if( lowPoints && (--lowPoints)) {
                lowerX = Fetch32( lowTable );
                lowTable += 2;
                lowerY = Fetch32( lowTable );
                lowTable += 2;
            }
        } else  {
            /* lowline */
            x2 = lowerX;
            y2 = lowerY;
            x3 = upperX;
            y3 = upperY;
            if( highPoints && (--highPoints)) {
                upperX = Fetch32( highTable );
                highTable += 2;
                upperY = Fetch32( highTable );
                highTable += 2;
            }
        }
        {
        // convert to line segment
        assert( segment < (segments + segCount) );

        scaledX2 = IOFixedMultiply( devScale, /* newX */ x3 );
        scaledY2 = IOFixedMultiply( crsrScale,
                      /* newY */    Interpolate( x1, y1, x2, y2, x3, y3,
                                            scale, lower ) );
        if( lowPoints || highPoints)
            segment->devUnits = scaledX2;
        else
            segment->devUnits = 0x7fffffff;
        segment->slope = IOFixedDivide( scaledY2 - scaledY1,
                                        scaledX2 - scaledX1 );
        segment->intercept = scaledY2
                            - IOFixedMultiply( segment->slope, scaledX2 );
/*        IOLog("devUnits = %08lx, slope = %08lx, intercept = %08lx\n",
                segment->devUnits, segment->slope, segment->intercept); */

        scaledX1 = scaledX2;
        scaledY1 = scaledY2;
        segment++;
        }

        // continue on from last point
        if( lowPoints && highPoints) {
            if( lowerX > upperX) {
                prevX1 = x1;
                prevY1 = y1;
            } else {
                /* swaplines */
                prevX1 = x1;
                prevY1 = y1;
                x1 = x3;
                y1 = y3;
            }
        } else {
            x2 = x1;
            y2 = y1;
            x1 = prevX1;
            y1 = prevY1;
            prevX1 = x2;
            prevY1 = y2;
        }

    } while( lowPoints || highPoints );
    
    if( _scaleSegCount && _scaleSegments)
        IODelete( _scaleSegments,
                    CursorDeviceSegment, _scaleSegCount );
    _scaleSegCount = segCount;
    _scaleSegments = (void *) segments;

    _fractX = _fractY = 0;

    data->release();
}


bool IOHIPointing::resetPointer()
{
    IOTakeLock( _deviceLock);

    _buttonMode = NX_RightButton;
//	IOLog("***resetPointer -- glob_accel = %08lx", glob_accel );
	if( glob_accel > 0 )
	{
		// Restore the last acceleration value, since we may have been hot
		// unplugged and re-plugged.
		setupForAcceleration(glob_accel);
	}
	else
	{
		setupForAcceleration(0x8000);
	}
    updateProperties();

    IOUnlock( _deviceLock);
    return true;
}

void IOHIPointing::dispatchAbsolutePointerEvent(Point *		newLoc,
                                                Bounds *	bounds,
                                                UInt32		buttonState,
                                                bool		proximity,
                                                int		pressure,
                                                int		pressureMin,
                                                int		pressureMax,
                                                int		stylusAngle,
                                                AbsoluteTime	ts)
{
    int buttons = 0;
    int dx, dy;
    
    IOTakeLock(_deviceLock);

    if (buttonState & 1) {
        buttons |= EV_LB;
    }

    if (buttonCount() > 1) {
        if (buttonState & -2) {	// any other buttons
            buttons |= EV_RB;
        }
    }

    if ((_pressureThresholdToClick < 255) && ((pressure - pressureMin) > ((pressureMax - pressureMin) * _pressureThresholdToClick / 256))) {
        buttons |= EV_LB;
    }

    if (_buttonMode == NX_OneButton) {
        if ((buttons & (EV_LB|EV_RB)) != 0) {
            buttons = EV_LB;
        }
    }

    if (_convertAbsoluteToRelative) {
        dx = newLoc->x - _previousLocation.x;
        dy = newLoc->y - _previousLocation.y;
        
        if ((_contactToMove && !_hadContact && (pressure > pressureMin)) || (abs(dx) > ((bounds->maxx - bounds->minx) / 20)) || (abs(dy) > ((bounds->maxy - bounds->miny) / 20))) {
            dx = 0;
            dy = 0;
        } else {
            scalePointer(&dx, &dy);
        }
        
        _previousLocation.x = newLoc->x;
        _previousLocation.y = newLoc->y;
    }

    IOUnlock(_deviceLock);

    _hadContact = (pressure > pressureMin);

    if (!_contactToMove || (pressure > pressureMin)) {
        pressure -= pressureMin;
        if (pressure > 255) {
            pressure = 255;
        }
        if (_convertAbsoluteToRelative) {
            if (_relativePointerEventAction && _relativePointerEventTarget) {
                (*_relativePointerEventAction)(_relativePointerEventTarget,
                                              buttons,
                                              dx,
                                              dy,
                                              ts);
            }
        } else {
            if (_absolutePointerEventAction && _absolutePointerEventTarget) {
                (*_absolutePointerEventAction)(_absolutePointerEventTarget,
                                              buttons,
                                              newLoc,
                                              bounds,
                                              proximity,
                                              pressure,
                                              stylusAngle,
                                              ts);
            }
        }
    }

    return;
}

void IOHIPointing::dispatchRelativePointerEvent(int        dx,
                                                int        dy,
                                                UInt32     buttonState,
                                                AbsoluteTime ts)
{
    int buttons;

    IOTakeLock( _deviceLock);

    buttons = 0;

    if( buttonState & 1)
        buttons |= EV_LB;

    if( buttonCount() > 1) {
	if( buttonState & 2)	// any others down
            buttons |= EV_RB;
	// Other magic bit reshuffling stuff.  It seems there was space
	// left over at some point for a "middle" mouse button between EV_LB and EV_RB
	if(buttonState & 4)
            buttons |= 2;
	// Add in the rest of the buttons in a linear fasion...
	buttons |= buttonState & ~0x7;
    }

    // Perform pointer acceleration computations
    scalePointer(&dx, &dy);

    // Perform button tying and mapping.  This
    // stuff applies to relative posn devices (mice) only.
    if ( _buttonMode == NX_OneButton )
    {
	// Remap both Left and Right (but no others?) to Left.
	if ( (buttons & (EV_LB|EV_RB)) != 0 ) {
            buttons |= EV_LB;
            buttons &= ~EV_RB;
	}
    }
    else if ( (buttonCount() > 1) && (_buttonMode == NX_LeftButton) )	
    // Menus on left button. Swap!
    {
	int temp = 0;
	if ( buttons & EV_LB )
	    temp = EV_RB;
	if ( buttons & EV_RB )
	    temp |= EV_LB;
	// Swap Left and Right, preserve everything else
	buttons = (buttons & ~(EV_LB|EV_RB)) | temp;
    }
    IOUnlock( _deviceLock);

    if (_relativePointerEventAction)          /* upstream call */
    {
      (*_relativePointerEventAction)(_relativePointerEventTarget,
                       /* buttons */ buttons,
                       /* deltaX */  dx,
                       /* deltaY */  dy,
                       /* atTime */  ts);
    }
}

void IOHIPointing::dispatchScrollWheelEvent(short deltaAxis1,
                                            short deltaAxis2,
                                            short deltaAxis3,
                                            AbsoluteTime ts)
{
    if (_scrollWheelEventAction) {
        (*_scrollWheelEventAction)(_scrollWheelEventTarget,
                                   deltaAxis1,
                                   deltaAxis2,
                                   deltaAxis3,
                                   ts);
    }
}

bool IOHIPointing::updateProperties( void )
{
    bool	ok;
    UInt32	res = resolution();

    ok = setProperty( kIOHIDPointerResolutionKey, &res, sizeof( res))
    &    setProperty( kIOHIDPointerAccelerationKey, &_acceleration,
                        sizeof( _acceleration))
    &    setProperty( kIOHIDPointerConvertAbsoluteKey, &_convertAbsoluteToRelative,
                        sizeof( _convertAbsoluteToRelative))
    &    setProperty( kIOHIDPointerContactToMoveKey, &_contactToMove,
                        sizeof( _contactToMove));

    return( ok & super::updateProperties() );
}

IOReturn IOHIPointing::setParamProperties( OSDictionary * dict )
{
    OSData *	data;
    IOReturn	err = kIOReturnSuccess;
    bool	updated = false;
    UInt8 *	bytes;

    IOTakeLock( _deviceLock);
    if( (data = OSDynamicCast( OSData,
		dict->getObject(kIOHIDPointerAccelerationKey)))) {

	setupForAcceleration( *((IOFixed *)data->getBytesNoCopy()) );
	updated = true;
    }
    IOUnlock( _deviceLock);

    if( dict->getObject(kIOHIDResetPointerKey))
	resetPointer();

    if ((data = OSDynamicCast(OSData,
                              dict->getObject(kIOHIDPointerConvertAbsoluteKey)))) {
        bytes = (UInt8 *) data->getBytesNoCopy();
        _convertAbsoluteToRelative = (bytes[0] != 0) ? true : false;
        updated = true;
    }

    if ((data = OSDynamicCast(OSData,
                              dict->getObject(kIOHIDPointerContactToMoveKey)))) {
        bytes = (UInt8 *) data->getBytesNoCopy();
        _contactToMove = (bytes[0] != 0) ? true : false;
        updated = true;
    }

    if( updated )
        updateProperties();

    return( err );
}

// subclasses override

IOItemCount IOHIPointing::buttonCount()
{
    return (1);
}

IOFixed IOHIPointing::resolution()
{
    return (100 << 16);
}

OSData * IOHIPointing::copyAccelerationTable()
{
static const UInt16 accl[] = {
	0x0000, 0x8000, 
        0x4032, 0x3030, 0x0002, 0x0000, 0x0000, 0x0001, 0x0001, 0x0000,
        0x0001, 0x0000, 0x0001, 0x0000, 0x0009, 0x0000, 0x713B, 0x0000,
        0x6000, 0x0004, 0x4EC5, 0x0010, 0x8000, 0x000C, 0x0000, 0x005F,
        0x0000, 0x0016, 0xEC4F, 0x008B, 0x0000, 0x001D, 0x3B14, 0x0094,
        0x8000, 0x0022, 0x7627, 0x0096, 0x0000, 0x0024, 0x6276, 0x0096,
        0x0000, 0x0026, 0x0000, 0x0096, 0x0000, 0x0028, 0x0000, 0x0096,
        0x0000
};
    
    OSData * data = OSDynamicCast( OSData,
                getProperty( "HIDPointerAccelerationTable" ));
    if( data)
        data->retain();
    else
        data = OSData::withBytesNoCopy( accl, sizeof( accl ) );
        
    return( data );
}
