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
#ifndef _IOHIPOINTING_H
#define _IOHIPOINTING_H

#include <IOKit/hidsystem/IOHIPointing.h>
#include <IOKit/hidsystem/IOHIDevice.h>
#include <IOKit/hidsystem/IOHIDTypes.h>

/* Start Action Definitions */

/*
 * HISTORICAL NOTE:
 *   The following entry points were part of the IOHIPointingEvents
 *   protocol.
 */
typedef void (*RelativePointerEventAction)(OSObject * target,
                        /* buttons */      int        buttons,
                        /* deltaX */       int        dx,
                        /* deltaY */       int        dy,
                        /* atTime */       AbsoluteTime ts);

typedef void (*AbsolutePointerEventAction)(OSObject * target,
                        /* buttons */      int        buttons,
                        /* at */           Point *    newLoc,
                        /* withBounds */   Bounds *   bounds,
                        /* inProximity */  bool       proximity,
                        /* withPressure */ int        pressure,
                        /* withAngle */    int        stylusAngle,
                        /* atTime */       AbsoluteTime ts);

typedef void (*ScrollWheelEventAction)(OSObject * target,
                                       short      deltaAxis1,
                                       short      deltaAxis2,
                                       short      deltaAxis3,
                                       AbsoluteTime ts);

/* End Action Definitions */

class IOHIPointing : public IOHIDevice
{
    OSDeclareDefaultStructors(IOHIPointing);

private:
    IOLock *		_deviceLock;  // Lock for all device access
    int			_buttonMode;  // The "handedness" of the pointer
    IOFixed		_acceleration;
    bool		_convertAbsoluteToRelative;
    bool		_contactToMove;
    bool		_hadContact;
    Point		_previousLocation;
    UInt8		_pressureThresholdToClick;	// A scale factor of 0 to 255 to determine how much pressure is necessary to generate a primary mouse click - a value of 255 means no click will be generated
    void *		_scaleSegments;
    IOItemCount		_scaleSegCount;
    IOFixed		_fractX;
    IOFixed		_fractY;

    OSObject *                 _relativePointerEventTarget;
    RelativePointerEventAction _relativePointerEventAction;
    OSObject *                 _absolutePointerEventTarget;
    AbsolutePointerEventAction _absolutePointerEventAction;
    OSObject *                 _scrollWheelEventTarget;
    ScrollWheelEventAction     _scrollWheelEventAction;
    

protected:
  virtual void dispatchRelativePointerEvent(int        dx,
                                            int        dy,
                                            UInt32     buttonState,
                                            AbsoluteTime ts);
    
  virtual void dispatchAbsolutePointerEvent(Point *	newLoc,
                                            Bounds *	bounds,
                                            UInt32	buttonState,
                                            bool	proximity,
                                            int		pressure,
                                            int		pressureMin,
                                            int		pressureMax,
                                            int		stylusAngle,
                                            AbsoluteTime	ts);

  virtual void dispatchScrollWheelEvent(short deltaAxis1,
                                        short deltaAxis2,
                                        short deltaAxis3,
                                        AbsoluteTime ts);

public:
  virtual bool init(OSDictionary * properties = 0);
  virtual bool start(IOService * provider);
  virtual void free();

  virtual bool open(IOService *                client,
		    IOOptionBits	       options,
                    RelativePointerEventAction rpeAction,
                    AbsolutePointerEventAction apeAction,
                    ScrollWheelEventAction     sweAction);
  virtual void close(IOService * client, IOOptionBits );

  virtual IOHIDKind hidKind();
  virtual bool 	    updateProperties( void );
  virtual IOReturn  setParamProperties(OSDictionary * dict);
  IOReturn powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
  IOReturn powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
  IOService *	_rootDomain; //Needs to be public for C function use


protected: // for subclasses to implement
  virtual OSData * copyAccelerationTable();
  virtual IOItemCount buttonCount();
  virtual IOFixed     resolution();

private:
  virtual bool resetPointer();
  virtual void scalePointer(int * dxp, int * dyp);
  virtual void setupForAcceleration(IOFixed accl);
};

#endif /* !_IOHIPOINTING_H */
