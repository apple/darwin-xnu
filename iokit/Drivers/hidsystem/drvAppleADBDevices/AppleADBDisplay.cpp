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
 * Copyright (c) 1997-1998 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  23 Jul 98 - start IOKit
 * suurballe 17 Nov 98 - ported to C++
 */

#include <assert.h>
#include <IOKit/IOLib.h>

#include "AppleADBDisplay.h"


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IODisplay
OSDefineMetaClassAndStructors( AppleADBDisplay, IODisplay )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn AppleADBDisplay::findADBDisplayInfoForType( UInt16 deviceType )
{
    char	stringBuf[ 32 ];
    OSNumber *	off;
    OSString *	key;
    OSData *	data;

    sprintf( stringBuf, "adb%dWiggle", deviceType);
    if( (off = OSDynamicCast( OSNumber, getProperty( stringBuf ))))
        wiggleLADAddr = off->unsigned32BitValue();
    else
        wiggleLADAddr = kWiggleLADAddr;

    sprintf( stringBuf, "adb%dModes", deviceType);
    key = OSDynamicCast( OSString, getProperty( stringBuf ));

    if( key && (data = OSDynamicCast( OSData, getProperty( key )))) {
	modeList = (UInt32 *) data->getBytesNoCopy();
	numModes = data->getLength() / sizeof( UInt32);
    }
    if( modeList )
        return(kIOReturnSuccess);
    else
        return( -49 );
}


IOReturn AppleADBDisplay::getConnectFlagsForDisplayMode(
			IODisplayModeID mode, UInt32 * flags )
{
    IOReturn		err;
    IODisplayConnect *	connect;
    IOFramebuffer *	framebuffer;
    int			timingNum;
    IOTimingInformation	info;

    *flags = 0;

    connect = getConnection();
    assert( connect );
    framebuffer = connect->getFramebuffer();
    assert( framebuffer );
  
    err = framebuffer->getTimingInfoForDisplayMode( mode, &info );

    if( kIOReturnSuccess == err) {
        for( timingNum = 0; timingNum < numModes; timingNum++ ) {
            if( info.appleTimingID == modeList[ timingNum ] ) {
                *flags = timingNum
		    ? ( kDisplayModeValidFlag | kDisplayModeSafeFlag )
                    : ( kDisplayModeValidFlag | kDisplayModeSafeFlag
		        | kDisplayModeDefaultFlag );
                break;
            }
        }
    }

    return( err );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn AppleADBDisplay::doConnect( void )
{
    IOReturn   		err;
    UInt16 		value;
    UInt32		retries = 9;
    IOByteCount		length;

    while ( retries-- ) {

	value = 0x6000 | (adbDevice->address() << 8);
	length = sizeof( value);
	err = adbDevice->writeRegister( 3, (UInt8 *) &value, &length );
	if( err)
            continue;

	/* IOSleep(10); */
	/* IODelay(1000); */
	length = sizeof( value);
	err = adbDevice->readRegister( 3, (UInt8 *) &value, &length );
    	if( err)
	    continue;

	if( (value & 0xf000) == 0x6000 )
	    break;
	else
	    err = kIOReturnNotAttached;
    }

    if( err)
        kprintf("%s: %d\n", __FUNCTION__, err);

    return(err);
}

static void autoPollHandler( IOService * self, UInt8 adbCommand,
                                IOByteCount length, UInt8 * data )
{
    ((AppleADBDisplay *)self)->packet( adbCommand, length, data );
}

void AppleADBDisplay::packet( UInt8 adbCommand,
                                IOByteCount length, UInt8 * data )
{
    if( length && (*data == waitAckValue) )
        waitAckValue = 0;
}

IOReturn AppleADBDisplay::writeWithAcknowledge( UInt8 regNum,
				UInt16 data, UInt8 ackValue )
{
    IOReturn	err;
    enum	{ kTimeoutMS = 400 };
    UInt32	timeout;
    IOByteCount	length;

    waitAckValue = ackValue;

    length = sizeof(data);
    err = adbDevice->writeRegister( regNum, (UInt8 *) &data, &length );

    if( !err) {
        timeout = kTimeoutMS / 50;
        while( waitAckValue && timeout-- )
            IOSleep( 50 );

        if( waitAckValue )
            err = -3;
    }
    waitAckValue = 0;

    return( err );
}

IOReturn AppleADBDisplay::setLogicalRegister( UInt16 address, UInt16 data )
{
    IOReturn	err = -1;
    UInt32	reconnects = 3;

    while( err && reconnects-- ) {
	err = writeWithAcknowledge( kADBReg1, address, kReg2DataRdy);
	if( err == kIOReturnSuccess )
	    err = writeWithAcknowledge( kADBReg2, data, kReg2DataAck);

	if( err ) {
	    if( doConnect() )
		break;
	}
    }
    if( err)
        kprintf( "%s: %x, %d\n", __FUNCTION__, address, err);

    return( err);
}

IOReturn AppleADBDisplay::getLogicalRegister( UInt16 address, UInt16 * data )
{
    IOReturn	err = -1;
    UInt32	reconnects = 3;
    UInt16	value;
    IOByteCount	length;

    while ( err && reconnects--) {
	err = writeWithAcknowledge( kADBReg1, address, kReg2DataRdy);
	if( err == kIOReturnSuccess ) {
            length = sizeof( value);
            err = adbDevice->readRegister( 2, (UInt8 *)&value, &length);
	    *data = value & 0xff;		// actually only 8 bits
	}
	if( err) {
	    if ( doConnect())
		break;
	}
    }
    if( err)
	kprintf( "%s: %x=%x, %d\n", __FUNCTION__, address, *data, err);

    return err;
}

void AppleADBDisplay::setWiggle( bool active )
{
    setLogicalRegister( wiggleLADAddr, (active ? 1 : 0));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleADBDisplay::start( IOService * nub )
{
    IOReturn	err;
    UInt16	data, deviceType;

    if( !super::start( nub))
        return false;

    if( OSDynamicCast( IODisplayConnect, nub ))
	return( true );

    assert( OSDynamicCast( IOADBDevice, nub ));
    adbDevice = (IOADBDevice *) nub;

    if( !adbDevice->seizeForClient( this, &autoPollHandler) ) {
        IOLog("%s: sieze failed\n", getName());
        return( false);
    }

    do {
	err = doConnect();
	if( err )
	    continue;

	err = setLogicalRegister( 0xff, 0xff);
	if( err)
	    continue;

	err = getLogicalRegister( 0xff, &data);
	if( err)
	    continue;

	err = getLogicalRegister( 0xff, &deviceType);
	if( err)
	    continue;

	kprintf("%s: found AVType %d\n",
		adbDevice->getName(), deviceType );

	err = findADBDisplayInfoForType( deviceType );
	if( err)
	    continue;

	avDisplayID = deviceType;
	setWiggle( false);

	registerService();
	return( true );

    } while( false );

    adbDevice->releaseFromClient( this );
    return( false );
}


bool AppleADBDisplay::tryAttach( IODisplayConnect * connect )
{
    IOReturn		err;
    bool		attached = false;
    UInt32		sense, extSense;
    IOFramebuffer *	framebuffer;
    IOIndex		fbConnect;
    UInt32		senseType;
    enum {
        kRSCFour	= 4,
        kRSCSix		= 6,
        kESCFourNTSC	= 0x0A,
        kESCSixStandard	= 0x2B,
    };

    do {

	framebuffer = connect->getFramebuffer();
	fbConnect = connect->getConnection();
	assert( framebuffer );

        if( kIOReturnSuccess != framebuffer->getAttributeForConnection(
				fbConnect,
				kConnectionSupportsAppleSense, NULL ))
            continue;

	err = framebuffer->getAppleSense( fbConnect,
				&senseType, &sense, &extSense, 0 );
	if( err)
	    continue;
	if( (sense != kRSCSix) || (extSense != kESCSixStandard) )	// straight-6
	    continue;

	setWiggle( true );
	err = framebuffer->getAppleSense( fbConnect,
				&senseType, &sense, &extSense, 0 );
	setWiggle( false );
	if( err)
	    continue;
	if( (sense != kRSCFour) || (extSense != kESCFourNTSC) )		// straight-4
	    continue;

 	kprintf( "%s: attached to %s\n",
		adbDevice->getName(), framebuffer->getName() );

	attached = true;

    } while( false);

    return( attached);
}


IOService * AppleADBDisplay::probe( IOService * nub, SInt32 * score )
{
    IODisplayConnect *	connect;

    // both ADB device & display connections come here!

    do {
        if( OSDynamicCast( IOADBDevice, nub))
	    continue;

        if( (connect = OSDynamicCast( IODisplayConnect, nub))
         && tryAttach( connect))
	    continue;

	nub = 0;

    } while( false );

    if( nub)
	return( super::probe( nub, score ));
    else
	return( 0 );
}



