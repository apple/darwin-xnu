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

#include <IOKit/adb/IOADBDevice.h>
#include <IOKit/graphics/IODisplay.h>


#define	kOrgDisplayAddr 		0x7	// Original display ADB address

#define kTelecasterADBHandlerID		0x03
#define kSmartDisplayADBHandlerID	0xc0

#define	kADBReg0			0x0	// Device register zero
#define	kADBReg1			0x1	// Device register one
#define	kADBReg2			0x2	// Device register two
#define	kADBReg3			0x3	// Device register three

#define	kReg2DataRdy			0xFD	// data (to be read) ready
#define	kReg2DataAck			0xFE	// data (just written) OK
#define kWiggleLADAddr			0x04	// 0x0f on Telecaster & Sousa?

#if 0

#define	kNoDevice		-1
#define	kTelecaster		0
#define	kSousaSoundUnit		1
#define	kHammerhead		2
#define	kOrca			3
#define	kWhaler			4
#define kWarriorEZ		5
#define kManta			6
#define kLastDeviceType		kManta

#define kDisplayLocalRemoteLADAddr	0x02	// lad address used in SetDisplayRemoteMode
#define kAudioKeypadEnableLADAddr	0x7D

#define kUnknown	-1
#define kLocal		0
#define kRemote		1

#endif

class AppleADBDisplay: public IODisplay
{
    OSDeclareDefaultStructors(AppleADBDisplay)

private:

    IOADBDevice * 	adbDevice;
    volatile UInt8	waitAckValue;
    UInt8		wiggleLADAddr;
    SInt16		avDisplayID;
    int			numModes;
    UInt32	 *	modeList;

    virtual IOReturn findADBDisplayInfoForType( UInt16 deviceType );
    virtual IOReturn getConnectFlagsForDisplayMode(
			IODisplayModeID mode, UInt32 * flags );
    virtual IOReturn doConnect( void );
    virtual IOReturn writeWithAcknowledge( UInt8 regNum, UInt16 data,
				UInt8 ackValue );
    virtual IOReturn setLogicalRegister( UInt16 address, UInt16 data );
    virtual IOReturn getLogicalRegister( UInt16 address, UInt16 * data );
    virtual void setWiggle( bool active );
    virtual bool tryAttach( IODisplayConnect * connect );

public:

    virtual bool start( IOService * nub );
    virtual IOService * probe( IOService * nub, SInt32 * score );

    virtual void packet( UInt8 adbCommand,
                                IOByteCount length, UInt8 * data );

};
