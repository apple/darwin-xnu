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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  23 Jul 98 - start IOKit
 */

#ifndef _IOKIT_IODISPLAY_H
#define _IOKIT_IODISPLAY_H

#include <IOKit/IOService.h>
#include <IOKit/graphics/IOFramebuffer.h>

extern const OSSymbol *	gIODisplayParametersKey;
extern const OSSymbol *	gIODisplayGUIDKey;

extern const OSSymbol *	gIODisplayValueKey;
extern const OSSymbol *	gIODisplayMinValueKey;
extern const OSSymbol *	gIODisplayMaxValueKey;

extern const OSSymbol *	gIODisplayContrastKey;
extern const OSSymbol *	gIODisplayBrightnessKey;
extern const OSSymbol *	gIODisplayHorizontalPositionKey;
extern const OSSymbol * gIODisplayHorizontalSizeKey;
extern const OSSymbol *	gIODisplayVerticalPositionKey;
extern const OSSymbol *	gIODisplayVerticalSizeKey;
extern const OSSymbol *	gIODisplayTrapezoidKey;
extern const OSSymbol *	gIODisplayPincushionKey;
extern const OSSymbol *	gIODisplayParallelogramKey;
extern const OSSymbol *	gIODisplayRotationKey;

extern const OSSymbol *	gIODisplayParametersCommitKey;
extern const OSSymbol *	gIODisplayParametersDefaultKey;

enum {
    kIODisplayMaxPowerStates = 4
};

struct DisplayPMVars // these are the private instance variables for power management
{
    IOIndex	connectIndex;
    // control bytes we send to the framebuffer to control syncs
    UInt32	syncControls[kIODisplayMaxPowerStates];
    // mask bits that go with the control byte
    UInt32	syncMask;
    // current state of sync signals
    UInt32	currentSyncs;
    // highest state number normally, lowest usable state in emergency
    unsigned long max_display_state;
    bool displayIdle;		// true if the display has had power lowered due to user inactivity
    bool powerControllable;	// false if no sync control available on video display
};

class IODisplayConnect : public IOService
{
    OSDeclareDefaultStructors(IODisplayConnect)

private:
    IOIndex	connection;

public:
    virtual bool initWithConnection( IOIndex connection );
    virtual IOFramebuffer * getFramebuffer( void );
    virtual IOIndex getConnection( void );
    virtual IOReturn getAttributeForConnection( IOIndex,  IOSelect, UInt32  * );
    virtual IOReturn setAttributeForConnection( IOIndex, IOSelect, UInt32 );
    virtual void joinPMtree ( IOService * driver );
};

class IODisplay : public IOService
{
    OSDeclareAbstractStructors(IODisplay)

public:
    static void initialize( void );

private:

    // used to query the framebuffer controller
    IODisplayConnect *	connection;
protected:
    // pointer to protected instance variables for power management
    struct DisplayPMVars * displayPMVars;

    /* Reserved for future expansion. */
    int 		_IODisplay_reserved[2];

    virtual void initForPM ( IOService * );

    virtual IOReturn setProperties( OSObject * properties );

    virtual  IOReturn setAggressiveness ( unsigned long, unsigned long newLevel );
    virtual IOReturn setPowerState ( unsigned long, IOService* );
    virtual  unsigned long maxCapabilityForDomainState  ( IOPMPowerFlags );
    virtual unsigned long initialPowerStateForDomainState ( IOPMPowerFlags );
    virtual  unsigned long  powerStateForDomainState ( IOPMPowerFlags );

public:
    virtual IOService * probe(	IOService * 	provider,
				SInt32 *	score );

    virtual bool start( IOService * provider );
    
    virtual IODisplayConnect * getConnection( void );

    virtual IOReturn getConnectFlagsForDisplayMode(
		IODisplayModeID mode, UInt32 * flags ) = 0;

    virtual IOReturn getGammaTableByIndex(
	UInt32 * channelCount, UInt32 * dataCount,
    	UInt32 * dataWidth, void ** data );

   virtual void dropOneLevel ( void );
   virtual void makeDisplayUsable ( void );
   IOReturn registerPowerDriver ( IOService*, IOPMPowerState*, unsigned long );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class AppleSenseDisplay : public IODisplay
{
    OSDeclareDefaultStructors(AppleSenseDisplay)

public:
    virtual IOService * probe(	IOService * 	provider,
                                SInt32 *	score );

    virtual IOReturn getConnectFlagsForDisplayMode(
                IODisplayModeID mode, UInt32 * flags );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class AppleNoSenseDisplay : public IODisplay
{
    OSDeclareDefaultStructors(AppleNoSenseDisplay)

public:
    virtual IOReturn getConnectFlagsForDisplayMode(
                IODisplayModeID mode, UInt32 * flags );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#endif /* ! _IOKIT_IODISPLAY_H */

