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
 * sdouglas  18 May 98 - make loadable.
 * sdouglas  23 Jul 98 - start IOKit
 * sdouglas  08 Dec 98 - start cpp
 */

#include <libkern/OSAtomic.h>
#include <IOKit/graphics/IODisplay.h>
#include <IOKit/IOLib.h>
#include <IOKit/assert.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

const OSSymbol * gIODisplayParametersKey;
const OSSymbol * gIODisplayGUIDKey;

const OSSymbol * gIODisplayValueKey;
const OSSymbol * gIODisplayMinValueKey;
const OSSymbol * gIODisplayMaxValueKey;

const OSSymbol * gIODisplayContrastKey;
const OSSymbol * gIODisplayBrightnessKey;
const OSSymbol * gIODisplayHorizontalPositionKey;
const OSSymbol * gIODisplayHorizontalSizeKey;
const OSSymbol * gIODisplayVerticalPositionKey;
const OSSymbol * gIODisplayVerticalSizeKey;
const OSSymbol * gIODisplayTrapezoidKey;
const OSSymbol * gIODisplayPincushionKey;
const OSSymbol * gIODisplayParallelogramKey;
const OSSymbol * gIODisplayRotationKey;

const OSSymbol * gIODisplayParametersCommitKey;
const OSSymbol * gIODisplayParametersDefaultKey;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClass( IODisplay, IOService )
OSDefineAbstractStructors( IODisplay, IOService )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IODisplay::initialize( void )
{
    gIODisplayParametersKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayParametersKey );
    gIODisplayGUIDKey		= OSSymbol::withCStringNoCopy(
                                kIODisplayGUIDKey );
    gIODisplayValueKey		= OSSymbol::withCStringNoCopy(
                                kIODisplayValueKey );
    gIODisplayMinValueKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayMinValueKey );
    gIODisplayMaxValueKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayMaxValueKey );
    gIODisplayContrastKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayContrastKey );
    gIODisplayBrightnessKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayBrightnessKey );
    gIODisplayHorizontalPositionKey = OSSymbol::withCStringNoCopy(
                                kIODisplayHorizontalPositionKey );
    gIODisplayHorizontalSizeKey = OSSymbol::withCStringNoCopy(
                                kIODisplayHorizontalSizeKey );
    gIODisplayVerticalPositionKey = OSSymbol::withCStringNoCopy(
                                kIODisplayVerticalPositionKey );
    gIODisplayVerticalSizeKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayVerticalSizeKey );
    gIODisplayTrapezoidKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayTrapezoidKey );
    gIODisplayPincushionKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayPincushionKey );
    gIODisplayParallelogramKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayParallelogramKey );
    gIODisplayRotationKey	= OSSymbol::withCStringNoCopy(
                                kIODisplayRotationKey );

    gIODisplayParametersCommitKey  = OSSymbol::withCStringNoCopy(
                                kIODisplayParametersCommitKey );
    gIODisplayParametersDefaultKey = OSSymbol::withCStringNoCopy(
                                kIODisplayParametersDefaultKey );
}

IOService * IODisplay::probe(	IOService * 	provider,
				SInt32 *	score )
{
    connection = OSDynamicCast(IODisplayConnect, provider);

    return( this );
}

IODisplayConnect * IODisplay::getConnection( void )
{
    return( connection );
}


IOReturn IODisplay::getGammaTableByIndex(
	UInt32 * /* channelCount */, UInt32 * /* dataCount */,
    	UInt32 * /* dataWidth */, void ** /* data */ )
{
    return( kIOReturnUnsupported);
}


bool IODisplay::start( IOService * provider )
{
    if ( super::start(provider) ) {
        if ( connection != NULL ) {
            displayPMVars =  (DisplayPMVars *)IOMalloc(sizeof(DisplayPMVars));	// make space for our variables
            assert( displayPMVars );
            displayPMVars->displayIdle = false;					// initialize some
            initForPM(provider);							// initialize power management of the device
            registerService();
        }
        return true;
    }
    return false;
}

IOReturn IODisplay::setProperties( OSObject * properties )
{
    IOService *		handler;
    OSDictionary *	dict;
    OSDictionary *	dict2;

    dict = OSDynamicCast( OSDictionary, properties);
    if( !dict)
        return( kIOReturnUnsupported );

    dict2 = OSDynamicCast( OSDictionary, dict->getObject(gIODisplayParametersKey));
    if( dict2)
        dict = dict2;

    handler = getClientWithCategory(gIODisplayParametersKey);
    if( !handler)
        return( kIOReturnUnsupported );

    return( handler->setProperties( dict ) );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
This is the power-controlling driver for a display.  It also acts as an agent of the policy-maker for display power
 which is the DisplayWrangler.  The Display Wrangler calls here to lower power by one state when it senses
 no user activity.  It also calls here to make the display usable after it has been idled down, and it also calls
 here to make the display barely usable if it senses a power emergency (e.g. low battery).

 This driver assumes a video display, and it calls the framebuffer driver to control the sync signals.  Non-video
 display drivers (e.g. flat panels) subclass IODisplay and override this and other  appropriate methods.
 */

static IOPMPowerState ourPowerStates[kIODisplayMaxPowerStates] = {
  {1,0,0,0,0,0,0,0,0,0,0,0},
//  {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
//  {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
  {1,0,0,0,0,0,0,0,0,0,0,0},
  {1,0,0,0,0,0,0,0,0,0,0,0},
  {1,IOPMDeviceUsable+IOPMMaxPerformance,0,IOPMPowerOn,0,0,0,0,0,0,0,0}
};


void IODisplay::initForPM ( IOService * provider )
{
    UInt32		capabilities = 0;
    unsigned long number_of_power_states;
    UInt32		currentSyncs = 0;
    IOReturn	err;

    displayPMVars->connectIndex = connection->getConnection();		// find out our index in the nub
    
    // what are the sync-controlling capabilities of the framebuffer?
    err = connection->getAttributeForConnection(  displayPMVars->connectIndex,
				kConnectionSyncEnable, &capabilities );

    // find out current state of sync lines
    err = connection->getAttributeForConnection(  displayPMVars->connectIndex,
				kConnectionSyncFlags, &currentSyncs );

    displayPMVars->currentSyncs = currentSyncs;
    displayPMVars->powerControllable = true;

    if ( (capabilities & kIOHSyncDisable) &&
         (capabilities & kIOVSyncDisable) &&
         !(capabilities & kIONoSeparateSyncControl ) ) {		// four power states
        number_of_power_states = 4;
        displayPMVars->syncControls[0] = 0 | kIOHSyncDisable | kIOVSyncDisable | kIOCSyncDisable;
        displayPMVars->syncControls[1] = 0 | kIOVSyncDisable | kIOCSyncDisable;
        displayPMVars->syncControls[2] = 0 | kIOHSyncDisable | kIOCSyncDisable;
        displayPMVars->syncControls[3] = 0;
        displayPMVars->syncMask = capabilities & (kIOHSyncDisable | kIOVSyncDisable | kIOCSyncDisable);
    }
    else {
        if ( capabilities & kIOCSyncDisable ) {		// two power states
            number_of_power_states = 2;
            ourPowerStates[1].capabilityFlags = ourPowerStates[3].capabilityFlags;
            displayPMVars->syncControls[0] = 0 | kIOCSyncDisable;
            displayPMVars->syncControls[1] = 0;
            displayPMVars->syncMask = 0 | kIOCSyncDisable;
        }
        else {						// two power states and not controllable
            number_of_power_states = 2;
            ourPowerStates[1].capabilityFlags = ourPowerStates[3].capabilityFlags;
            ourPowerStates[0].capabilityFlags |= IOPMNotAttainable;
            ourPowerStates[1].capabilityFlags |= IOPMNotAttainable;
            displayPMVars->syncControls[0] = displayPMVars->currentSyncs;
            displayPMVars->syncControls[1] = displayPMVars->currentSyncs;
            displayPMVars->syncMask = displayPMVars->currentSyncs;
            displayPMVars->powerControllable = false;
        }
    }

    PMinit();							// initialize superclass variables
    provider->joinPMtree(this);					// attach into the power management hierarchy

    registerPowerDriver(this,ourPowerStates,number_of_power_states);	// register ourselves with policy-maker (us)

}


//*********************************************************************************
// registerPowerDriver
//
// We intercept this call to our superclass just to snoop early on
// the number of power states.
//*********************************************************************************

IOReturn IODisplay::registerPowerDriver ( IOService* x, IOPMPowerState*y, unsigned long numberOfStates )
{
    displayPMVars->max_display_state = numberOfStates - 1;
    return super::registerPowerDriver(x,y,numberOfStates);
}


//*********************************************************************************
// setAggressiveness
//
// We are informed by our power domain parent of a new level of "power management
// aggressiveness".  Our only interest is if it implies a power management
// emergency, in which case we keep the display brightness low.
//*********************************************************************************

IOReturn IODisplay::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
    unsigned long i;

    if ( type == kPMGeneralAggressiveness  ) {
        if ( newLevel >= kIOPowerEmergencyLevel ) {				// emergency level
            for ( i = 0; i < pm_vars->theNumberOfPowerStates; i++ ) {			// find lowest usable state
                if ( pm_vars->thePowerStates[i].capabilityFlags & IOPMDeviceUsable ) {
                    break;
                }
            }
            displayPMVars->max_display_state = i;
            if ( pm_vars->myCurrentState > i ) {					// if we are currently above that,
                changePowerStateToPriv(i);						// drop to emergency level
            }
        }
        else {								// not emergency level
            if ( pm_vars->aggressiveness >= kIOPowerEmergencyLevel ) {			// but it was emergency level
                displayPMVars->max_display_state =  pm_vars->theNumberOfPowerStates - 1;
                if ( ! displayPMVars->displayIdle ) {
                    changePowerStateToPriv(displayPMVars->max_display_state);		// return to normal usable level
                }
            }
        }
    }
    super::setAggressiveness(type, newLevel);
    return IOPMNoErr;
}


// **********************************************************************************
// dropOneLevel
//
// Called by the display wrangler when it decides there hasn't been user
// activity for a while.  We drop one power level.  This can be called by the
// display wrangler before we have been completely initialized.
// **********************************************************************************
void IODisplay::dropOneLevel ( void )
{
    if ( initialized && displayPMVars->powerControllable) {
        displayPMVars->displayIdle = true;
        if ( pm_vars != NULL ) {
            if ( pm_vars->myCurrentState > 0 ) {
                changePowerStateToPriv(pm_vars->myCurrentState - 1);	// drop a level
            }
            else {
                changePowerStateToPriv(0);	// this may rescind previous request for domain power
            }
        }
    }
}


//*********************************************************************************
// makeDisplayUsable
//
// The DisplayWrangler has sensed user activity after we have idled the
// display and wants us to make it usable again.  We are running on its
// workloop thread.  This can be called before we are completely
// initialized.
//*********************************************************************************
void IODisplay::makeDisplayUsable ( void )
{
    if ( initialized && displayPMVars->powerControllable) {
        displayPMVars->displayIdle = false;
        if ( pm_vars != NULL ) {
            changePowerStateToPriv(displayPMVars->max_display_state);
        }
    }
}


// **********************************************************************************
// setPowerState
//
// Called by the superclass to change the display power state.
// **********************************************************************************
IOReturn IODisplay::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
    UInt32 flags;
    if( initialized) {
        flags =(displayPMVars->syncControls[powerStateOrdinal])<<8;
        flags |= displayPMVars->syncMask;
        displayPMVars->currentSyncs = displayPMVars->syncControls[powerStateOrdinal];
        connection->setAttributeForConnection( displayPMVars->connectIndex, kConnectionSyncEnable, flags );
    }
    return IOPMAckImplied;
}


// **********************************************************************************
// maxCapabilityForDomainState
//
// This simple device needs only power.  If the power domain is supplying
// power, the display can go to its highest state.  If there is no power
// it can only be in its lowest state, which is off.
// **********************************************************************************
unsigned long  IODisplay::maxCapabilityForDomainState ( IOPMPowerFlags domainState )
{
   if ( domainState &  IOPMPowerOn ) {
       return pm_vars->theNumberOfPowerStates-1;
   }
   else {
       return 0;
   }
}


// **********************************************************************************
// initialPowerStateForDomainState
//
// The power domain may be changing state.  If power is on in the new
// state, that will not affect our state at all.  In that case ask the ndrv
// what our current state is.  If domain power is off, we can attain
// only our lowest state, which is off.
// **********************************************************************************
unsigned long  IODisplay::initialPowerStateForDomainState ( IOPMPowerFlags domainState )
{
   long unsigned i;

   if ( domainState &  IOPMPowerOn ) {			// domain has power
       for ( i =  pm_vars->theNumberOfPowerStates-1; i > 0; i-- ) {	// compare to our table to find current power state
           if ( (displayPMVars->syncControls[i] & displayPMVars->syncMask)
		== (displayPMVars->currentSyncs & displayPMVars->syncMask) ) {
               break;
           }
       }
       return i;
   }
   else {
       return 0;						// domain is down, so display is off
   }
}


// **********************************************************************************
// powerStateForDomainState
//
// The power domain may be changing state.  If power is on in the new
// state, that will not affect our state at all.  In that case ask the ndrv
// what our current state is.  If domain power is off, we can attain
// only our lowest state, which is off.
// **********************************************************************************
unsigned long  IODisplay::powerStateForDomainState ( IOPMPowerFlags domainState )
{
   long unsigned i;

   if ( domainState &  IOPMPowerOn ) {			// domain has power
       for ( i =  pm_vars->theNumberOfPowerStates-1; i > 0; i-- ) {	// compare to our table to find current power state
           if ( (displayPMVars->syncControls[i] & displayPMVars->syncMask)
	        == (displayPMVars->currentSyncs & displayPMVars->syncMask) ) {
               break;
           }
       }
       return i;
   }
   else {
       return 0;						// domain is down, so display is off
   }
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IODisplay

OSDefineMetaClassAndStructors(AppleSenseDisplay, IODisplay)


IOService * AppleSenseDisplay::probe(	IOService * 	provider,
					SInt32 *	score )
{
    IODisplayConnect *	connect;
    IOFramebuffer *	framebuffer;
    IOService *		ret = 0;
    UInt32		sense, extSense;
    UInt32		senseType, displayType;

    do {

	if( 0 == super::probe( provider, score ))
            continue;

	connect = getConnection();
	if( !connect)
            continue;

	framebuffer = connect->getFramebuffer();
	assert( framebuffer );

        if( kIOReturnSuccess != framebuffer->getAttributeForConnection(
				connect->getConnection(),
				kConnectionSupportsAppleSense, NULL ))
            continue;

	ret = this;

        if( kIOReturnSuccess != framebuffer->getAppleSense(
                            connect->getConnection(),
                            &senseType, &sense, &extSense, &displayType ))
	    continue;
        sense = ((sense & 0xff) << 8) | (extSense & 0xff);
        setProperty( kDisplayProductID, sense, 32);
        setProperty( kDisplayVendorID, kDisplayVendorIDUnknown, 32);
        setProperty( "AppleDisplayType", displayType, 32);

    } while( false);

    return( ret );
}

IOReturn AppleSenseDisplay::getConnectFlagsForDisplayMode(
		IODisplayModeID mode, UInt32 * flags )
{
    IOFramebuffer *	framebuffer;
    IODisplayConnect *	connect;

    connect = getConnection();
    framebuffer = connect->getFramebuffer();

    return( framebuffer->connectFlags(
                            connect->getConnection(),
                            mode, flags ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#undef super
#define super IODisplay

OSDefineMetaClassAndStructors(AppleNoSenseDisplay, IODisplay)


IOReturn AppleNoSenseDisplay::getConnectFlagsForDisplayMode(
		IODisplayModeID /* mode */, UInt32 * flags)
{
    *flags = kDisplayModeValidFlag | kDisplayModeSafeFlag;

    setProperty( kDisplayProductID, kDisplayProductIDGeneric, 32);
    setProperty( kDisplayVendorID, kDisplayVendorIDUnknown, 32);

    return( kIOReturnSuccess );
}


