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
 * Copyright (c) 1999 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  18 Mar 99 - first checked in.
 */


#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>

#include "IODisplayWrangler.h"

bool wranglerHasRoot( OSObject * us, void *, IOService * yourDevice );

#define	DODEFAULTMODE	0

#if DODEFAULTMODE
enum {
    kAquaMinWidth	= 800,
    kAquaMinHeight	= 600
};
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// tiddly nub

#undef super
#define super IOService

OSDefineMetaClassAndStructors(IODisplayConnect, IOService)

bool IODisplayConnect::initWithConnection( IOIndex _connection )
{
    char	name[ 12 ];

    if( !super::init())
	return( false);

    connection = _connection;

    sprintf( name, "display%ld", connection);

    setName( name);

    return( true);
}

IOFramebuffer * IODisplayConnect::getFramebuffer( void )
{
    return( (IOFramebuffer *) getProvider());
}

IOIndex IODisplayConnect::getConnection( void )
{
    return( connection);
}

IOReturn  IODisplayConnect::getAttributeForConnection( IOIndex connectIndex,  IOSelect selector, UInt32  * value )
{
   return ((IOFramebuffer *) getProvider())->getAttributeForConnection( connectIndex,  selector,  value );
}

IOReturn  IODisplayConnect::setAttributeForConnection( IOIndex connectIndex, IOSelect selector, UInt32  info )
{
   return ((IOFramebuffer *) getProvider())->setAttributeForConnection( connectIndex,  selector,  info );
}


//*********************************************************************************
// joinPMtree
//
// The policy-maker in the display driver calls here when initializing.
// We attach it into the power management hierarchy as a child of our
// frame buffer. 
//*********************************************************************************
void IODisplayConnect::joinPMtree ( IOService * driver )
{
    getProvider()->addPowerChild(driver);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService
OSDefineMetaClassAndStructors(IODisplayWrangler, IOService);

IODisplayWrangler *	gIODisplayWrangler;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IODisplayWrangler::start( IOService * provider )
{
    OSObject *	notify;

    if( !super::start( provider))
	return( false);

    assert( gIODisplayWrangler == 0 );
    gIODisplayWrangler = this;

    fMatchingLock = IOLockAlloc();
    fFramebuffers = OSSet::withCapacity( 1 );
    fDisplays = OSSet::withCapacity( 1 );

    assert( fMatchingLock && fFramebuffers && fDisplays );

    notify = addNotification( gIOPublishNotification,
        serviceMatching("IODisplay"), _displayHandler,
        this, fDisplays );
    assert( notify );

    notify = addNotification( gIOPublishNotification,
        serviceMatching("IODisplayConnect"), _displayConnectHandler,
        this, 0, 50000 );
    assert( notify );

    rootDomain = NULL;
    addNotification( gIOPublishNotification,serviceMatching("IOPMrootDomain"),	// look for the Root Domain
                 (IOServiceNotificationHandler)wranglerHasRoot, this, 0 );

    // initialize power managment
    gIODisplayWrangler->initForPM();
    // set default screen-dim timeout
    gIODisplayWrangler->setAggressiveness ( kPMMinutesToDim, 30 );

    return( true );
}


bool wranglerHasRoot( OSObject * us, void *, IOService * yourDevice )
{
    if ( yourDevice != NULL ) {
        ((IODisplayWrangler *)us)->rootDomain = yourDevice;
    }
    return true;
}


bool IODisplayWrangler::_displayHandler( void * target, void * ref,
                            IOService * newService )
{

    return( ((IODisplayWrangler *)target)->displayHandler( (OSSet *) ref, 
		(IODisplay *) newService ));
}

bool IODisplayWrangler::_displayConnectHandler( void * target, void * ref,
                            IOService * newService )
{
    return( ((IODisplayWrangler *)target)->displayConnectHandler( ref, 
		(IODisplayConnect *) newService ));
}

bool IODisplayWrangler::displayHandler( OSSet * set,
                            IODisplay * newDisplay )
{
    assert( OSDynamicCast( IODisplay, newDisplay ));
    
    IOTakeLock( fMatchingLock );

    set->setObject( newDisplay );

    IOUnlock( fMatchingLock );

    return( true );
}

bool IODisplayWrangler::displayConnectHandler( void * /* ref */,
                            IODisplayConnect * connect )
{
    SInt32		score = 50000;
    OSIterator *	iter;
    IODisplay *		display;
    bool		found = false;

    assert( OSDynamicCast( IODisplayConnect, connect ));
    
    IOTakeLock( fMatchingLock );

    iter = OSCollectionIterator::withCollection( fDisplays );
    if( iter) {
	while( !found && (display = (IODisplay *) iter->getNextObject())) {
	    if( display->getConnection())
		continue;

	    do {
		if( !display->attach( connect ))
		    continue;
		found =  ((display->probe( connect, &score ))
                        && (display->start( connect )));
		if( !found)
                    display->detach( connect );
	    } while( false);
	}
	iter->release();
    }

    IOUnlock( fMatchingLock );

    return( true);
}

IOReturn IODisplayWrangler::clientStart( IOFramebuffer * fb )
{
    IOReturn	err = kIOReturnSuccess;

//    IOTakeLock( fFBLock );

    if( gIODisplayWrangler &&
	gIODisplayWrangler->fFramebuffers->setObject( fb )) {

        // framebuffer not yet done

        err = fb->open();
        if( kIOReturnSuccess == err) {
            gIODisplayWrangler->makeDisplayConnects( fb );
	    gIODisplayWrangler->findStartupMode( fb );
	}
        // try to open it next time
        // else gIODisplayWrangler->fFramebuffers->removeObject( fb );
    }

//    IOUnlock( fFBLock );

    return( err );
}

bool IODisplayWrangler::makeDisplayConnects( IOFramebuffer * fb )
{
    IODisplayConnect *	connect;
    IOItemCount		i;

    for( i = 0; i < fb->getConnectionCount(); i++) {

	connect = new IODisplayConnect;
	if( 0 == connect)
	    continue;

	if( (connect->initWithConnection( i ))
	 && (connect->attach( fb ))) {

	    connect->registerService( kIOServiceSynchronous );
	}
	connect->release();
    }

    return( true );
}

IODisplayConnect * IODisplayWrangler::getDisplayConnect(
			IOFramebuffer * fb, IOIndex connect )
{
    OSIterator	*	iter;
    OSObject	*	next;
    IODisplayConnect *  connection = 0;

    iter = fb->getClientIterator();
    if( iter) {
	while( (next = iter->getNextObject())) {
            connection = OSDynamicCast( IODisplayConnect, next);
            if( connection && (0 == (connect--)))
		break;
	}
	iter->release();
    }
    return( connection );
}


IOReturn IODisplayWrangler::getConnectFlagsForDisplayMode(
		IODisplayConnect * connect,
		IODisplayModeID mode, UInt32 * flags )
{
    IOReturn		err = kIOReturnUnsupported;
    IODisplay * 	display;

    display = OSDynamicCast( IODisplay, connect->getClient());
    if( display)
        err = display->getConnectFlagsForDisplayMode( mode, flags );
    else {
	kprintf("%s: no display\n", connect->getFramebuffer()->getName());
        err = connect->getFramebuffer()->connectFlags( 
			connect->getConnection(), mode, flags );
    }

    return( err );
}

IOReturn IODisplayWrangler::getFlagsForDisplayMode(
		IOFramebuffer * fb,
		IODisplayModeID mode, UInt32 * flags )
{
    IODisplayConnect * 		connect;

    // should look at all connections
    connect = gIODisplayWrangler->getDisplayConnect( fb, 0 );
    if( !connect) {
	kprintf("%s: no display connect\n", fb->getName());
	return( kIOReturnUnsupported );
    }

    return( gIODisplayWrangler->
		getConnectFlagsForDisplayMode( connect, mode, flags ));
}

IOReturn IODisplayWrangler::getDefaultMode( IOFramebuffer * fb,
                                IODisplayModeID * mode, IOIndex * depth )
{
#if DODEFAULTMODE
    UInt32			thisFlags, bestFlags = 0;
    IODisplayModeID		thisMode, bestMode = 0;
    IOIndex			bestDepth;
    UInt32			i;
    IOReturn			err;
    IODisplayModeInformation	info;
    char			arg[ 64 ];
    const char *		param;
    UInt32			lookWidth, lookHeight, lookRefresh, lookDepth;
    static const char		bitsToIndex[] = { 0, 0, 1, 1, 2 };
    UInt32			numModes;
    IODisplayModeID *		allModes;
    bool			foundForced;
    bool			killedDefault = false;
    bool			haveSubst = false;

    numModes = fb->getDisplayModeCount();
    allModes = IONew( IODisplayModeID, numModes );

    if( NULL == allModes)
	return( kIOReturnNoMemory);
    err = fb->getDisplayModes( allModes );
    if( err) // leak
        return( err );

    if( PE_parse_boot_arg("dm", arg)) {

	param = arg;
	lookWidth = strtol( param, (char **) &param, 0);
	param++;
	lookHeight = strtol( param, (char **) &param, 0);
	param++;
	lookRefresh = strtol( param, (char **) &param, 0);
	param++;
	lookDepth = strtol( param, (char **) &param, 0);
	if( lookDepth == 15)
	    lookDepth = 16;
	if( lookDepth > 32)
            lookDepth = 32;

kprintf("%s: Looking %dx%d@%d,%d\n", fb->getName(), lookWidth, lookHeight,
		lookRefresh, lookDepth );

    } else {
	param = 0;
	lookWidth = 1024;
	lookHeight = 768;
	lookRefresh = 75;
	lookDepth = 16;
    }

    bestDepth = bitsToIndex[ lookDepth / 8 ];

    for( i = 0; i < numModes; i++) {

	thisMode = allModes[ i ];
        if( getFlagsForDisplayMode( fb, thisMode, &thisFlags))
	    continue;

        // make sure it does 16/32 && requested mode
        err = fb->getInformationForDisplayMode( thisMode, &info);
        if( err)
            continue;
        if( 0 == info.maxDepthIndex)
            continue;
#if 0
	kprintf("%d x %d @ %d = %x\n", info.nominalWidth, info.nominalHeight, 
		info.refreshRate >> 16, thisFlags);
#endif

	if( 0 == (thisFlags & kDisplayModeValidFlag))
	    continue;

        foundForced = (param
            && (info.nominalWidth == lookWidth)
            && (info.nominalHeight == lookHeight)
            && (((info.refreshRate + 0x8000) >> 16) == lookRefresh) );

        if( (thisFlags & kDisplayModeDefaultFlag) 
         && ((info.nominalWidth < kAquaMinWidth)
            || (info.nominalHeight < kAquaMinHeight)) ) {

            thisFlags &= ~kDisplayModeDefaultFlag;
            killedDefault = true;
            haveSubst = false;

        } else if( killedDefault 
          && (info.nominalWidth >= kAquaMinWidth)
          && (info.nominalHeight >= kAquaMinHeight) ) {

           if( thisFlags & kDisplayModeSafeFlag) {
                thisFlags |= kDisplayModeDefaultFlag;
                killedDefault = false;
            } else if( !haveSubst) {
                thisFlags |= kDisplayModeDefaultFlag;
                haveSubst = true;
            }
        }

	if( foundForced 
	|| (thisFlags & kDisplayModeDefaultFlag)
	|| (((bestFlags & kDisplayModeDefaultFlag) == 0)
		&& (thisFlags & kDisplayModeSafeFlag)) ) {

	    bestMode = thisMode;
	    bestFlags = thisFlags;

            bestDepth = bitsToIndex[ lookDepth / 8 ];
            if( bestDepth > info.maxDepthIndex)
                bestDepth = info.maxDepthIndex;

	    if( foundForced)
		break;
	}
    }

    IODelete( allModes, IODisplayModeID, numModes );

    if( bestMode) {
	*mode = bestMode;
	*depth = bestDepth;
	return( kIOReturnSuccess);
    } else
#endif	/* DODEFAULTMODE */
	return( kIOReturnUnsupported);
}

// Determine a startup mode given the framebuffer & displays

IOReturn IODisplayWrangler::findStartupMode( IOFramebuffer * fb )
{
    IODisplayModeID		mode;
    IOIndex			depth;
    IODisplayModeID		startMode;
    IOIndex			startDepth;
    IOReturn			err;

    fb->getCurrentDisplayMode( &mode, &depth);
    err = fb->getStartupDisplayMode( &startMode, &startDepth );
    if( err) {
        startMode = mode;
        startDepth = depth;
    }

#if DODEFAULTMODE
    IODisplayModeInformation	info;
    UInt32			startFlags = 0;

    do {
        err = getFlagsForDisplayMode( fb, startMode, &startFlags );
	if( err)
	    continue;
        err = fb->getInformationForDisplayMode( startMode, &info);
	if( err)
	    continue;

        if( (info.nominalWidth < kAquaMinWidth)
         || (info.nominalHeight < kAquaMinHeight)) {
            err = kIOReturnNoResources;
	    continue;
        }

        if( startDepth == 2)
            startDepth = 1;

        if( (startDepth == 0) && (info.maxDepthIndex > 0))
            startDepth = 1;

    } while( false );

    if( err
        || (startDepth == 0)
        || ((startFlags & kDisplayModeValidFlag)
                        != kDisplayModeValidFlag) ) {
        // look for default
        err = getDefaultMode( fb, &startMode, &startDepth );
    }
#endif /* DODEFAULTMODE */
    if( (startMode != mode) || (startDepth != depth))
        fb->setDisplayMode( startMode, startDepth );

    fb->setupForCurrentConfig();

    return( kIOReturnSuccess );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define kNumber_of_power_states 5

static IOPMPowerState ourPowerStates[kNumber_of_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},
    {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
    {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
    {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
    {1,IOPMDeviceUsable,0,IOPMPowerOn,0,0,0,0,0,0,0,0}

};


/*
 This is the Power Management policy-maker for the displays.  It senses when the display is idle
  and lowers power accordingly.  It raises power back up when the display becomes un-idle.

 It senses idleness with a combination of an idle timer and the "activityTickle" method call.  "activityTickle"
  is called by objects which sense keyboard activity, mouse activity, or other button activity (display contrast,
  display brightness, PCMCIA eject).  The method sets a "displayInUse" flag.  When the timer expires,
  this flag is checked.  If it is on, the display is judged "in use".  The flag is cleared and the timer is restarted.

  If the flag is off when the timer expires, then there has been no user activity since the last timer
  expiration, and the display is judged idle and its power is lowered.

  The period of the timer is a function of the current value of Power Management aggressiveness.  As that factor
  varies from 1 to 999, the timer period varies from 1004 seconds to 6 seconds.  Above 1000, the system is in
  a very aggressive power management condition, and the timer period is 5 seconds.  (In this case, the display dims
  between five and ten seconds after the last user activity).

  This driver calls the drivers for each display and has them move their display between various power states.
  When the display is idle, its power is dropped state by state until it is in the lowest state.  When it becomes un-idle
  it is powered back up to the state where it was last being used.

  In times of very high power management aggressiveness, the display will not be operated above the lowest power
  state which is marked "usable".

  When Power Management is turned off (aggressiveness = 0), the display is never judged idle and never dimmed.

 We register with Power Management only so that we can be informed of changes in the Power Management
 aggressiveness factor.  We don't really have a device with power states so we implement the absolute minimum.
 The display drivers themselves are part of the Power Management hierarchy under their respective frame buffers.
 
 */


// **********************************************************************************
// initForPM
//
// **********************************************************************************
void IODisplayWrangler::initForPM (void )
{
    
    PMinit();			// initialize superclass variables

    mins_to_dim = 0;
    use_general_aggressiveness = false;

    pm_vars->thePlatform->PMRegisterDevice(0,this);			// attach into the power management hierarchy

    registerPowerDriver(this,ourPowerStates,kNumber_of_power_states);	// register ourselves with policy-maker (us)
    
    registerService();							// HID system is waiting for this
    
}


//*********************************************************************************
// setAggressiveness
//
// We are informed by our power domain parent of a new level of "power management
// aggressiveness" which we use as a factor in our judgement of when we are idle.
// This change implies a change in our idle timer period, so restart that timer.
// timer.
//*********************************************************************************

IOReturn IODisplayWrangler::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
    if ( type == kPMMinutesToDim  ) {						// minutes to dim received
        if(  newLevel == 0 ) {
            if( pm_vars->myCurrentState <  kNumber_of_power_states-1 ) {	// pm turned off while idle?
                makeDisplaysUsable();						// yes, bring displays up again
               }
        }
        mins_to_dim = newLevel;
        use_general_aggressiveness = false;
        if (  pm_vars->aggressiveness < kIOPowerEmergencyLevel ) {		// no, currently in emergency level?
            setIdleTimerPeriod(newLevel*60);					// no, set new timeout
        }
    }
    if ( type == kPMGeneralAggressiveness  ) {					// general factor received
        if ( newLevel >= kIOPowerEmergencyLevel ) {				// emergency level?
            setIdleTimerPeriod(5);						// yes
        }
        else {
            if ( pm_vars->aggressiveness >= kIOPowerEmergencyLevel ) {			// no, coming out of emergency level?
                if (use_general_aggressiveness ) {					// yes, set new timer period
                    setIdleTimerPeriod(333-(newLevel/3));
                }
                else {
                    setIdleTimerPeriod(mins_to_dim*60);
                }
            }
            else {
                if (use_general_aggressiveness ) {					// no, maybe set period
                    setIdleTimerPeriod(333-(newLevel/3));
                }
            }
        }
    }
   super::setAggressiveness(type, newLevel);
   return IOPMNoErr;
}


// **********************************************************************************
// activityTickle
//
// This is called by the HID system and calls the superclass in turn.
// **********************************************************************************

bool IODisplayWrangler::activityTickle ( unsigned long, unsigned long )
{
    if ( rootDomain != NULL ) {
    	rootDomain->activityTickle (kIOPMSubclassPolicy);
    }
    return super::activityTickle (kIOPMSuperclassPolicy1,kNumber_of_power_states-1 );
}


// **********************************************************************************
// setPowerState
//
// The vanilla policy-maker in the superclass is changing our power state.
// If it's down, inform the displays to lower one state, too.  If it's up,
// the idle displays are made usable.
// **********************************************************************************
IOReturn  IODisplayWrangler::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
    if ( powerStateOrdinal == 0 ) {					// system is going to sleep
        return IOPMNoErr;
    }
    if ( powerStateOrdinal < pm_vars->myCurrentState ) {		// HI is idle, drop power
        idleDisplays();
        return IOPMNoErr;
    }
    if ( powerStateOrdinal == kNumber_of_power_states-1 ) {		// there is activity, raise power
        makeDisplaysUsable();
        return IOPMNoErr;
    }
    return IOPMNoErr;
}


// **********************************************************************************
// makeDisplaysUsable
//
// **********************************************************************************
void IODisplayWrangler::makeDisplaysUsable ( void )
{
    OSIterator *	iter;
    IODisplay *	display;

    IOTakeLock( fMatchingLock );

    iter = OSCollectionIterator::withCollection( fDisplays );
    if( iter ) {
        while( (display = (IODisplay *) iter->getNextObject()) ) {
            display->makeDisplayUsable();
        }
        iter->release();
    }
    IOUnlock( fMatchingLock );
}


// **********************************************************************************
// idleDisplays
//
// **********************************************************************************
void IODisplayWrangler::idleDisplays ( void )
{
    OSIterator *	iter;
    IODisplay *	display;

    IOTakeLock( fMatchingLock );

    iter = OSCollectionIterator::withCollection( fDisplays );
    if( iter ) {
        while( (display = (IODisplay *) iter->getNextObject()) ) {
            display->dropOneLevel();
        }
        iter->release();
    }
    IOUnlock( fMatchingLock );
}


