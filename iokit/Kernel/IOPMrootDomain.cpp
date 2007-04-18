/*
 * Copyright (c) 1998-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMessage.h>
#include "RootDomainUserClient.h"
#include "IOKit/pwr_mgt/IOPowerConnection.h"
#include "IOPMPowerStateQueue.h"
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOHibernatePrivate.h>

#ifdef __ppc__
#include <ppc/pms.h>
#endif

extern "C" void kprintf(const char *, ...);

extern const IORegistryPlane * gIOPowerPlane;

IOReturn broadcast_aggressiveness ( OSObject *, void *, void *, void *, void * );
static void sleepTimerExpired(thread_call_param_t);
static void wakeupClamshellTimerExpired ( thread_call_param_t us);


#define number_of_power_states 5
#define OFF_STATE 0
#define RESTART_STATE 1
#define SLEEP_STATE 2
#define DOZE_STATE 3
#define ON_STATE 4

#define ON_POWER kIOPMPowerOn
#define RESTART_POWER kIOPMRestart
#define SLEEP_POWER kIOPMAuxPowerOn
#define DOZE_POWER kIOPMDoze

static IOPMPowerState ourPowerStates[number_of_power_states] = {
    {1,0,			0,		0,0,0,0,0,0,0,0,0},		// state 0, off
    {1,kIOPMRestartCapability,	kIOPMRestart,	RESTART_POWER,0,0,0,0,0,0,0,0},	// state 1, restart
    {1,kIOPMSleepCapability,	kIOPMSleep,	SLEEP_POWER,0,0,0,0,0,0,0,0},	// state 2, sleep
    {1,kIOPMDoze,		kIOPMDoze,	DOZE_POWER,0,0,0,0,0,0,0,0},	// state 3, doze
    {1,kIOPMPowerOn,		kIOPMPowerOn,	ON_POWER,0,0,0,0,0,0,0,0},	// state 4, on
};

// RESERVED IOPMrootDomain class variables
#define diskSyncCalloutEntry                _reserved->diskSyncCalloutEntry
#define _settingController                  _reserved->_settingController
#define _batteryLocationNotifier            _reserved->_batteryLocationNotifier
#define _displayWranglerNotifier            _reserved->_displayWranglerNotifier


static IOPMrootDomain * gRootDomain;
static UInt32           gSleepOrShutdownPending = 0;


#define super IOService
OSDefineMetaClassAndStructors(IOPMrootDomain,IOService)

extern "C"
{
    IONotifier * registerSleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref)
    {
        return gRootDomain->registerInterest( gIOGeneralInterest, handler, self, ref );
    }

    IONotifier * registerPrioritySleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref)
    {
        return gRootDomain->registerInterest( gIOPriorityPowerStateInterest, handler, self, ref );
    }

    IOReturn acknowledgeSleepWakeNotification(void * PMrefcon)
    {
        return gRootDomain->allowPowerChange ( (unsigned long)PMrefcon );
    }

    IOReturn vetoSleepWakeNotification(void * PMrefcon)
    {
        return gRootDomain->cancelPowerChange ( (unsigned long)PMrefcon );
    }
    
    IOReturn rootDomainRestart ( void )
    {
        return gRootDomain->restartSystem();
    }
    
    IOReturn rootDomainShutdown ( void )
    {
        return gRootDomain->shutdownSystem();
    }

	void IOSystemShutdownNotification ( void )
    {
	IOCatalogue::disableExternalLinker();
        for ( int i = 0; i < 100; i++ )
        {
            if ( OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending ) ) break;
            IOSleep( 100 );
        }
    }

    int sync_internal(void);    
}

/*
A device is always in the highest power state which satisfies its driver, its policy-maker, and any power domain
children it has, but within the constraint of the power state provided by its parent.  The driver expresses its desire by
calling changePowerStateTo(), the policy-maker expresses its desire by calling changePowerStateToPriv(), and the children
express their desires by calling requestPowerDomainState().

The Root Power Domain owns the policy for idle and demand sleep and doze for the system.  It is a power-managed IOService just
like the others in the system.  It implements several power states which correspond to what we see as Sleep, Doze, etc.

The sleep/doze policy is as follows:
Sleep and Doze are prevented if the case is open so that nobody will think the machine is off and plug/unplug cards.
Sleep and Doze are prevented if the sleep timeout slider in the preferences panel is at zero.
The system cannot Sleep, but can Doze if some object in the tree is in a power state marked kIOPMPreventSystemSleep.

These three conditions are enforced using the "driver clamp" by calling changePowerStateTo().  For example, if the case is
opened, changePowerStateTo(ON_STATE) is called to hold the system on regardless of the desires of the children of the root or
the state of the other clamp.

Demand Sleep/Doze is initiated by pressing the front panel power button, closing the clamshell, or selecting the menu item.
In this case the root's parent actually initiates the power state change so that the root has no choice and does not give
applications the opportunity to veto the change.

Idle Sleep/Doze occurs if no objects in the tree are in a state marked kIOPMPreventIdleSleep.  When this is true, the root's
children are not holding the root on, so it sets the "policy-maker clamp" by calling changePowerStateToPriv(ON_STATE)
to hold itself on until the sleep timer expires.  This timer is set for the difference between the sleep timeout slider and
the larger of the display dim timeout slider and the disk spindown timeout slider in the Preferences panel.  For example, if
the system is set to sleep after thirty idle minutes, and the display and disk are set to sleep after five idle minutes,
when there is no longer an object in the tree holding the system out of Idle Sleep (via kIOPMPreventIdleSleep), the root
sets its timer for 25 minutes (30 - 5).  When the timer expires, it releases its clamp and now nothing is holding it awake,
so it falls asleep.

Demand sleep is prevented when the system is booting.  When preferences are transmitted by the loginwindow at the end of
boot, a flag is cleared, and this allows subsequent Demand Sleep.

The system will not Sleep, but will Doze if some object calls setSleepSupported(kPCICantSleep) during a power change to the sleep state (this can be done by the PCI Aux Power Supply drivers, Slots99, MacRISC299, etc.).  This is not enforced with
a clamp, but sets a flag which is noticed before actually sleeping the kernel.  If the flag is set, the root steps up
one power state from Sleep to Doze, and any objects in the tree for which this is relevent will act appropriately (USB and
ADB will turn on again so that they can wake the system out of Doze (keyboard/mouse activity will cause the Display Wrangler
to be tickled)).
*/

// **********************************************************************************

IOPMrootDomain * IOPMrootDomain::construct( void )
{
    IOPMrootDomain                          *root;

    root = new IOPMrootDomain;
    if( root)
        root->init();

    return( root );
}

// **********************************************************************************

static void disk_sync_callout(thread_call_param_t p0, thread_call_param_t p1)
{
    IOService                               *rootDomain = (IOService *) p0;
    unsigned long                           pmRef = (unsigned long) p1;

    IOHibernateSystemSleep();
    sync_internal();
    rootDomain->allowPowerChange(pmRef);
}

// **********************************************************************************
// start
//
// We don't do much here.  The real initialization occurs when the platform
// expert informs us we are the root.
// **********************************************************************************


bool IOPMrootDomain::start ( IOService * nub )
{
    OSDictionary                            *tmpDict;

    pmPowerStateQueue = 0;

    _reserved = (ExpansionData *)IOMalloc(sizeof(ExpansionData));
    if(!_reserved) return false;

    super::start(nub);

    gRootDomain = this;

    PMinit();
    setProperty("IOSleepSupported","");

    allowSleep = true;
    sleepIsSupported = true;
    systemBooting = true;
    ignoringClamshell = true;
    sleepSlider = 0;
    idleSleepPending = false;
    canSleep = true;
    wrangler = NULL;
    sleepASAP = false;
    _settingController = NULL;
    ignoringClamshellDuringWakeup = false;
    
    tmpDict = OSDictionary::withCapacity(1);
    setProperty(kRootDomainSupportedFeatures, tmpDict);
    tmpDict->release();
    
    pm_vars->PMworkloop = IOWorkLoop::workLoop();				
    pmPowerStateQueue = IOPMPowerStateQueue::PMPowerStateQueue(this);
    pm_vars->PMworkloop->addEventSource(pmPowerStateQueue);
    
    featuresDictLock = IOLockAlloc();
    
    extraSleepTimer = thread_call_allocate((thread_call_func_t)sleepTimerExpired, (thread_call_param_t) this);
    clamshellWakeupIgnore = thread_call_allocate((thread_call_func_t)wakeupClamshellTimerExpired, (thread_call_param_t) this);
    diskSyncCalloutEntry = thread_call_allocate(&disk_sync_callout, (thread_call_param_t) this);

    // create our parent
    patriarch = new IORootParent;
    patriarch->init();
    patriarch->attach(this);
    patriarch->start(this);
    patriarch->youAreRoot();
    patriarch->wakeSystem();
    patriarch->addPowerChild(this);
        
    registerPowerDriver(this,ourPowerStates,number_of_power_states);

    setPMRootDomain(this);
    // set a clamp until we sleep
    changePowerStateToPriv(ON_STATE);

    // install power change handler
    registerPrioritySleepWakeInterest( &sysPowerDownHandler, this, 0);

    // Register for a notification when IODisplayWrangler is published
    _displayWranglerNotifier = addNotification( gIOPublishNotification, 
                                                serviceMatching("IODisplayWrangler"), 
                                                &displayWranglerPublished, this, 0);

    _batteryLocationNotifier = addNotification( gIOPublishNotification, 
                                                resourceMatching("battery"), 
                                                &batteryLocationPublished, this, this);

    const OSSymbol *ucClassName = OSSymbol::withCStringNoCopy("RootDomainUserClient");
    setProperty(gIOUserClientClassKey, (OSObject *) ucClassName);
    ucClassName->release();

    IORegistryEntry     *temp_entry = NULL;
    if( (temp_entry = IORegistryEntry::fromPath("mac-io/battery", gIODTPlane)) ||
        (temp_entry = IORegistryEntry::fromPath("mac-io/via-pmu/battery", gIODTPlane)))
    {
        // If this machine has a battery, publish the fact that the backlight
        //    supports dimming.
        // Notice similar call in IOPMrootDomain::batteryLocationPublished() to 
        //    detect batteries on SMU machines.
        publishFeature("DisplayDims");
        temp_entry->release();
    }

    IOHibernateSystemInit(this);

    registerService();						// let clients find us

    return true;
}

IOReturn     IOPMrootDomain::setPMSetting(int type, OSNumber *n)
{
    if(_settingController && _settingController->func) {
        int         seconds;
        seconds = n->unsigned32BitValue();
        return (*(_settingController->func))(type, seconds, _settingController->refcon);
    } else {
        return kIOReturnNoDevice;
    }   
}

// **********************************************************************************
// setProperties
//
// Receive a setProperty call
// The "System Boot" property means the system is completely booted.
// **********************************************************************************
IOReturn IOPMrootDomain::setProperties ( OSObject *props_obj)
{
    IOReturn                            return_value = kIOReturnSuccess;
    OSDictionary                        *dict = OSDynamicCast(OSDictionary, props_obj);
    OSBoolean                           *b;
    OSNumber                            *n;
    OSString                            *str;
    const OSSymbol                      *boot_complete_string = OSSymbol::withCString("System Boot Complete");
    const OSSymbol                            *power_button_string = OSSymbol::withCString("DisablePowerButtonSleep");
    const OSSymbol                            *stall_halt_string = OSSymbol::withCString("StallSystemAtHalt");
    const OSSymbol                            *auto_wake_string = OSSymbol::withCString("wake");
    const OSSymbol                            *auto_power_string = OSSymbol::withCString("poweron");
    const OSSymbol                            *wakeonring_string = OSSymbol::withCString("WakeOnRing");
    const OSSymbol                            *fileserver_string = OSSymbol::withCString("AutoRestartOnPowerLoss");
    const OSSymbol                            *wakeonlid_string = OSSymbol::withCString("WakeOnLid");
    const OSSymbol                            *wakeonac_string = OSSymbol::withCString("WakeOnACChange");
    const OSSymbol                            *hibernatemode_string = OSSymbol::withCString(kIOHibernateModeKey);
    const OSSymbol                            *hibernatefile_string = OSSymbol::withCString(kIOHibernateFileKey);
    const OSSymbol                            *hibernatefreeratio_string = OSSymbol::withCString(kIOHibernateFreeRatioKey);
    const OSSymbol                            *hibernatefreetime_string = OSSymbol::withCString(kIOHibernateFreeTimeKey);
    const OSSymbol                            *timezone_string = OSSymbol::withCString("TimeZoneOffsetSeconds");
    
    if(!dict) 
    {
        return_value = kIOReturnBadArgument;
        goto exit;
    }

    if( systemBooting 
        && boot_complete_string 
        && dict->getObject(boot_complete_string)) 
    {
        systemBooting = false;
        adjustPowerState();
    }
    
    if( power_button_string
        && (b = OSDynamicCast(OSBoolean, dict->getObject(power_button_string))) ) 
    {
        setProperty(power_button_string, b);
    }

    if( stall_halt_string
        && (b = OSDynamicCast(OSBoolean, dict->getObject(stall_halt_string))) ) 
    {
        setProperty(stall_halt_string, b);
    }

    if ( hibernatemode_string
	&& (n = OSDynamicCast(OSNumber, dict->getObject(hibernatemode_string))))
    {
	setProperty(hibernatemode_string, n);
    }
    if ( hibernatefreeratio_string
	&& (n = OSDynamicCast(OSNumber, dict->getObject(hibernatefreeratio_string))))
    {
	setProperty(hibernatefreeratio_string, n);
    }
    if ( hibernatefreetime_string
	&& (n = OSDynamicCast(OSNumber, dict->getObject(hibernatefreetime_string))))
    {
	setProperty(hibernatefreetime_string, n);
    }
    if ( hibernatefile_string
	&& (str = OSDynamicCast(OSString, dict->getObject(hibernatefile_string))))
    {
	setProperty(hibernatefile_string, str);
    }

    // Relay AutoWake setting to its controller
    if( auto_wake_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(auto_wake_string))) )
    {
        return_value = setPMSetting(kIOPMAutoWakeSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }

    // Relay AutoPower setting to its controller
    if( auto_power_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(auto_power_string))) )
    {
        return_value = setPMSetting(kIOPMAutoPowerOnSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }

    // Relay WakeOnRing setting to its controller
    if( wakeonring_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(wakeonring_string))) )
    {
        return_value = setPMSetting(kIOPMWakeOnRingSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }

    // Relay FileServer setting to its controller
    if( fileserver_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(fileserver_string))) )
    {
        return_value = setPMSetting(kIOPMAutoRestartOnPowerLossSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }

    // Relay WakeOnLid setting to its controller
    if( wakeonlid_string 
        && (n = OSDynamicCast(OSNumber, dict->getObject(wakeonlid_string))) )
    {
        return_value = setPMSetting(kIOPMWakeOnLidSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }
    
    // Relay WakeOnACChange setting to its controller
    if( wakeonac_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(wakeonac_string))) )
    {
        return_value = setPMSetting(kIOPMWakeOnACChangeSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }

    // Relay timezone offset in seconds to SMU
    if( timezone_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(timezone_string))) )
    {
        return_value = setPMSetting(kIOPMTimeZoneSetting, n);
        if(kIOReturnSuccess != return_value) goto exit;
    }


    exit:
    if(boot_complete_string) boot_complete_string->release();
    if(power_button_string) power_button_string->release();
    if(stall_halt_string) stall_halt_string->release();
    if(auto_wake_string) auto_wake_string->release();
    if(auto_power_string) auto_power_string->release();
    if(wakeonring_string) wakeonring_string->release();
    if(fileserver_string) fileserver_string->release();
    if(wakeonlid_string) wakeonlid_string->release();
    if(wakeonac_string) wakeonac_string->release();
    if(timezone_string) timezone_string->release();
    return return_value;
}


//*********************************************************************************
// youAreRoot
//
// Power Managment is informing us that we are the root power domain.
// We know we are not the root however, since we have just instantiated a parent
// for ourselves and made it the root.  We override this method so it will have
// no effect
//*********************************************************************************
IOReturn IOPMrootDomain::youAreRoot ( void )
{
    return IOPMNoErr;
}

// **********************************************************************************
// command_received
//
// No longer used
// **********************************************************************************
void IOPMrootDomain::command_received ( void * w, void * x, void * y, void * z )
{
    super::command_received(w,x,y,z);
}


// **********************************************************************************
// broadcast_aggressiveness
//
// **********************************************************************************
IOReturn broadcast_aggressiveness ( OSObject * root, void * x, void * y, void *, void * )
{
    ((IOPMrootDomain *)root)->broadcast_it((unsigned long)x,(unsigned long)y);
    return IOPMNoErr;
}


// **********************************************************************************
// broadcast_it
//
// We are behind the command gate to broadcast an aggressiveness factor.  We let the
// superclass do it, but we need to snoop on factors that affect idle sleep.
// **********************************************************************************
void IOPMrootDomain::broadcast_it (unsigned long type, unsigned long value)
{
    super::setAggressiveness(type,value);

    // Save user's spin down timer to restore after we replace it for idle sleep
    if( type == kPMMinutesToSpinDown ) user_spindown = value;

    // Use longestNonSleepSlider to calculate dimming adjust idle sleep timer
    longestNonSleepSlider = pm_vars->current_aggressiveness_values[kPMMinutesToDim];


    if ( type == kPMMinutesToSleep ) {
        if ( (sleepSlider == 0) && (value != 0) ) {
            sleepSlider = value;
            // idle sleep is now enabled, maybe sleep now
            adjustPowerState();
        }
        sleepSlider = value;
        if ( sleepSlider == 0 ) {			
            // idle sleep is now disabled
            adjustPowerState();
            // make sure we're powered
            patriarch->wakeSystem();
        }
    }
    if ( sleepSlider > longestNonSleepSlider ) {
        extraSleepDelay = sleepSlider - longestNonSleepSlider ;
    }
    else {
        extraSleepDelay = 0;
    }
}


// **********************************************************************************
// sleepTimerExpired
//
// **********************************************************************************
static void sleepTimerExpired ( thread_call_param_t us)
{
    ((IOPMrootDomain *)us)->handleSleepTimerExpiration();
    }
    
   
static void wakeupClamshellTimerExpired ( thread_call_param_t us)
{
    ((IOPMrootDomain *)us)->stopIgnoringClamshellEventsDuringWakeup();
}

    
// **********************************************************************************
// handleSleepTimerExpiration
//
// The time between the sleep idle timeout and the next longest one has elapsed.
// It's time to sleep.  Start that by removing the clamp that's holding us awake.
// **********************************************************************************
void IOPMrootDomain::handleSleepTimerExpiration ( void )
{
    // accelerate disk spin down if spin down timer is non-zero (zero = never spin down)  
    if(0 != user_spindown)
        setQuickSpinDownTimeout();

    sleepASAP = true;
    adjustPowerState();
}


void IOPMrootDomain::stopIgnoringClamshellEventsDuringWakeup(void)
{
    OSObject *  state;

    // Allow clamshell-induced sleep now
    ignoringClamshellDuringWakeup = false;

    if ((state = getProperty(kAppleClamshellStateKey)))
        publishResource(kAppleClamshellStateKey, state);
}

//*********************************************************************************
// setAggressiveness
//
// Some aggressiveness factor has changed.  We broadcast it to the hierarchy while on
// the Power Mangement workloop thread.  This enables objects in the
// hierarchy to successfully alter their idle timers, which are all on the
// same thread.
//*********************************************************************************

static int pmsallsetup = 0;

IOReturn IOPMrootDomain::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
#ifdef __ppc__
	if(pmsExperimental & 3) kprintf("setAggressiveness: type = %08X, newlevel = %08X\n", type, newLevel);
	if(pmsExperimental & 1) {						/* Is experimental mode enabled? */
		if(pmsInstalled && (type == kPMSetProcessorSpeed)) {	/* We want to look at all processor speed changes if stepper is installed */
			if(pmsallsetup) return kIOReturnSuccess;	/* If already running, just eat this */
			kprintf("setAggressiveness: starting stepper...\n");
			pmsallsetup = 1;						/* Remember we did this */
			pmsPark();
			pmsStart();								/* Get it all started up... */
			return kIOReturnSuccess;				/* Leave now... */
		}
	}
#endif

    if ( pm_vars->PMcommandGate ) {
        pm_vars->PMcommandGate->runAction(broadcast_aggressiveness,(void *)type,(void *)newLevel);
    }
    
    return kIOReturnSuccess;
}


// **********************************************************************************
// sleepSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::sleepSystem ( void )
{
    //kprintf("sleep demand received\n");
    if ( !systemBooting && allowSleep && sleepIsSupported ) {
        patriarch->sleepSystem();

        return kIOReturnSuccess;
    }
    if ( !systemBooting && allowSleep && !sleepIsSupported ) {
        patriarch->dozeSystem();
        return kIOReturnSuccess;
    }
    return kIOReturnSuccess;
}


// **********************************************************************************
// shutdownSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::shutdownSystem ( void )
{
    //patriarch->shutDownSystem();
    return kIOReturnUnsupported;
}


// **********************************************************************************
// restartSystem
//
// **********************************************************************************
IOReturn IOPMrootDomain::restartSystem ( void )
{
    //patriarch->restartSystem();
    return kIOReturnUnsupported;
}


// **********************************************************************************
// powerChangeDone
//
// This overrides powerChangeDone in IOService.
//
// Finder sleep and idle sleep move us from the ON state to the SLEEP_STATE.
// In this case:
// If we just finished going to the SLEEP_STATE, and the platform is capable of true sleep,
// sleep the kernel.  Otherwise switch up to the DOZE_STATE which will keep almost
// everything as off as it can get.
//
// **********************************************************************************
void IOPMrootDomain::powerChangeDone ( unsigned long previousState )
{
    OSNumber *		propertyPtr;
    unsigned short	theProperty;
    AbsoluteTime        deadline;
    
    switch ( pm_vars->myCurrentState ) {
        case SLEEP_STATE:
            if ( canSleep && sleepIsSupported ) 
            {
                // re-enable this timer for next sleep
                idleSleepPending = false;			

                IOLog("System %sSleep\n", gIOHibernateState ? "Safe" : "");

                IOHibernateSystemHasSlept();

                pm_vars->thePlatform->sleepKernel();

                // The CPU(s) are off at this point. When they're awakened by CPU interrupt,
                // code will resume execution here.

                // Now we're waking...
		IOHibernateSystemWake();

                // stay awake for at least 30 seconds
                clock_interval_to_deadline(30, kSecondScale, &deadline);	
                thread_call_enter_delayed(extraSleepTimer, deadline);
                // this gets turned off when we sleep again
                idleSleepPending = true;
                
                // Ignore closed clamshell during wakeup and for a few seconds
                // after wakeup is complete
                ignoringClamshellDuringWakeup = true;

                // sleep transition complete
                gSleepOrShutdownPending = 0;

				// trip the reset of the calendar clock
				clock_wakeup_calendar();

                // get us some power
                patriarch->wakeSystem();
                
                // early stage wake notification
                tellClients(kIOMessageSystemWillPowerOn);

                // tell the tree we're waking
                IOLog("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
                systemWake();
                
                // Allow drivers to request extra processing time before clamshell
                // sleep if kIOREMSleepEnabledKey is present.
                // Ignore clamshell events for at least 5 seconds 
                if(getProperty(kIOREMSleepEnabledKey)) {
                    // clamshellWakeupIgnore callout clears ignoreClamshellDuringWakeup bit   
                    clock_interval_to_deadline(5, kSecondScale, &deadline);
                    if(clamshellWakeupIgnore) thread_call_enter_delayed(clamshellWakeupIgnore, deadline);
                } else ignoringClamshellDuringWakeup = false;
                
                // Find out what woke us
                propertyPtr = OSDynamicCast(OSNumber,getProperty("WakeEvent"));
                if ( propertyPtr ) {				
                    theProperty = propertyPtr->unsigned16BitValue();
                    IOLog("Wake event %04x\n",theProperty);
                    if ( (theProperty & 0x0008) ||	//lid
                        (theProperty & 0x0800) ||	// front panel button
                        (theProperty & 0x0020) ||	// external keyboard
                        (theProperty & 0x0001) ) {	// internal keyboard
                            // We've identified the wakeup event as UI driven
                            reportUserInput();
                    }
                } else {
                    // Since we can't identify the wakeup event, treat it as UI activity
                    reportUserInput();
                }
                            
                // Wake for thirty seconds
                changePowerStateToPriv(ON_STATE);		
                powerOverrideOffPriv();
            } else {
                // allow us to step up a power state
                patriarch->sleepToDoze();
                // and do it
                changePowerStateToPriv(DOZE_STATE);
            }
            break;

        case DOZE_STATE:
            if ( previousState != DOZE_STATE ) 
            {
                IOLog("System Doze\n");
            }
            // re-enable this timer for next sleep
            idleSleepPending = false;
            gSleepOrShutdownPending = 0;
            break;
            
    	case RESTART_STATE:
            IOLog("System Restart\n");
            PEHaltRestart(kPERestartCPU);
            break;
            
    	case OFF_STATE:
            IOLog("System Halt\n");
            PEHaltRestart(kPEHaltCPU);
            break;
    }
}


// **********************************************************************************
// wakeFromDoze
//
// The Display Wrangler calls here when it switches to its highest state.  If the 
// system is currently dozing, allow it to wake by making sure the parent is
// providing power.
// **********************************************************************************
void IOPMrootDomain::wakeFromDoze( void )
{
    if ( pm_vars->myCurrentState == DOZE_STATE ) 
    {
        // reset this till next attempt
        canSleep = true;
        powerOverrideOffPriv();

        // early wake notification
        tellClients(kIOMessageSystemWillPowerOn);

        // allow us to wake if children so desire
        patriarch->wakeSystem();
    }
}


// **********************************************************************************
// publishFeature
//
// Adds a new feature to the supported features dictionary
// 
// 
// **********************************************************************************
void IOPMrootDomain::publishFeature( const char * feature )
{
    if(featuresDictLock) IOLockLock(featuresDictLock);
    OSDictionary *features =
        (OSDictionary *) getProperty(kRootDomainSupportedFeatures);
    
    if ( features && OSDynamicCast(OSDictionary, features))
        features = OSDictionary::withDictionary(features);
    else
        features = OSDictionary::withCapacity(1);

    features->setObject(feature, kOSBooleanTrue);
    setProperty(kRootDomainSupportedFeatures, features);
    features->release();
    if(featuresDictLock) IOLockUnlock(featuresDictLock);
}


void IOPMrootDomain::unIdleDevice( IOService *theDevice, unsigned long theState )
{
    if(pmPowerStateQueue)
        pmPowerStateQueue->unIdleOccurred(theDevice, theState);
}

void IOPMrootDomain::announcePowerSourceChange( void )
{
    IORegistryEntry                 *_batteryRegEntry = (IORegistryEntry *) getProperty("BatteryEntry");

    // (if possible) re-publish power source state under IOPMrootDomain
    // (only done if the battery controller publishes an IOResource defining battery location)
    if(_batteryRegEntry)
    {
        OSArray             *batt_info;
        batt_info = (OSArray *) _batteryRegEntry->getProperty(kIOBatteryInfoKey);
        if(batt_info)
            setProperty(kIOBatteryInfoKey, batt_info);
    }

    messageClients(kIOPMMessageBatteryStatusHasChanged);
}

IOReturn IOPMrootDomain::registerPMSettingController
        (IOPMSettingControllerCallback func, void *info)
{
    if(_settingController) return kIOReturnExclusiveAccess;
    
    _settingController = (PMSettingCtrl *)IOMalloc(sizeof(PMSettingCtrl));
    if(!_settingController) return kIOReturnNoMemory;
    
    _settingController->func = func;
    _settingController->refcon = info;
    return kIOReturnSuccess;
}


//*********************************************************************************
// receivePowerNotification
//
// The power controller is notifying us of a hardware-related power management
// event that we must handle. This is a result of an 'environment' interrupt from
// the power mgt micro.
//*********************************************************************************

IOReturn IOPMrootDomain::receivePowerNotification (UInt32 msg)
{
    if (msg & kIOPMOverTemp) 
    {
        IOLog("Power Management received emergency overtemp signal. Going to sleep.");
        (void) sleepSystem ();
    }
    if (msg & kIOPMSetDesktopMode) 
    {
        desktopMode = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetDesktopMode | kIOPMSetValue);
    }
    if (msg & kIOPMSetACAdaptorConnected) 
    {
        acAdaptorConnect = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetACAdaptorConnected | kIOPMSetValue);
    }
    if (msg & kIOPMEnableClamshell) 
    {
        ignoringClamshell = false;
    }
    if (msg & kIOPMDisableClamshell) 
    {
        ignoringClamshell = true;
    }

    if (msg & kIOPMProcessorSpeedChange) 
    {
        IOService *pmu = waitForService(serviceMatching("ApplePMU"));
        pmu->callPlatformFunction("prepareForSleep", false, 0, 0, 0, 0);
        pm_vars->thePlatform->sleepKernel();
        pmu->callPlatformFunction("recoverFromSleep", false, 0, 0, 0, 0);
    }

    if (msg & kIOPMSleepNow) 
    {
      (void) sleepSystem ();
    }
    
    if (msg & kIOPMPowerEmergency) 
    {
      (void) sleepSystem ();
    }

    if (msg & kIOPMClamshellClosed) 
    {
        if ( !ignoringClamshell && !ignoringClamshellDuringWakeup 
                    && (!desktopMode || !acAdaptorConnect) ) 
        {

             (void) sleepSystem ();
        }
    }

    if (msg & kIOPMPowerButton) 
    {				
        // toggle state of sleep/wake
        // are we dozing?
        if ( pm_vars->myCurrentState == DOZE_STATE ) 
        {
            // yes, tell the tree we're waking 
            systemWake();
            // wake the Display Wrangler
            reportUserInput();					
        }
        else {
            // Check that power button sleep is enabled
            if(kOSBooleanTrue != getProperty(OSString::withCString("DisablePowerButtonSleep")))
                sleepSystem();
        }
    }

    // if the case has been closed, we allow
    // the machine to be put to sleep or to idle sleep

    if ( (msg & kIOPMAllowSleep) && !allowSleep ) 
    {
        allowSleep = true;
        adjustPowerState();
    }

    // if the case has been opened, we disallow sleep/doze

    if (msg & kIOPMPreventSleep) {
        allowSleep = false;
	    // are we dozing?
        if ( pm_vars->myCurrentState == DOZE_STATE ) {
            // yes, tell the tree we're waking 
            systemWake();
            adjustPowerState();
            // wake the Display Wrangler
            reportUserInput();
        } else {
            adjustPowerState();
            // make sure we have power to clamp
            patriarch->wakeSystem();
        }
    }

   return 0;
}


//*********************************************************************************
// sleepSupported
//
//*********************************************************************************

void IOPMrootDomain::setSleepSupported( IOOptionBits flags )
{
    if ( flags & kPCICantSleep ) 
    {
        canSleep = false;
    } else {
        platformSleepSupport = flags;
    }

}

//*********************************************************************************
// requestPowerDomainState
//
// The root domain intercepts this call to the superclass.
//
// If the clamp bit is not set in the desire, then the child doesn't need the power
// state it's requesting; it just wants it.  The root ignores desires but not needs.
// If the clamp bit is not set, the root takes it that the child can tolerate no
// power and interprets the request accordingly.  If all children can thus tolerate
// no power, we are on our way to idle sleep.
//*********************************************************************************

IOReturn IOPMrootDomain::requestPowerDomainState ( IOPMPowerFlags desiredState, IOPowerConnection * whichChild, unsigned long specification )
{
    OSIterator                              *iter;
    OSObject                                *next;
    IOPowerConnection                       *connection;
    unsigned long                           powerRequestFlag = 0;
    IOPMPowerFlags                          editedDesire = desiredState;

    // if they don't really need it, they don't get it
    if ( !(desiredState & kIOPMPreventIdleSleep) ) {
        editedDesire = 0;
    }


    IOLockLock(pm_vars->childLock);

    // recompute sleepIsSupported and see if all children are asleep
    iter = getChildIterator(gIOPowerPlane);
    sleepIsSupported = true;
    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection,next)) ) 
            {
                if ( connection == whichChild ) 
                {
                    powerRequestFlag += editedDesire;
                    if ( desiredState & kIOPMPreventSystemSleep ) 
                    {
                        sleepIsSupported = false;
                    }
                } else {
                    powerRequestFlag += connection->getDesiredDomainState();
                    if ( connection->getPreventSystemSleepFlag() ) 
                    {
                        sleepIsSupported = false;
                    }
                }
            }
        }
        iter->release();
    }
    
    if ( (extraSleepDelay == 0) &&  (powerRequestFlag == 0) ) 
    {
        sleepASAP = true;
    }
    
    // this may put the system to sleep
    adjustPowerState();
    
    IOLockUnlock(pm_vars->childLock);

    editedDesire |= desiredState & kIOPMPreventSystemSleep;

    return super::requestPowerDomainState(editedDesire,whichChild,specification);
}


//*********************************************************************************
// getSleepSupported
//
//*********************************************************************************

IOOptionBits IOPMrootDomain::getSleepSupported( void )
{
    return( platformSleepSupport );
}


//*********************************************************************************
// tellChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//*********************************************************************************

bool IOPMrootDomain::tellChangeDown ( unsigned long stateNum )
{
    switch ( stateNum ) {
        case DOZE_STATE:
        case SLEEP_STATE:
            return super::tellClientsWithResponse(kIOMessageSystemWillSleep);
        case RESTART_STATE:
            return super::tellClientsWithResponse(kIOMessageSystemWillRestart);
        case OFF_STATE:
            return super::tellClientsWithResponse(kIOMessageSystemWillPowerOff);
    }
    // this shouldn't execute
    return super::tellChangeDown(stateNum);
}


//*********************************************************************************
// askChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//
// This must be idle sleep since we don't ask apps during any other power change.
//*********************************************************************************

bool IOPMrootDomain::askChangeDown ( unsigned long )
{
    return super::tellClientsWithResponse(kIOMessageCanSystemSleep);
}


//*********************************************************************************
// tellNoChangeDown
//
// Notify registered applications and kernel clients that we are not
// dropping power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//
// This must be a vetoed idle sleep, since no other power change can be vetoed.
//*********************************************************************************

void IOPMrootDomain::tellNoChangeDown ( unsigned long )
{
    return tellClients(kIOMessageSystemWillNotSleep);
}


//*********************************************************************************
// tellChangeUp
//
// Notify registered applications and kernel clients that we are raising power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//*********************************************************************************

void IOPMrootDomain::tellChangeUp ( unsigned long stateNum)
{
    if ( stateNum == ON_STATE ) 
    {
	IOHibernateSystemPostWake();
        return tellClients(kIOMessageSystemHasPoweredOn);
    }
}

//*********************************************************************************
// reportUserInput
//
//*********************************************************************************

void IOPMrootDomain::reportUserInput ( void )
{
    OSIterator * iter;

    if(!wrangler) 
    {
        iter = getMatchingServices(serviceMatching("IODisplayWrangler"));
        if(iter) 
        {
            wrangler = (IOService *) iter->getNextObject();
            iter->release();
        }
    }

    if(wrangler)
        wrangler->activityTickle(0,0);
}

//*********************************************************************************
// setQuickSpinDownTimeout
//
//*********************************************************************************

void IOPMrootDomain::setQuickSpinDownTimeout ( void )
{
    super::setAggressiveness((unsigned long)kPMMinutesToSpinDown,(unsigned long)1);
}

//*********************************************************************************
// restoreUserSpinDownTimeout
//
//*********************************************************************************

void IOPMrootDomain::restoreUserSpinDownTimeout ( void )
{
    super::setAggressiveness((unsigned long)kPMMinutesToSpinDown,(unsigned long)user_spindown);
}

//*********************************************************************************
// changePowerStateTo & changePowerStateToPriv
//
// Override of these methods for logging purposes.
//*********************************************************************************

IOReturn IOPMrootDomain::changePowerStateTo ( unsigned long ordinal )
{
    return super::changePowerStateTo(ordinal);
}

IOReturn IOPMrootDomain::changePowerStateToPriv ( unsigned long ordinal )
{
    return super::changePowerStateToPriv(ordinal);
}


//*********************************************************************************
// sysPowerDownHandler
//
// Receives a notification when the RootDomain changes state. 
//
// Allows us to take action on system sleep, power down, and restart after
// applications have received their power change notifications and replied,
// but before drivers have powered down. We perform a vfs sync on power down.
//*********************************************************************************

IOReturn IOPMrootDomain::sysPowerDownHandler( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize )
{
    IOReturn                             ret;
    IOPowerStateChangeNotification      *params = (IOPowerStateChangeNotification *) messageArgument;
    IOPMrootDomain                      *rootDomain = OSDynamicCast(IOPMrootDomain, service);

    if(!rootDomain)
        return kIOReturnUnsupported;

    switch (messageType) {
        case kIOMessageSystemWillSleep:
            rootDomain->powerOverrideOnPriv();		// start ignoring children's requests
                                                        // (fall through to other cases)

            // Interested applications have been notified of an impending power
            // change and have acked (when applicable).
            // This is our chance to save whatever state we can before powering
            // down.
            // We call sync_internal defined in xnu/bsd/vfs/vfs_syscalls.c,
            // via callout

            // We will ack within 20 seconds
            params->returnValue = 20 * 1000 * 1000;
            if (gIOHibernateState)
                params->returnValue += gIOHibernateFreeTime * 1000; 	//add in time we could spend freeing pages

            if ( ! OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending ) )
            {
                // Purposely delay the ack and hope that shutdown occurs quickly.
                // Another option is not to schedule the thread and wait for
                // ack timeout...
                AbsoluteTime deadline;
                clock_interval_to_deadline( 30, kSecondScale, &deadline );
                thread_call_enter1_delayed( rootDomain->diskSyncCalloutEntry, 
                                            (thread_call_param_t)params->powerRef,
                                            deadline );
            }
            else
                thread_call_enter1(rootDomain->diskSyncCalloutEntry, (thread_call_param_t)params->powerRef);
            ret = kIOReturnSuccess;
            break;

        case kIOMessageSystemWillPowerOff:
        case kIOMessageSystemWillRestart:
            ret = kIOReturnUnsupported;
            break;

        default:
            ret = kIOReturnUnsupported;
            break;
    }
    return ret;
}
		
//*********************************************************************************
// displayWranglerNotification
//
// Receives a notification when the IODisplayWrangler changes state.
//
// Allows us to take action on display dim/undim.
//
// When the display goes dim we:
// - Start the idle sleep timer
// - set the quick spin down timeout
//
// On wake from display dim:
// - Cancel the idle sleep timer
// - restore the user's chosen spindown timer from the "quick" spin down value
//*********************************************************************************

IOReturn IOPMrootDomain::displayWranglerNotification( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize )
{
    IOPMrootDomain *                rootDomain = OSDynamicCast(IOPMrootDomain, (IOService *)target);
    AbsoluteTime                 deadline;
    static bool                  deviceAlreadyPoweredOff = false;

    if(!rootDomain)
        return kIOReturnUnsupported;

    switch (messageType) {
       case kIOMessageDeviceWillPowerOff:
            // The IODisplayWrangler has powered off either because of idle display sleep
            // or force system sleep.
            
            // The display wrangler will send the DeviceWillPowerOff message 4 times until
            // it gets into its lowest state. We only want to act on the first of those 4.
            if( deviceAlreadyPoweredOff ) return kIOReturnUnsupported;

           deviceAlreadyPoweredOff = true;

           if( rootDomain->extraSleepDelay ) 
           {
                // start the extra sleep timer
                clock_interval_to_deadline(rootDomain->extraSleepDelay*60, kSecondScale, &deadline );
                thread_call_enter_delayed(rootDomain->extraSleepTimer, deadline);
                rootDomain->idleSleepPending = true;
            } else {
                // accelerate disk spin down if spin down timer is non-zero (zero = never spin down)
                // and if system sleep is non-Never
                if( (0 != rootDomain->user_spindown) && (0 != rootDomain->sleepSlider) )
                    rootDomain->setQuickSpinDownTimeout();
            }

             break;

        case kIOMessageDeviceHasPoweredOn:

            // The display has powered on either because of UI activity or wake from sleep/doze
            deviceAlreadyPoweredOff = false;
            rootDomain->adjustPowerState();
            

            // cancel any pending idle sleep
            if(rootDomain->idleSleepPending) 
            {
                thread_call_cancel(rootDomain->extraSleepTimer);
                rootDomain->idleSleepPending = false;
            }

            // Change the spindown value back to the user's selection from our accelerated setting
            if(0 != rootDomain->user_spindown)
                rootDomain->restoreUserSpinDownTimeout();

            // Put on the policy maker's on clamp.

            break;

         default:
             break;
     }
     return kIOReturnUnsupported;
 }

//*********************************************************************************
// displayWranglerPublished
//
// Receives a notification when the IODisplayWrangler is published.
// When it's published we install a power state change handler.
//
//*********************************************************************************

bool IOPMrootDomain::displayWranglerPublished( void * target, void * refCon,
                                    IOService * newService)
{
    IOPMrootDomain *                rootDomain = OSDynamicCast(IOPMrootDomain, (IOService *)target);

    if(!rootDomain)
        return false;

    rootDomain->wrangler = newService;
    
    // we found the display wrangler, now install a handler
    if( !rootDomain->wrangler->registerInterest( gIOGeneralInterest, &displayWranglerNotification, target, 0) ) {
        IOLog("IOPMrootDomain::displayWranglerPublished registerInterest failed\n");
        return false;
    }
    
    return true;
}

//*********************************************************************************
// batteryLocationPublished
//
// Notification on AppleSMU publishing location of battery data
//
//*********************************************************************************

bool IOPMrootDomain::batteryLocationPublished( void * target, void * root_domain,
        IOService * resourceService )
{
    IORegistryEntry                     *battery_location;

    battery_location = (IORegistryEntry *) resourceService->getProperty("battery");
    if (!battery_location || !OSDynamicCast(IORegistryEntry, battery_location))
        return (true);
        
    ((IOPMrootDomain *)root_domain)->setProperty("BatteryEntry", battery_location);
    
    // rdar://2936060
    // All laptops have dimmable LCD displays
    // All laptops have batteries
    // So if this machine has a battery, publish the fact that the backlight
    // supports dimming.
    ((IOPMrootDomain *)root_domain)->publishFeature("DisplayDims");
    
    ((IOPMrootDomain *)root_domain)->announcePowerSourceChange();
    return (true);
}



//*********************************************************************************
// adjustPowerState
//
// Some condition that affects our wake/sleep/doze decision has changed.
//
// If the sleep slider is in the off position, we cannot sleep or doze.
// If the enclosure is open, we cannot sleep or doze.
// If the system is still booting, we cannot sleep or doze.
//
// In those circumstances, we prevent sleep and doze by holding power on with
// changePowerStateToPriv(ON).
//
// If the above conditions do not exist, and also the sleep timer has expired, we
// allow sleep or doze to occur with either changePowerStateToPriv(SLEEP) or
// changePowerStateToPriv(DOZE) depending on whether or not we already know the
// platform cannot sleep.
//
// In this case, sleep or doze will either occur immediately or at the next time
// that no children are holding the system out of idle sleep via the 
// kIOPMPreventIdleSleep flag in their power state arrays.
//*********************************************************************************

void IOPMrootDomain::adjustPowerState( void )
{
    if ( (sleepSlider == 0) ||
        ! allowSleep ||
        systemBooting ) {
        changePowerStateToPriv(ON_STATE);
    } else {
        if ( sleepASAP ) 
        {
            sleepASAP = false;
            if ( sleepIsSupported ) 
            {
                changePowerStateToPriv(SLEEP_STATE);
            } else {
                changePowerStateToPriv(DOZE_STATE);
            }
        }
    }
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClassAndStructors(IORootParent, IOService)

// This array exactly parallels the state array for the root domain.
// Power state changes initiated by a device can be vetoed by a client of the device, and
// power state changes initiated by the parent of a device cannot be vetoed by a client of the device,
// so when the root domain wants a power state change that cannot be vetoed (e.g. demand sleep), it asks
// its parent to make the change.  That is the reason for this complexity.

static IOPMPowerState patriarchPowerStates[number_of_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},                                          // off
    {1,0,RESTART_POWER,0,0,0,0,0,0,0,0,0},                              // reset
    {1,0,SLEEP_POWER,0,0,0,0,0,0,0,0,0},                                // sleep
    {1,0,DOZE_POWER,0,0,0,0,0,0,0,0,0},                         	// doze
    {1,0,ON_POWER,0,0,0,0,0,0,0,0,0}                                    // running
};

bool IORootParent::start ( IOService * nub )
{
    mostRecentChange = ON_STATE;
    super::start(nub);
    PMinit();
    registerPowerDriver(this,patriarchPowerStates,number_of_power_states);
    powerOverrideOnPriv();
    return true;
}


void IORootParent::shutDownSystem ( void )
{
    mostRecentChange = OFF_STATE;
    changePowerStateToPriv(OFF_STATE);
}


void IORootParent::restartSystem ( void )
{
    mostRecentChange = RESTART_STATE;
    changePowerStateToPriv(RESTART_STATE);
}


void IORootParent::sleepSystem ( void )
{
    mostRecentChange = SLEEP_STATE;
    changePowerStateToPriv(SLEEP_STATE);
}


void IORootParent::dozeSystem ( void )
{
    mostRecentChange = DOZE_STATE;
    changePowerStateToPriv(DOZE_STATE);
}

// Called in demand sleep when sleep discovered to be impossible after actually attaining that state.
// This brings the parent to doze, which allows the root to step up from sleep to doze.

// In idle sleep, do nothing because the parent is still on and the root can freely change state.

void IORootParent::sleepToDoze ( void )
{
    if ( mostRecentChange == SLEEP_STATE ) {
        changePowerStateToPriv(DOZE_STATE);
    }
}


void IORootParent::wakeSystem ( void )
{
    mostRecentChange = ON_STATE;
    changePowerStateToPriv(ON_STATE);
}

