/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/IOReturn.h>
#include "RootDomainUserClient.h"
#include "IOKit/pwr_mgt/IOPowerConnection.h"
#include "IOPMPowerStateQueue.h"
#include <IOKit/IOCatalogue.h>
#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include "IOServicePrivate.h"	// _IOServiceInterestNotifier


#if __i386__
__BEGIN_DECLS
#include "IOPMrootDomainInternal.h"
__END_DECLS
#endif


//#define DEBUG   1
#if DEBUG
#define DEBUG_LOG(x...) do { kprintf(x); } while (0)
#else
#define DEBUG_LOG(x...)
#endif
#define HaltRestartLog(x...)  do { kprintf(x); } while (0)

extern "C" {
IOReturn OSMetaClassSystemSleepOrWake( UInt32 );
}

extern const IORegistryPlane * gIOPowerPlane;

IOReturn broadcast_aggressiveness ( OSObject *, void *, void *, void *, void * );
static void sleepTimerExpired(thread_call_param_t);
static void wakeupClamshellTimerExpired ( thread_call_param_t us);
static void notifySystemShutdown( IOService * root, unsigned long event );

// "IOPMSetSleepSupported"  callPlatformFunction name
static const OSSymbol *sleepSupportedPEFunction = NULL;

#define kIOSleepSupportedKey  "IOSleepSupported"

#define kRD_AllPowerSources (kIOPMSupportedOnAC \
                           | kIOPMSupportedOnBatt \
                           | kIOPMSupportedOnUPS)

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

enum 
{
    // not idle around autowake time, secs
    kAutoWakePreWindow  = 45,
    kAutoWakePostWindow = 15
};


#define kLocalEvalClamshellCommand        (1 << 15)

static IOPMPowerState ourPowerStates[number_of_power_states] = {
    // state 0, off
    {1,0,			0,		0,0,0,0,0,0,0,0,0},
    // state 1, restart
    {1,kIOPMRestartCapability,	kIOPMRestart,	RESTART_POWER,0,0,0,0,0,0,0,0},	
    // state 2, sleep
    {1,kIOPMSleepCapability,	kIOPMSleep,	SLEEP_POWER,0,0,0,0,0,0,0,0},	
    // state 3, doze
    {1,kIOPMDoze,		kIOPMDoze,	DOZE_POWER,0,0,0,0,0,0,0,0},	
    // state 4, on
    {1,kIOPMPowerOn,		kIOPMPowerOn,	ON_POWER,0,0,0,0,0,0,0,0},	
};

static IOPMrootDomain * gRootDomain;
static UInt32           gSleepOrShutdownPending = 0;

struct timeval gIOLastSleepTime;
struct timeval gIOLastWakeTime;

// Constants used as arguments to IOPMrootDomain::informCPUStateChange
#define kCPUUnknownIndex    9999999
enum {
    kInformAC = 0,
    kInformLid = 1,
    kInformableCount = 2
};

class PMSettingObject : public OSObject
{
    OSDeclareDefaultStructors(PMSettingObject)
private:
    IOPMrootDomain                  *parent;
    IOPMSettingControllerCallback   func;
    OSObject                        *target;
    uintptr_t                       refcon;
    uint32_t                        *publishedFeatureID;
    int                             releaseAtCount;
public:
    static PMSettingObject *pmSettingObject(
                IOPMrootDomain      *parent_arg,
                IOPMSettingControllerCallback   handler_arg,
                OSObject    *target_arg,
                uintptr_t   refcon_arg,
                uint32_t    supportedPowerSources,
                const OSSymbol *settings[]);

    void setPMSetting(const OSSymbol *type, OSObject *obj);

    void taggedRelease(const void *tag, const int when) const;
    void free(void);
};

/*
 * Internal helper object for Shutdown/Restart notifications.
 */
#define kPMHaltMaxWorkers   8
#define kPMHaltTimeoutMS    100

class PMHaltWorker : public OSObject
{
    OSDeclareDefaultStructors( PMHaltWorker )

public:
    IOService *  service;    // service being worked on
    AbsoluteTime startTime;  // time when work started
    int          depth;      // work on nubs at this PM-tree depth
    int          visits;     // number of nodes visited (debug)
    IOLock *     lock;
    bool         timeout;    // service took too long

    static  PMHaltWorker * worker( void );
    static  void main( void * arg );
    static  void work( PMHaltWorker * me );
    static  void checkTimeout( PMHaltWorker * me, AbsoluteTime * now );
    virtual void free( void );
};

OSDefineMetaClassAndStructors( PMHaltWorker, OSObject )


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
    IOService       *rootDomain = (IOService *) p0;
    unsigned long   pmRef = (unsigned long) p1;

    DEBUG_LOG("disk_sync_callout: start\n");

#if	HIBERNATION
    IOHibernateSystemSleep();
#endif
    sync_internal();
    rootDomain->allowPowerChange(pmRef);
    DEBUG_LOG("disk_sync_callout: finish\n");
}

// **********************************************************************************

static UInt32 computeDeltaTimeMS( const AbsoluteTime * startTime )
{
	AbsoluteTime	endTime;
	UInt64			nano = 0;

	clock_get_uptime(&endTime);
	if (CMP_ABSOLUTETIME(&endTime, startTime) > 0)
	{
		SUB_ABSOLUTETIME(&endTime, startTime);
		absolutetime_to_nanoseconds(endTime, &nano);
	}

	return (UInt32)(nano / 1000000ULL);
}

// **********************************************************************************
// start
//
// We don't do much here.  The real initialization occurs when the platform
// expert informs us we are the root.
// **********************************************************************************

#define kRootDomainSettingsCount        16

static SYSCTL_STRUCT(_kern, OID_AUTO, sleeptime, 
		     CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
		     &gIOLastSleepTime, timeval, "");

static SYSCTL_STRUCT(_kern, OID_AUTO, waketime, 
		     CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
		     &gIOLastWakeTime, timeval, "");

static const OSSymbol * gIOPMSettingAutoWakeSecondsKey;

bool IOPMrootDomain::start ( IOService * nub )
{
    OSIterator      *psIterator;
    OSDictionary    *tmpDict;

    gIOPMSettingAutoWakeSecondsKey = OSSymbol::withCString(kIOPMSettingAutoWakeSecondsKey);

    const OSSymbol  *settingsArr[kRootDomainSettingsCount] = 
        {
            OSSymbol::withCString(kIOPMSettingSleepOnPowerButtonKey),
            gIOPMSettingAutoWakeSecondsKey,
            OSSymbol::withCString(kIOPMSettingAutoPowerSecondsKey),
            OSSymbol::withCString(kIOPMSettingAutoWakeCalendarKey),
            OSSymbol::withCString(kIOPMSettingAutoPowerCalendarKey),
            OSSymbol::withCString(kIOPMSettingDebugWakeRelativeKey),
            OSSymbol::withCString(kIOPMSettingDebugPowerRelativeKey),
            OSSymbol::withCString(kIOPMSettingWakeOnRingKey),
            OSSymbol::withCString(kIOPMSettingRestartOnPowerLossKey),
            OSSymbol::withCString(kIOPMSettingWakeOnClamshellKey),
            OSSymbol::withCString(kIOPMSettingWakeOnACChangeKey),
            OSSymbol::withCString(kIOPMSettingTimeZoneOffsetKey),
            OSSymbol::withCString(kIOPMSettingDisplaySleepUsesDimKey),
            OSSymbol::withCString(kIOPMSettingMobileMotionModuleKey),
            OSSymbol::withCString(kIOPMSettingGraphicsSwitchKey),
            OSSymbol::withCString(kIOPMStateConsoleShutdown)
        };
    

    pmPowerStateQueue = 0;

    _reserved = (ExpansionData *)IOMalloc(sizeof(ExpansionData));
    if(!_reserved) return false;

    super::start(nub);

    gRootDomain = this;

    PMinit();
    
    sleepSupportedPEFunction = OSSymbol::withCString("IOPMSetSleepSupported");
    canSleep = true;
    setProperty(kIOSleepSupportedKey,true);

    userDisabledAllSleep = false;
    allowSleep = true;
    sleepIsSupported = true;
    systemBooting = true;
    sleepSlider = 0;
    idleSleepPending = false;
    wrangler = NULL;
    sleepASAP = false;
    clamshellIsClosed = false;
    clamshellExists = false;
    ignoringClamshell = true;
    ignoringClamshellDuringWakeup = false;
    acAdaptorConnect = true;

    idxPMCPUClamshell = kCPUUnknownIndex;
    idxPMCPULimitedPower = kCPUUnknownIndex;
        
    tmpDict = OSDictionary::withCapacity(1);
    setProperty(kRootDomainSupportedFeatures, tmpDict);
    tmpDict->release();
    
    settingsCallbacks = OSDictionary::withCapacity(1);

    // Create a list of the valid PM settings that we'll relay to
    // interested clients in setProperties() => setPMSetting()
    allowedPMSettings = OSArray::withObjects(
                    (const OSObject **)settingsArr,
                    kRootDomainSettingsCount,
                    0);
                    
    fPMSettingsDict = OSDictionary::withCapacity(5);
            
    pmPowerStateQueue = IOPMPowerStateQueue::PMPowerStateQueue(this);
    getPMworkloop()->addEventSource(pmPowerStateQueue);
    
    featuresDictLock = IOLockAlloc();
    settingsCtrlLock = IORecursiveLockAlloc();
    
    extraSleepTimer = thread_call_allocate(
                        (thread_call_func_t)sleepTimerExpired, 
                        (thread_call_param_t) this);
    clamshellWakeupIgnore = thread_call_allocate(
                        (thread_call_func_t)wakeupClamshellTimerExpired, 
                        (thread_call_param_t) this);
    diskSyncCalloutEntry = thread_call_allocate(
                        &disk_sync_callout, 
                        (thread_call_param_t) this);

    // create our parent
    patriarch = new IORootParent;
    patriarch->init();
    patriarch->attach(this);
    patriarch->start(this);
    patriarch->addPowerChild(this);
        
    registerPowerDriver(this,ourPowerStates,number_of_power_states);

    setPMRootDomain(this);
    // set a clamp until we sleep
    changePowerStateToPriv(ON_STATE);

    // install power change handler
    registerPrioritySleepWakeInterest( &sysPowerDownHandler, this, 0);

#if !NO_KERNEL_HID
    // Register for a notification when IODisplayWrangler is published
    _displayWranglerNotifier = addNotification( 
                gIOPublishNotification, serviceMatching("IODisplayWrangler"), 
                &displayWranglerPublished, this, 0);
#endif

    // Battery location published - ApplePMU support only
    _batteryPublishNotifier = addNotification( 
                gIOPublishNotification, serviceMatching("IOPMPowerSource"), 
                &batteryPublished, this, this);
     

    const OSSymbol *ucClassName = OSSymbol::withCStringNoCopy("RootDomainUserClient");
    setProperty(gIOUserClientClassKey, (OSObject *) ucClassName);
    ucClassName->release();

    // IOBacklightDisplay can take a long time to load at boot, or it may
    // not load at all if you're booting with clamshell closed. We publish
    // 'DisplayDims' here redundantly to get it published early and at all.
    psIterator = getMatchingServices( serviceMatching("IOPMPowerSource") );
    if( psIterator && psIterator->getNextObject() )
    {
        // There's at least one battery on the system, so we publish
        // 'DisplayDims' support for the LCD.
        publishFeature("DisplayDims");
    }
    if(psIterator) {
        psIterator->release();
    }


    sysctl_register_oid(&sysctl__kern_sleeptime);
    sysctl_register_oid(&sysctl__kern_waketime);

#if	HIBERNATION
    IOHibernateSystemInit(this);
#endif

    registerService();						// let clients find us

    return true;
}

// **********************************************************************************
// setProperties
//
// Receive a setProperty call
// The "System Boot" property means the system is completely booted.
// **********************************************************************************
IOReturn IOPMrootDomain::setProperties ( OSObject *props_obj)
{
    IOReturn                        return_value = kIOReturnSuccess;
    OSDictionary                    *dict = OSDynamicCast(OSDictionary, props_obj);
    OSBoolean                       *b;
    OSNumber                        *n;
    OSString                        *str;
    OSSymbol                        *type;
    OSObject                        *obj;
    unsigned int                    i;

    const OSSymbol *boot_complete_string = 
                OSSymbol::withCString("System Boot Complete");
    const OSSymbol *sys_shutdown_string = 
                OSSymbol::withCString("System Shutdown");
    const OSSymbol *stall_halt_string = 
                OSSymbol::withCString("StallSystemAtHalt");
    const OSSymbol *battery_warning_disabled_string = 
                OSSymbol::withCString("BatteryWarningsDisabled");
    const OSSymbol *idle_seconds_string = 
                OSSymbol::withCString("System Idle Seconds");
#if	HIBERNATION
    const OSSymbol *hibernatemode_string = 
                OSSymbol::withCString(kIOHibernateModeKey);
    const OSSymbol *hibernatefile_string = 
                OSSymbol::withCString(kIOHibernateFileKey);
    const OSSymbol *hibernatefreeratio_string = 
                OSSymbol::withCString(kIOHibernateFreeRatioKey);
    const OSSymbol *hibernatefreetime_string = 
                OSSymbol::withCString(kIOHibernateFreeTimeKey);
#endif
    const OSSymbol *sleepdisabled_string =
                OSSymbol::withCString("SleepDisabled");
    
    if(!dict) 
    {
        return_value = kIOReturnBadArgument;
        goto exit;
    }

    if ((n = OSDynamicCast(OSNumber, dict->getObject(idle_seconds_string))))
    {
        setProperty(idle_seconds_string, n);
	idleSeconds = n->unsigned32BitValue();
    }

    if( systemBooting 
        && boot_complete_string 
        && dict->getObject(boot_complete_string)) 
    {
        systemBooting = false;
        adjustPowerState();

        // If lid is closed, re-send lid closed notification
        // now that booting is complete.
        if( clamshellIsClosed )
        {
            this->receivePowerNotification(kLocalEvalClamshellCommand);
        }
    }
    
    if( battery_warning_disabled_string
        && dict->getObject(battery_warning_disabled_string))
    {
        setProperty( battery_warning_disabled_string, 
                        dict->getObject(battery_warning_disabled_string));
    }
    
    if( sys_shutdown_string 
        && (b = OSDynamicCast(OSBoolean, dict->getObject(sys_shutdown_string)))) 
    {
    
        if(kOSBooleanTrue == b)
        {
            /* We set systemShutdown = true during shutdown
               to prevent sleep at unexpected times while loginwindow is trying
               to shutdown apps and while the OS is trying to transition to
               complete power of.
               
               Set to true during shutdown, as soon as loginwindow shows
               the "shutdown countdown dialog", through individual app
               termination, and through black screen kernel shutdown.
             */
             kprintf("systemShutdown true\n");
            systemShutdown = true;
        } else {
            /*
             A shutdown was initiated, but then the shutdown
             was cancelled, clearing systemShutdown to false here.
            */
            kprintf("systemShutdown false\n");
            systemShutdown = false;            
        }        
    }
    
    if( stall_halt_string
        && (b = OSDynamicCast(OSBoolean, dict->getObject(stall_halt_string))) ) 
    {
        setProperty(stall_halt_string, b);
    }

#if	HIBERNATION
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
#endif
    
    if( sleepdisabled_string
        && (b = OSDynamicCast(OSBoolean, dict->getObject(sleepdisabled_string))) )
    {
        setProperty(sleepdisabled_string, b);
        
        userDisabledAllSleep = (kOSBooleanTrue == b);
    }

    // Relay our allowed PM settings onto our registered PM clients
    for(i = 0; i < allowedPMSettings->getCount(); i++) {

        type = (OSSymbol *)allowedPMSettings->getObject(i);
        if(!type) continue;

        obj = dict->getObject(type);
        if(!obj) continue;

	if ((gIOPMSettingAutoWakeSecondsKey == type) && ((n = OSDynamicCast(OSNumber, obj))))
	{
	    UInt32 rsecs = n->unsigned32BitValue();
	    if (!rsecs)
		autoWakeStart = autoWakeEnd = 0;
	    else
	    {
		AbsoluteTime deadline;
		clock_interval_to_deadline(rsecs + kAutoWakePostWindow, kSecondScale, &deadline);
		autoWakeEnd = AbsoluteTime_to_scalar(&deadline);
		if (rsecs > kAutoWakePreWindow)
		    rsecs -= kAutoWakePreWindow;
		else
		    rsecs = 0;
		clock_interval_to_deadline(rsecs, kSecondScale, &deadline);
		autoWakeStart = AbsoluteTime_to_scalar(&deadline);
	    }
	}
        
        return_value = setPMSetting(type, obj);
        
        if(kIOReturnSuccess != return_value) goto exit;
    }

exit:
    if(sleepdisabled_string) sleepdisabled_string->release();
    if(boot_complete_string) boot_complete_string->release();
    if(stall_halt_string) stall_halt_string->release();
    if(idle_seconds_string) idle_seconds_string->release();
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
	if (getAggressiveness(kPMMinutesToDim, (unsigned long *)&longestNonSleepSlider)
		!= kIOReturnSuccess)
		longestNonSleepSlider = 0;

    if ( type == kPMMinutesToSleep ) {
        DEBUG_LOG("PM idle time -> %ld secs (ena %d)\n", idleSeconds, (value != 0));
        if (0x7fffffff == value)
            value = idleSeconds;

        if ( (sleepSlider == 0) && (value != 0) ) {
            if (!wrangler)
            {
                sleepASAP = false;
                changePowerStateToPriv(ON_STATE);
                if (idleSeconds)
                {
                    AbsoluteTime deadline;
                    // stay awake for at least idleSeconds
                    clock_interval_to_deadline(idleSeconds, kSecondScale, &deadline);	
                    thread_call_enter_delayed(extraSleepTimer, deadline);
                    // this gets turned off when we sleep again
                    idleSleepPending = true;
                }
            }
            else
            {
                // If sleepASAP is already set, then calling adjustPowerState() here
                // will put the system to sleep immediately which is bad.  Note that
                // this aggressiveness change can occur without waking up the display
                // by (dis)connecting the AC adapter. To get around this, the power
                // clamp is restore to ON state then dropped after waiting for the
                // sleep timer to expire.

                if (sleepASAP)
                {
                    AbsoluteTime deadline;
                    // stay awake for at least sleepSlider minutes
                    clock_interval_to_deadline(value * 60, kSecondScale, &deadline);	
                    thread_call_enter_delayed(extraSleepTimer, deadline);
                    // this gets turned off when we sleep again
                    idleSleepPending = true;
                    sleepASAP = false;
                }
            }
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
    DEBUG_LOG("SleepTimerExpired\n");

    AbsoluteTime time;

    clock_get_uptime(&time);
    if ((AbsoluteTime_to_scalar(&time) > autoWakeStart) && (AbsoluteTime_to_scalar(&time) < autoWakeEnd))
    {
	thread_call_enter_delayed(extraSleepTimer, *((AbsoluteTime *) &autoWakeEnd));
	return;
    }

    // accelerate disk spin down if spin down timer is non-zero (zero = never spin down)  
    if(0 != user_spindown)
        setQuickSpinDownTimeout();

    sleepASAP = true;
    adjustPowerState();
}


void IOPMrootDomain::stopIgnoringClamshellEventsDuringWakeup(void)
{
    // Allow clamshell-induced sleep now
    ignoringClamshellDuringWakeup = false;

    // Re-send clamshell event, in case it causes a sleep
    if(clamshellIsClosed) 
        this->receivePowerNotification( kLocalEvalClamshellCommand );
}

//*********************************************************************************
// setAggressiveness
//
// Some aggressiveness factor has changed.  We broadcast it to the hierarchy while on
// the Power Mangement workloop thread.  This enables objects in the
// hierarchy to successfully alter their idle timers, which are all on the
// same thread.
//*********************************************************************************

IOReturn IOPMrootDomain::setAggressiveness ( unsigned long type, unsigned long newLevel )
{
    IOWorkLoop * pmWorkLoop = getPMworkloop();
    if (pmWorkLoop)
        pmWorkLoop->runAction(broadcast_aggressiveness,this,(void *)type,(void *)newLevel);

    return kIOReturnSuccess;
}


// **********************************************************************************
// sleepSystem
//
// **********************************************************************************
/* public */
IOReturn IOPMrootDomain::sleepSystem ( void )
{
    return sleepSystemOptions (NULL);
}

/* private */
IOReturn IOPMrootDomain::sleepSystemOptions ( OSDictionary *options )
{
	/* sleepSystem is a public function, and may be called by any kernel driver.
     * And that's bad - drivers should sleep the system by calling 
     * receivePowerNotification() instead. Drivers should not use sleepSystem.
     *
     * Note that user space app calls to IOPMSleepSystem() will also travel
     * this code path and thus be correctly identified as software sleeps.
     */
          
    if (options && options->getObject("OSSwitch")) 
    {

        // Log specific sleep cause for OS Switch hibernation
        return privateSleepSystem( kIOPMOSSwitchHibernationKey) ;

    } else {

        return privateSleepSystem( kIOPMSoftwareSleepKey);

    }
}

/* private */
IOReturn IOPMrootDomain::privateSleepSystem ( const char *sleepReason )
{
    // Record sleep cause in IORegistry
    if (sleepReason) {
        setProperty(kRootDomainSleepReasonKey, sleepReason);
    }

    if(systemShutdown) {
        kprintf("Preventing system sleep on grounds of systemShutdown.\n");
    }
    
    if( userDisabledAllSleep )
    {
        /* Prevent sleep of all kinds if directed to by user space */
        return kIOReturnNotPermitted;
    }

    if ( !systemBooting 
      && !systemShutdown 
      && allowSleep)
    {
        if ( !sleepIsSupported ) {
            setSleepSupported( kPCICantSleep );
            kprintf("Sleep prevented by kIOPMPreventSystemSleep flag\n");
        }
        patriarch->sleepSystem();
        return kIOReturnSuccess;
    } else {
        // Unable to sleep because system is in the process of booting or shutting down,
        // or sleep has otherwise been disallowed.
        return kIOReturnError;
    }
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
    AbsoluteTime    deadline;

    DEBUG_LOG("PowerChangeDone: %ld -> %ld\n", previousState, getPowerState());

    switch ( getPowerState() ) {
        case SLEEP_STATE:
			if ( previousState != ON_STATE )
				break;

            if ( canSleep && sleepIsSupported ) 
            {
                // re-enable this timer for next sleep
                idleSleepPending = false;			

                uint32_t secs, microsecs;
                clock_get_calendar_microtime(&secs, &microsecs);
                logtime(secs);
                gIOLastSleepTime.tv_sec  = secs;
                gIOLastSleepTime.tv_usec = microsecs;

#if	HIBERNATION
                IOLog("System %sSleep\n", gIOHibernateState ? "Safe" : "");

                IOHibernateSystemHasSlept();
#else
                IOLog("System Sleep\n");
#endif

                getPlatform()->sleepKernel();

                // The CPU(s) are off at this point. When they're awakened by CPU interrupt,
                // code will resume execution here.

                // Now we're waking...
#if	HIBERNATION
                IOHibernateSystemWake();
#endif

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
#if	HIBERNATION
                IOLog("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
#endif
                systemWake();
                
                // Allow drivers to request extra processing time before clamshell
                // sleep if kIOREMSleepEnabledKey is present.
                // Ignore clamshell events for at least 5 seconds 
                if(getProperty(kIOREMSleepEnabledKey)) {
                    // clamshellWakeupIgnore callout clears ignoreClamshellDuringWakeup bit   
                    clock_interval_to_deadline(5, kSecondScale, &deadline);
                    if(clamshellWakeupIgnore)  {
                        thread_call_enter_delayed(clamshellWakeupIgnore, deadline);
                    }
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
            } else {
                // allow us to step up a power state
                patriarch->sleepToDoze();

                // ignore children's request for higher power during doze.
                powerOverrideOnPriv();
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

            // Invalidate prior activity tickles to allow wake from doze.
            if (wrangler) wrangler->changePowerStateTo(0);
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
    if ( getPowerState() == DOZE_STATE ) 
    {
        // Reset sleep support till next sleep attempt.
        // A machine's support of sleep vs. doze can change over the course of
        // a running system, so we recalculate it before every sleep.
        setSleepSupported(0);

        changePowerStateToPriv(ON_STATE);
        powerOverrideOffPriv();

        // early wake notification
        tellClients(kIOMessageSystemWillPowerOn);

        // allow us to wake if children so desire
        patriarch->wakeSystem();
    }
}


// *****************************************************************************
// publishFeature
//
// Adds a new feature to the supported features dictionary
// 
// 
// *****************************************************************************
void IOPMrootDomain::publishFeature( const char * feature )
{
    publishFeature(feature, kIOPMSupportedOnAC 
                                  | kIOPMSupportedOnBatt 
                                  | kIOPMSupportedOnUPS,
                            NULL);
    return;
}


// *****************************************************************************
// publishFeature (with supported power source specified)
//
// Adds a new feature to the supported features dictionary
// 
// 
// *****************************************************************************
void IOPMrootDomain::publishFeature( 
    const char *feature, 
    uint32_t supportedWhere,
    uint32_t *uniqueFeatureID)
{
    static uint16_t     next_feature_id = 500;

    OSNumber            *new_feature_data = NULL;
    OSNumber            *existing_feature = NULL;
    OSArray             *existing_feature_arr = NULL;
    OSObject            *osObj = NULL;
    uint32_t            feature_value = 0;

    supportedWhere &= kRD_AllPowerSources; // mask off any craziness!

//    kprintf("IOPMrootDomain::publishFeature [\"%s\":%0x01x]\n", feature, supportedWhere);

    if(!supportedWhere) {
        // Feature isn't supported anywhere!
        return;
    }
    
    if(next_feature_id > 5000) {
        // Far, far too many features!
        return;
    }

    if(featuresDictLock) IOLockLock(featuresDictLock);

    OSDictionary *features =
        (OSDictionary *) getProperty(kRootDomainSupportedFeatures);
    
    // Create new features dict if necessary
    if ( features && OSDynamicCast(OSDictionary, features)) {
        features = OSDictionary::withDictionary(features);
    } else {
        features = OSDictionary::withCapacity(1);
    }
    
    // Create OSNumber to track new feature
    
    next_feature_id += 1;
    if( uniqueFeatureID ) {
        // We don't really mind if the calling kext didn't give us a place
        // to stash their unique id. Many kexts don't plan to unload, and thus
        // have no need to remove themselves later.
        *uniqueFeatureID = next_feature_id;
    }
    
    feature_value = supportedWhere + (next_feature_id << 16);
    new_feature_data = OSNumber::withNumber(
                                (unsigned long long)feature_value, 32);

    // Does features object already exist?
    if( (osObj = features->getObject(feature)) )
    {
        if(( existing_feature = OSDynamicCast(OSNumber, osObj) ))
        {
            // We need to create an OSArray to hold the now 2 elements.
            existing_feature_arr = OSArray::withObjects(
                            (const OSObject **)&existing_feature, 1, 2);
            existing_feature_arr->setObject(new_feature_data);
            features->setObject(feature, existing_feature_arr);
        } else if(( existing_feature_arr = OSDynamicCast(OSArray, osObj) ))
        {
            // Add object to existing array
            existing_feature_arr->setObject(new_feature_data);        
        }
    } else {
        // The easy case: no previously existing features listed. We simply
        // set the OSNumber at key 'feature' and we're on our way.
        features->setObject(feature, new_feature_data);        
    }
    
    new_feature_data->release();

    setProperty(kRootDomainSupportedFeatures, features);

    features->release();

    if(featuresDictLock) IOLockUnlock(featuresDictLock);    

    // Notify EnergySaver and all those in user space so they might
    // re-populate their feature specific UI    
    if(pmPowerStateQueue) {
        pmPowerStateQueue->featureChangeOccurred( 
                            kIOPMMessageFeatureChange, this);
    }
}

// *****************************************************************************
// removePublishedFeature
//
// Removes previously published feature
// 
// 
// *****************************************************************************
IOReturn IOPMrootDomain::removePublishedFeature( uint32_t removeFeatureID )
{
    IOReturn                ret = kIOReturnError;
    uint32_t                feature_value = 0;
    uint16_t                feature_id = 0;
    bool                    madeAChange = false;
    
    OSSymbol                *dictKey = NULL;
    OSCollectionIterator    *dictIterator = NULL;
    OSArray                 *arrayMember  = NULL;
    OSNumber                *numberMember = NULL;
    OSObject                *osObj        = NULL;
    OSNumber                *osNum        = NULL;

    if(featuresDictLock) IOLockLock(featuresDictLock);

    OSDictionary *features =
        (OSDictionary *) getProperty(kRootDomainSupportedFeatures);
    
    if ( features && OSDynamicCast(OSDictionary, features) )
    {
        // Any modifications to the dictionary are made to the copy to prevent
        // races & crashes with userland clients. Dictionary updated
        // automically later.
        features = OSDictionary::withDictionary(features);
    } else {
        features = NULL;
        ret = kIOReturnNotFound;
        goto exit;
    }
    
    // We iterate 'features' dictionary looking for an entry tagged
    // with 'removeFeatureID'. If found, we remove it from our tracking
    // structures and notify the OS via a general interest message.
    
    dictIterator = OSCollectionIterator::withCollection(features);
    if(!dictIterator) {
        goto exit;
    }
    
    while( (dictKey = OSDynamicCast(OSSymbol, dictIterator->getNextObject())) )
    {
        osObj = features->getObject(dictKey);
        
        // Each Feature is either tracked by an OSNumber
        if( osObj && (numberMember = OSDynamicCast(OSNumber, osObj)) )
        {
            feature_value = numberMember->unsigned32BitValue();
            feature_id = (uint16_t)(feature_value >> 16);

            if( feature_id == (uint16_t)removeFeatureID )
            {
                // Remove this node
                features->removeObject(dictKey);
                madeAChange = true;
                break;
            }
        
        // Or tracked by an OSArray of OSNumbers
        } else if( osObj && (arrayMember = OSDynamicCast(OSArray, osObj)) )
        {
            unsigned int arrayCount = arrayMember->getCount();
            
            for(unsigned int i=0; i<arrayCount; i++)
            {
                osNum = OSDynamicCast(OSNumber, arrayMember->getObject(i));
                if(!osNum) {
                    continue;
                }
                
                feature_value = osNum->unsigned32BitValue();
                feature_id = (uint16_t)(feature_value >> 16);

                if( feature_id == (uint16_t)removeFeatureID )
                {
                    // Remove this node
                    if( 1 == arrayCount ) {
                        // If the array only contains one element, remove
                        // the whole thing.
                        features->removeObject(dictKey);
                    } else {
                        // Otherwise just remove the element in question.
                        arrayMember->removeObject(i);                    
                    }

                    madeAChange = true;
                    break;
                }
            }
        }    
    }
    
    
    dictIterator->release();
    
    if( madeAChange )
    {
        ret = kIOReturnSuccess;    

        setProperty(kRootDomainSupportedFeatures, features);
    
        // Notify EnergySaver and all those in user space so they might
        // re-populate their feature specific UI    
        if(pmPowerStateQueue) {
            pmPowerStateQueue->featureChangeOccurred( 
                                kIOPMMessageFeatureChange, this);
        }
    } else {
        ret = kIOReturnNotFound;
    }
    
exit:
    if(features)    features->release();
    if(featuresDictLock) IOLockUnlock(featuresDictLock);    
    return ret;
}


// **********************************************************************************
// unIdleDevice
//
// Enqueues unidle event to be performed later in a serialized context.
// 
// **********************************************************************************
void IOPMrootDomain::unIdleDevice( IOService *theDevice, unsigned long theState )
{
    if(pmPowerStateQueue)
        pmPowerStateQueue->unIdleOccurred(theDevice, theState);
}

// **********************************************************************************
// announcePowerSourceChange
//
// Notifies "interested parties" that the batteries have changed state
// 
// **********************************************************************************
void IOPMrootDomain::announcePowerSourceChange( void )
{
    IORegistryEntry *_batteryRegEntry = (IORegistryEntry *) getProperty("BatteryEntry");

    // (if possible) re-publish power source state under IOPMrootDomain;
    // only do so if the battery controller publishes an IOResource 
    // defining battery location. Called from ApplePMU battery driver.

    if(_batteryRegEntry)
    {
        OSArray             *batt_info;
        batt_info = (OSArray *) _batteryRegEntry->getProperty(kIOBatteryInfoKey);
        if(batt_info)
            setProperty(kIOBatteryInfoKey, batt_info);
    }

}


// *****************************************************************************
// setPMSetting (private)
//
// Internal helper to relay PM settings changes from user space to individual
// drivers. Should be called only by IOPMrootDomain::setProperties.
// 
// *****************************************************************************
IOReturn     IOPMrootDomain::setPMSetting(
    const OSSymbol *type, 
    OSObject *obj)
{
    OSArray             *arr = NULL;
    PMSettingObject     *p_obj = NULL;
    int                 count;
    int                 i;

    if(NULL == type) return kIOReturnBadArgument;

    IORecursiveLockLock(settingsCtrlLock);
    
    fPMSettingsDict->setObject(type, obj);

    arr = (OSArray *)settingsCallbacks->getObject(type);
    if(NULL == arr) goto exit;
    count = arr->getCount();
    for(i=0; i<count; i++) {
        p_obj = (PMSettingObject *)OSDynamicCast(PMSettingObject, arr->getObject(i));
        if(p_obj) p_obj->setPMSetting(type, obj);
    }

exit:
    IORecursiveLockUnlock(settingsCtrlLock);
    return kIOReturnSuccess;
}

// *****************************************************************************
// copyPMSetting (public)
//
// Allows kexts to safely read setting values, without being subscribed to
// notifications.
// 
// *****************************************************************************
OSObject * IOPMrootDomain::copyPMSetting(
    OSSymbol *whichSetting)
{
    OSObject *obj = NULL;

    if(!whichSetting) return NULL;

    IORecursiveLockLock(settingsCtrlLock);
    obj = fPMSettingsDict->getObject(whichSetting);
    if(obj) {
        obj->retain();
    }
    IORecursiveLockUnlock(settingsCtrlLock);
    
    return obj;
}

// *****************************************************************************
// registerPMSettingController (public)
//
// direct wrapper to registerPMSettingController with uint32_t power source arg
// *****************************************************************************
IOReturn IOPMrootDomain::registerPMSettingController(
    const OSSymbol *                settings[],
    IOPMSettingControllerCallback   func,
    OSObject                        *target,
    uintptr_t                       refcon,
    OSObject                        **handle)
{
    return registerPMSettingController( 
            settings,
            (kIOPMSupportedOnAC | kIOPMSupportedOnBatt | kIOPMSupportedOnUPS),
            func, target, refcon, handle);
}

// *****************************************************************************
// registerPMSettingController (public)
//
// Kexts may register for notifications when a particular setting is changed.
// A list of settings is available in IOPM.h.
// Arguments:
//  * settings - An OSArray containing OSSymbols. Caller should populate this
//          array with a list of settings caller wants notifications from.
//  * func - A C function callback of the type IOPMSettingControllerCallback
//  * target - caller may provide an OSObject *, which PM will pass as an 
//          target to calls to "func"
//  * refcon - caller may provide an void *, which PM will pass as an 
//          argument to calls to "func"
//  * handle - This is a return argument. We will populate this pointer upon
//          call success. Hold onto this and pass this argument to
//          IOPMrootDomain::deRegisterPMSettingCallback when unloading your kext
// Returns:
//      kIOReturnSuccess on success
// *****************************************************************************
IOReturn IOPMrootDomain::registerPMSettingController(
    const OSSymbol *                settings[],
    uint32_t                        supportedPowerSources,
    IOPMSettingControllerCallback   func,
    OSObject                        *target,
    uintptr_t                       refcon,
    OSObject                        **handle)
{
    PMSettingObject     *pmso = NULL;
    OSArray             *list = NULL;
    IOReturn            ret = kIOReturnSuccess;
    int                 i;

    if( NULL == settings ||
        NULL == func ||
        NULL == handle)
    {
        return kIOReturnBadArgument;
    }

    pmso = PMSettingObject::pmSettingObject(
                (IOPMrootDomain *)this, func, target, 
                refcon, supportedPowerSources, settings);

    if(!pmso) {
        ret = kIOReturnInternalError;
        goto bail_no_unlock;
    }

    IORecursiveLockLock(settingsCtrlLock);
    for(i=0; settings[i]; i++) 
    {
        list = (OSArray *)settingsCallbacks->getObject(settings[i]);
        if(!list) {
            // New array of callbacks for this setting
            list = OSArray::withCapacity(1);
            settingsCallbacks->setObject(settings[i], list);
            list->release();
        }

        // Add caller to the callback list
        list->setObject(pmso);
    }

    IORecursiveLockUnlock(settingsCtrlLock);
    
    ret = kIOReturnSuccess;

    // Track this instance by its OSData ptr from now on  
    *handle = pmso;

bail_no_unlock:
    if(kIOReturnSuccess != ret) 
    {
        // Error return case
        if(pmso) pmso->release();
        if(handle) *handle = NULL;
    }
    return ret;
}


//******************************************************************************
// sleepOnClamshellClosed
//
// contains the logic to determine if the system should sleep when the clamshell
// is closed.
//******************************************************************************

bool IOPMrootDomain::shouldSleepOnClamshellClosed ( void )
{
    return ( !ignoringClamshell 
          && !ignoringClamshellDuringWakeup 
          && !(desktopMode && acAdaptorConnect) );
}

void IOPMrootDomain::sendClientClamshellNotification ( void )
{
    /* Only broadcast clamshell alert if clamshell exists. */
    if(!clamshellExists)
        return;
        
    setProperty(kAppleClamshellStateKey, 
                    clamshellIsClosed ? kOSBooleanTrue : kOSBooleanFalse);

    setProperty(kAppleClamshellCausesSleepKey, 
       shouldSleepOnClamshellClosed() ? kOSBooleanTrue : kOSBooleanFalse);


    /* Argument to message is a bitfiel of 
     *      ( kClamshellStateBit | kClamshellSleepBit )
     */
    messageClients(kIOPMMessageClamshellStateChange,
        (void *) ( (clamshellIsClosed ? kClamshellStateBit : 0)
             | ( shouldSleepOnClamshellClosed() ? kClamshellSleepBit : 0)) );
}

//******************************************************************************
// informCPUStateChange
//
// Call into PM CPU code so that CPU power savings may dynamically adjust for
// running on battery, with the lid closed, etc.
//
// informCPUStateChange is a no-op on non x86 systems
// only x86 has explicit support in the IntelCPUPowerManagement kext
//******************************************************************************

void IOPMrootDomain::informCPUStateChange(
    uint32_t type, 
    uint32_t value )
{
#ifdef __i386__

    pmioctlVariableInfo_t varInfoStruct;                            
    int                 pmCPUret = 0;
    const char          *varNameStr = NULL;
    int32_t             *varIndex   = NULL;

    if (kInformAC == type) {
        varNameStr = kIOPMRootDomainBatPowerCString;
        varIndex = &idxPMCPULimitedPower;
    } else if (kInformLid == type) {
        varNameStr = kIOPMRootDomainLidCloseCString;
        varIndex = &idxPMCPUClamshell;
    } else {
        return;
    }
    
    // Set the new value!
    // pmCPUControl will assign us a new ID if one doesn't exist yet
    bzero(&varInfoStruct, sizeof(pmioctlVariableInfo_t));
    varInfoStruct.varID         = *varIndex;
    varInfoStruct.varType       = vBool;
    varInfoStruct.varInitValue  = value;
    varInfoStruct.varCurValue   = value;
    strncpy( (char *)varInfoStruct.varName,
             (const char *)varNameStr,
             strlen(varNameStr) + 1 );                 
    
    // Set!
    pmCPUret = pmCPUControl( PMIOCSETVARINFO, (void *)&varInfoStruct );

    // pmCPU only assigns numerical id's when a new varName is specified
    if ((0 == pmCPUret)
        && (*varIndex == kCPUUnknownIndex))
    {
        // pmCPUControl has assigned us a new variable ID. 
        // Let's re-read the structure we just SET to learn that ID.
        pmCPUret = pmCPUControl( PMIOCGETVARNAMEINFO, (void *)&varInfoStruct );

        if (0 == pmCPUret) 
        {        
            // Store it in idxPMCPUClamshell or idxPMCPULimitedPower
            *varIndex = varInfoStruct.varID;
        }
    } 
    
    return;
    
#endif __i386__
}

//******************************************************************************
// systemPowerEventOccurred
//
// The power controller is notifying us of a hardware-related power management
// event that we must handle. 
//
// systemPowerEventOccurred covers the same functionality that receivePowerNotification
// does; it simply provides a richer API for conveying more information.
//******************************************************************************
IOReturn IOPMrootDomain::systemPowerEventOccurred(
    const OSSymbol *event,
    uint32_t intValue)
{
    IOReturn        attempt = kIOReturnSuccess;
    OSNumber        *newNumber = NULL;

    if (!event) 
        return kIOReturnBadArgument;
        
    newNumber = OSNumber::withNumber(intValue, 8*sizeof(intValue));
    if (!newNumber)
        return kIOReturnInternalError;

    attempt = systemPowerEventOccurred(event, (OSObject *)newNumber);

    newNumber->release();

    return attempt;
}

IOReturn IOPMrootDomain::systemPowerEventOccurred(
    const OSSymbol *event,
    OSObject *value)
{
    OSDictionary *thermalsDict = NULL;
    bool shouldUpdate = true;
    
    if (!event || !value) 
        return kIOReturnBadArgument;

    // LOCK
    // We reuse featuresDict Lock because it already exists and guards
    // the very infrequently used publish/remove feature mechanism; so there's zero rsk
    // of stepping on that lock.
    if (featuresDictLock) IOLockLock(featuresDictLock);

    thermalsDict = (OSDictionary *)getProperty(kIOPMRootDomainPowerStatusKey);
                   
    if (thermalsDict && OSDynamicCast(OSDictionary, thermalsDict)) {
        thermalsDict = OSDictionary::withDictionary(thermalsDict);                        
    } else {
        thermalsDict = OSDictionary::withCapacity(1);
    }

    if (!thermalsDict) {
        shouldUpdate = false;
        goto exit;
    }

    thermalsDict->setObject (event, value);

    setProperty (kIOPMRootDomainPowerStatusKey, thermalsDict);

    thermalsDict->release();

exit:
    // UNLOCK
    if (featuresDictLock) IOLockUnlock(featuresDictLock);

    if (shouldUpdate)
        messageClients (kIOPMMessageSystemPowerEventOccurred, (void *)NULL);

    return kIOReturnSuccess;
}


//******************************************************************************
// receivePowerNotification
//
// The power controller is notifying us of a hardware-related power management
// event that we must handle. This may be a result of an 'environment' interrupt from
// the power mgt micro.
//******************************************************************************

IOReturn IOPMrootDomain::receivePowerNotification (UInt32 msg)
{
    bool        eval_clamshell = false;

    /*
     * Local (IOPMrootDomain only) eval clamshell command
     */
    if (msg & kLocalEvalClamshellCommand)
    {
        eval_clamshell = true;
    }

    /*
     * Overtemp
     */
    if (msg & kIOPMOverTemp) 
    {
        IOLog("PowerManagement emergency overtemp signal. Going to sleep!");
        
        privateSleepSystem (kIOPMThermalEmergencySleepKey);
    }

    /*
     * PMU Processor Speed Change
     */
    if (msg & kIOPMProcessorSpeedChange) 
    {
        IOService *pmu = waitForService(serviceMatching("ApplePMU"));
        pmu->callPlatformFunction("prepareForSleep", false, 0, 0, 0, 0);
        getPlatform()->sleepKernel();
        pmu->callPlatformFunction("recoverFromSleep", false, 0, 0, 0, 0);
    }

    /*
     * Sleep Now!
     */
    if (msg & kIOPMSleepNow) 
    {
        privateSleepSystem (kIOPMSoftwareSleepKey);
    }
    
    /*
     * Power Emergency
     */
    if (msg & kIOPMPowerEmergency) 
    {
        privateSleepSystem (kIOPMLowPowerSleepKey);
    }

    
    /*
     * Clamshell OPEN
     */
    if (msg & kIOPMClamshellOpened) 
    {
        // Received clamshel open message from clamshell controlling driver
        // Update our internal state and tell general interest clients
        clamshellIsClosed = false;
        clamshellExists = true;
                
        // Tell PMCPU
        informCPUStateChange(kInformLid, 0);

        // Tell general interest clients        
        sendClientClamshellNotification();
    } 

    /* 
     * Clamshell CLOSED
     * Send the clamshell interest notification since the lid is closing. 
     */
    if (msg & kIOPMClamshellClosed)
    {
        // Received clamshel open message from clamshell controlling driver
        // Update our internal state and tell general interest clients
        clamshellIsClosed = true;
        clamshellExists = true;

        // Tell PMCPU
        informCPUStateChange(kInformLid, 1);

        // Tell general interest clients
        sendClientClamshellNotification();
        
        // And set eval_clamshell = so we can attempt 
        eval_clamshell = true;
    }

    /*
     * Set Desktop mode (sent from graphics)
     *
     *  -> reevaluate lid state
     */
    if (msg & kIOPMSetDesktopMode) 
    {
        desktopMode = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetDesktopMode | kIOPMSetValue);

        sendClientClamshellNotification();

        // Re-evaluate the lid state
        if( clamshellIsClosed )
        {
            eval_clamshell = true;
        }
    }
    
    /*
     * AC Adaptor connected
     *
     *  -> reevaluate lid state
     */
    if (msg & kIOPMSetACAdaptorConnected) 
    {
        acAdaptorConnect = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetACAdaptorConnected | kIOPMSetValue);

        // Tell PMCPU
        informCPUStateChange(kInformAC, !acAdaptorConnect);

        sendClientClamshellNotification();

        // Re-evaluate the lid state
        if( clamshellIsClosed )
        {
            eval_clamshell = true;
        }

    }
    
    /*
     * Enable Clamshell (external display disappear)
     *
     *  -> reevaluate lid state
     */
    if (msg & kIOPMEnableClamshell) 
    {
        // Re-evaluate the lid state
        // System should sleep on external display disappearance
        // in lid closed operation.
        if( clamshellIsClosed && (true == ignoringClamshell) )        
        {
            eval_clamshell = true;
        }

        ignoringClamshell = false;

        sendClientClamshellNotification();
    }
    
    /*
     * Disable Clamshell (external display appeared)
     * We don't bother re-evaluating clamshell state. If the system is awake,
     * the lid is probably open. 
     */
    if (msg & kIOPMDisableClamshell) 
    {
        ignoringClamshell = true;

        sendClientClamshellNotification();
    }

    /*
     * Evaluate clamshell and SLEEP if appropiate
     */
    if ( eval_clamshell && shouldSleepOnClamshellClosed() ) 
    {


        // SLEEP!
        privateSleepSystem (kIOPMClamshellSleepKey);
    }

    /*
     * Power Button
     */
    if (msg & kIOPMPowerButton) 
    {
        // toggle state of sleep/wake
        // are we dozing?
        if ( getPowerState() == DOZE_STATE ) 
        {
            // yes, tell the tree we're waking 
            systemWake();
            // wake the Display Wrangler
            reportUserInput();
        }
        else {
            OSString *pbs = OSString::withCString("DisablePowerButtonSleep");
            // Check that power button sleep is enabled
            if( pbs ) {
                if( kOSBooleanTrue != getProperty(pbs))
                privateSleepSystem (kIOPMPowerButtonSleepKey);
            }
        }
    }

    /*
     * Allow Sleep
     *
     */
    if ( (msg & kIOPMAllowSleep) && !allowSleep ) 
    {
        allowSleep = true;
        adjustPowerState();
    }

    /*
     * Prevent Sleep
     *
     */
    if (msg & kIOPMPreventSleep) {
        allowSleep = false;
	    // are we dozing?
        if ( getPowerState() == DOZE_STATE ) {
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
        canSleep = true;
        platformSleepSupport = flags;
    }

    setProperty(kIOSleepSupportedKey, canSleep);

}

//*********************************************************************************
// requestPowerDomainState
//
// The root domain intercepts this call to the superclass.
// Called on the PM work loop thread.
//
// If the clamp bit is not set in the desire, then the child doesn't need the power
// state it's requesting; it just wants it.  The root ignores desires but not needs.
// If the clamp bit is not set, the root takes it that the child can tolerate no
// power and interprets the request accordingly.  If all children can thus tolerate
// no power, we are on our way to idle sleep.
//*********************************************************************************

IOReturn IOPMrootDomain::requestPowerDomainState (
    IOPMPowerFlags      desiredState,
    IOPowerConnection * whichChild,
    unsigned long       specification )
{
    OSIterator          *iter;
    OSObject            *next;
    IOPowerConnection   *connection;
    unsigned long       powerRequestFlag = 0;
    IOPMPowerFlags      editedDesire;

#if DEBUG
    IOService           *powerChild;
    powerChild = (IOService *) whichChild->getChildEntry(gIOPowerPlane);
#endif

    DEBUG_LOG("RequestPowerDomainState: flags %lx, child %p [%s], spec %lx\n",
        desiredState, powerChild, powerChild ? powerChild->getName() : "?",
        specification);
    
    // Force the child's input power requirements to 0 unless the prevent
    // idle-sleep flag is set. No input power flags map to our state 0.
    // Our power clamp (deviceDesire) keeps the minimum power state at 2.

    if (desiredState & kIOPMPreventIdleSleep)
        editedDesire = desiredState;
    else
        editedDesire = 0;

    // Recompute sleep supported flag (doze if not supported)
    sleepIsSupported = true;

    iter = getChildIterator(gIOPowerPlane);
    if ( iter ) 
    {
        while ( (next = iter->getNextObject()) ) 
        {
            if ( (connection = OSDynamicCast(IOPowerConnection, next)) ) 
            {
                // Ignore child that are in the process of joining.
				if (connection->getReadyFlag() == false)
					continue;

                // Is this connection attached to the child that called
                // requestPowerDomainState()?

                if ( connection == whichChild ) 
                {
                    // Yes, OR in the child's input power requirements.
                    powerRequestFlag |= editedDesire;

                    if ( desiredState & kIOPMPreventSystemSleep )
                        sleepIsSupported = false;
                }
                else
                {
#if DEBUG
                    powerChild = (IOService *) connection->getChildEntry(gIOPowerPlane);
#endif
                    DEBUG_LOG("  child %p, PState %ld, noIdle %d, noSleep %d, valid %d  %s\n",
                        powerChild,
                        connection->getDesiredDomainState(),
                        connection->getPreventIdleSleepFlag(),
                        connection->getPreventSystemSleepFlag(),
                        connection->getReadyFlag(),
                        powerChild ? powerChild->getName() : "?");

                    // No, OR in the child's desired power domain state.
                    // Which is our power state desired by this child.
                    powerRequestFlag |= connection->getDesiredDomainState();

                    if ( connection->getPreventSystemSleepFlag() )
                        sleepIsSupported = false;
                }
            }
        }
        iter->release();
    }
    
    if ( !powerRequestFlag && !systemBooting ) 
    {
	if (!wrangler)
	{
	    sleepASAP = false;
	    changePowerStateToPriv(ON_STATE);
	    if (idleSeconds)
	    {
		AbsoluteTime deadline;
		// stay awake for at least idleSeconds
		clock_interval_to_deadline(idleSeconds, kSecondScale, &deadline);	
		thread_call_enter_delayed(extraSleepTimer, deadline);
		// this gets turned off when we sleep again
		idleSleepPending = true;
	    }
	}
	else if (extraSleepDelay == 0)
	{
	    sleepASAP = true;
	}
    }
    
    DEBUG_LOG("  sleepDelay %lx, mergedFlags %lx, sleepASAP %x, booting %x\n",
        extraSleepDelay, powerRequestFlag, sleepASAP, systemBooting);

    // Drop our power clamp to SLEEP_STATE when all devices become idle.
    // Needed when the system sleep and display sleep timeouts are the same.
    // Otherwise, the extra sleep timer will also drop our power clamp.

    adjustPowerState();

    editedDesire |= (desiredState & kIOPMPreventSystemSleep);

    // If our power clamp has already dropped to SLEEP_STATE, and no child
    // is keeping us at max power, then this will trigger idle sleep.

    return super::requestPowerDomainState(editedDesire, whichChild, specification);
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
// handlePlatformHaltRestart
//
//*********************************************************************************

struct HaltRestartApplierContext {
	IOPMrootDomain *	RootDomain;
	unsigned long		PowerState;
	IOPMPowerFlags		PowerFlags;
	UInt32				MessageType;
	UInt32				Counter;
};

static void
platformHaltRestartApplier( OSObject * object, void * context )
{
	IOPowerStateChangeNotification	notify;
	HaltRestartApplierContext *		ctx;
	AbsoluteTime					startTime;
	UInt32							deltaTime;

	ctx = (HaltRestartApplierContext *) context;
	
	memset(&notify, 0, sizeof(notify));
    notify.powerRef    = (void *)ctx->Counter;
    notify.returnValue = 0;
    notify.stateNumber = ctx->PowerState;
    notify.stateFlags  = ctx->PowerFlags;

	clock_get_uptime(&startTime);
    ctx->RootDomain->messageClient( ctx->MessageType, object, (void *)&notify );
	deltaTime = computeDeltaTimeMS(&startTime);

	if ((deltaTime > kPMHaltTimeoutMS) || (gIOKitDebug & kIOLogDebugPower))
	{
		_IOServiceInterestNotifier * notifier;
		notifier = OSDynamicCast(_IOServiceInterestNotifier, object);

		// IOService children of IOPMrootDomain are not instrumented.
		// Only IORootParent currently falls under that group.

		if (notifier)
		{
			HaltRestartLog("%s handler %p took %lu ms\n",
				(ctx->MessageType == kIOMessageSystemWillPowerOff) ?
					"PowerOff" : "Restart",
				notifier->handler, deltaTime );
		}
	}

	ctx->Counter++;
}

void IOPMrootDomain::handlePlatformHaltRestart( UInt32 pe_type )
{
	HaltRestartApplierContext	ctx;
	AbsoluteTime				startTime;
	UInt32						deltaTime;

	memset(&ctx, 0, sizeof(ctx));
	ctx.RootDomain = this;

	clock_get_uptime(&startTime);
	switch (pe_type)
	{
		case kPEHaltCPU:
			ctx.PowerState  = OFF_STATE;
			ctx.MessageType = kIOMessageSystemWillPowerOff;
			break;
		
		case kPERestartCPU:
			ctx.PowerState  = RESTART_STATE;
			ctx.MessageType = kIOMessageSystemWillRestart;
			break;

		default:
			return;
	}

	// Notify legacy clients
	applyToInterested(gIOPriorityPowerStateInterest, platformHaltRestartApplier, &ctx);

	// Notify in power tree order
	notifySystemShutdown(this, ctx.MessageType);

	deltaTime = computeDeltaTimeMS(&startTime);
	HaltRestartLog("%s all drivers took %lu ms\n",
		(ctx.MessageType == kIOMessageSystemWillPowerOff) ?
			"PowerOff" : "Restart",
		deltaTime );
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
	
            // Direct callout into OSMetaClass so it can disable kmod unloads
            // during sleep/wake to prevent deadlocks.
            OSMetaClassSystemSleepOrWake( kIOMessageSystemWillSleep );

            return super::tellClientsWithResponse(kIOMessageSystemWillSleep);
    }
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
    if (idleSeconds && !wrangler)
    {
	AbsoluteTime deadline;
	sleepASAP = false;
	// stay awake for at least idleSeconds
	clock_interval_to_deadline(idleSeconds, kSecondScale, &deadline);	
	thread_call_enter_delayed(extraSleepTimer, deadline);
	// this gets turned off when we sleep again
	idleSleepPending = true;
    }
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
        // Direct callout into OSMetaClass so it can disable kmod unloads
        // during sleep/wake to prevent deadlocks.
        OSMetaClassSystemSleepOrWake( kIOMessageSystemHasPoweredOn );

	if (getPowerState() == ON_STATE)
	{
	    // this is a quick wake from aborted sleep
	    if (idleSeconds && !wrangler)
	    {
		AbsoluteTime deadline;
		sleepASAP = false;
		// stay awake for at least idleSeconds
		clock_interval_to_deadline(idleSeconds, kSecondScale, &deadline);	
		thread_call_enter_delayed(extraSleepTimer, deadline);
		// this gets turned off when we sleep again
		idleSleepPending = true;
	    }
	    tellClients(kIOMessageSystemWillPowerOn);
	}
#if	HIBERNATION
	else
	{
	    IOHibernateSystemPostWake();
	}
#endif
        return tellClients(kIOMessageSystemHasPoweredOn);
    }
}

//*********************************************************************************
// reportUserInput
//
//*********************************************************************************

void IOPMrootDomain::reportUserInput ( void )
{
#if !NO_KERNEL_HID
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
#endif
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
    IOReturn    ret;

    DEBUG_LOG("ChangePowerStateToPriv: power state %ld\n", ordinal);

	if ( (getPowerState() == DOZE_STATE) && (ordinal != ON_STATE) )
	{
		return kIOReturnSuccess;
	}

    if( (userDisabledAllSleep || systemBooting || systemShutdown) 
        && (ordinal == SLEEP_STATE) )
    {
        DEBUG_LOG("  sleep denied: disableAllSleep %d, booting %d, shutdown %d\n",
            userDisabledAllSleep, systemBooting, systemShutdown);
        super::changePowerStateToPriv(ON_STATE);
    }

    if( (SLEEP_STATE == ordinal) && sleepSupportedPEFunction )
    {

        // Determine if the machine supports sleep, or must doze.
        ret = getPlatform()->callPlatformFunction(
                            sleepSupportedPEFunction, false,
                            NULL, NULL, NULL, NULL);
    
        // If the machine only supports doze, the callPlatformFunction call
        // boils down to IOPMrootDomain::setSleepSupported(kPCICantSleep), 
        // otherwise nothing.
    }

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
            DEBUG_LOG("SystemWillSleep\n");

            // Interested applications have been notified of an impending power
            // change and have acked (when applicable).
            // This is our chance to save whatever state we can before powering
            // down.
            // We call sync_internal defined in xnu/bsd/vfs/vfs_syscalls.c,
            // via callout

            // We will ack within 20 seconds
            params->returnValue = 20 * 1000 * 1000;
#if	HIBERNATION
            if (gIOHibernateState)
                params->returnValue += gIOHibernateFreeTime * 1000; 	//add in time we could spend freeing pages
#endif

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
// When the display sleeps we:
// - Start the idle sleep timer
// - set the quick spin down timeout
//
// On wake from display sleep:
// - Cancel the idle sleep timer
// - restore the user's chosen spindown timer from the "quick" spin down value
//*********************************************************************************

IOReturn IOPMrootDomain::displayWranglerNotification(
    void * target, void * refCon,
    UInt32 messageType, IOService * service,
    void * messageArgument, vm_size_t argSize )
{
#if !NO_KERNEL_HID
    IOPMrootDomain *    rootDomain = OSDynamicCast(IOPMrootDomain, (IOService *)target);
    AbsoluteTime        deadline;
    static int          displayPowerState = 4;

    if (!rootDomain)
        return kIOReturnUnsupported;

    switch (messageType) {
       case kIOMessageDeviceWillPowerOff:
            DEBUG_LOG("DisplayWranglerWillPowerOff: new p-state %d\n",
                displayPowerState - 1);

            // The display wrangler has dropped power because of idle display sleep
            // or force system sleep. We will receive 4 messages before the display
            // wrangler reaches its lowest state. Act only when going to state 2.
            //
            // 4->3 Display Dim
            // 3->2 Display Sleep
            // 2->1 Not visible to user
            // 1->0 Not visible to user

            displayPowerState--;
            if ( 2 != displayPowerState )
                return kIOReturnUnsupported;

            // We start a timer here if the System Sleep timer is greater than the
            // Display Sleep timer. We kick off this timer when the display sleeps.
            //
            // Note that, although Display Dim timings may change adaptively accordingly
            // to the user's activity patterns, Display Sleep _always_ occurs at the
            // specified interval since last user activity.

            if ( rootDomain->extraSleepDelay )
            {
                clock_interval_to_deadline(rootDomain->extraSleepDelay*60, kSecondScale, &deadline);
                thread_call_enter_delayed(rootDomain->extraSleepTimer, deadline);
                rootDomain->idleSleepPending = true;
                DEBUG_LOG("  sleep timer set to expire in %ld min\n",
                    rootDomain->extraSleepDelay);
            } else {
                // Accelerate disk spindown if system sleep and display sleep
                // sliders are set to the same value (e.g. both set to 5 min),
                // and display is about to go dark. Check that spin down timer
                // is non-zero (zero = never spin down) and system sleep is
                // not set to never sleep.

                if ( (0 != rootDomain->user_spindown) && (0 != rootDomain->sleepSlider) )
                {
                    DEBUG_LOG("  accelerate quick disk spindown, was %d min\n",
                        rootDomain->user_spindown);
                    rootDomain->setQuickSpinDownTimeout();
                }
            }

            break;

        case kIOMessageDeviceHasPoweredOn:
            DEBUG_LOG("DisplayWranglerHasPoweredOn: previous p-state %d\n",
                displayPowerState);

            // The display wrangler has powered on either because of user activity 
            // or wake from sleep/doze.

            displayPowerState = 4;
            rootDomain->adjustPowerState();

            // cancel any pending idle sleep timers
            if (rootDomain->idleSleepPending) 
            {
                DEBUG_LOG("  extra-sleep timer stopped\n");
                thread_call_cancel(rootDomain->extraSleepTimer);
                rootDomain->idleSleepPending = false;
            }

            // Change the spindown value back to the user's selection from our
            // accelerated setting.
            if (0 != rootDomain->user_spindown)
            {
                DEBUG_LOG("  restoring disk spindown to %d min\n",
                    rootDomain->user_spindown);
                rootDomain->restoreUserSpinDownTimeout();
            }

            break;

         default:
             break;
     }
#endif
     return kIOReturnUnsupported;
 }

//*********************************************************************************
// displayWranglerPublished
//
// Receives a notification when the IODisplayWrangler is published.
// When it's published we install a power state change handler.
//
//*********************************************************************************

bool IOPMrootDomain::displayWranglerPublished( 
    void * target, 
    void * refCon,
    IOService * newService)
{
#if !NO_KERNEL_HID
    IOPMrootDomain *rootDomain = 
            OSDynamicCast(IOPMrootDomain, (IOService *)target);

    if(!rootDomain)
        return false;

    rootDomain->wrangler = newService;
    
    // we found the display wrangler, now install a handler
    if( !rootDomain->wrangler->registerInterest( gIOGeneralInterest, 
                            &displayWranglerNotification, target, 0) ) 
    {
        return false;
    }
#endif
    return true;
}

//*********************************************************************************
// batteryPublished
//
// Notification on battery class IOPowerSource appearance
//
//******************************************************************************

bool IOPMrootDomain::batteryPublished( 
    void * target, 
    void * root_domain,
    IOService * resourceService )
{    
    // rdar://2936060&4435589    
    // All laptops have dimmable LCD displays
    // All laptops have batteries
    // So if this machine has a battery, publish the fact that the backlight
    // supports dimming.
    ((IOPMrootDomain *)root_domain)->publishFeature("DisplayDims");

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
    if ( (sleepSlider == 0) 
        || !allowSleep 
        || systemBooting 
        || systemShutdown
        || userDisabledAllSleep )
    {
        DEBUG_LOG("AdjustPowerState %ld -> ON: slider %ld, allowSleep %d, "
            "booting %d, shutdown %d, userDisabled %d\n",
            getPowerState(), sleepSlider, allowSleep, systemBooting,
            systemShutdown, userDisabledAllSleep);

        changePowerStateToPriv(ON_STATE);
    } else {
        if ( sleepASAP ) 
        {
            DEBUG_LOG("AdjustPowerState SLEEP\n");

            /* Convenient place to run any code at idle sleep time
             * IOPMrootDomain initiates an  idle sleep here
             *
             * Set last sleep cause accordingly.
             */
            setProperty(kRootDomainSleepReasonKey, kIOPMIdleSleepKey);
        
            sleepASAP = false;
            if ( !sleepIsSupported ) 
            {
                setSleepSupported( kPCICantSleep );
                kprintf("Sleep prevented by kIOPMPreventSystemSleep flag\n");
            }
            changePowerStateToPriv(SLEEP_STATE);
        }
    }
}

//*********************************************************************************
// PMHaltWorker Class
//
//*********************************************************************************

static unsigned int		gPMHaltBusyCount;
static unsigned int		gPMHaltIdleCount;
static int				gPMHaltDepth;
static unsigned long    gPMHaltEvent;
static IOLock *			gPMHaltLock  = 0;
static OSArray *		gPMHaltArray = 0;
static const OSSymbol * gPMHaltClientAcknowledgeKey = 0;

PMHaltWorker * PMHaltWorker::worker( void )
{
	PMHaltWorker *	me;
	IOThread		thread;

	do {
		me = OSTypeAlloc( PMHaltWorker );
		if (!me || !me->init())
			break;

		me->lock = IOLockAlloc();
		if (!me->lock)
			break;

		DEBUG_LOG("PMHaltWorker %p\n", me);
		me->retain();	// thread holds extra retain
		thread = IOCreateThread( &PMHaltWorker::main, me );
		if (!thread)
		{
			me->release();
			break;
		}
		return me;

	} while (false);

	if (me) me->release();
	return 0;
}

void PMHaltWorker::free( void )
{
	DEBUG_LOG("PMHaltWorker free %p\n", this);
	if (lock)
	{
		IOLockFree(lock);
		lock = 0;
	}
	return OSObject::free();
}

void PMHaltWorker::main( void * arg )
{
	PMHaltWorker * me = (PMHaltWorker *) arg;

	IOLockLock( gPMHaltLock );
	gPMHaltBusyCount++;
	me->depth = gPMHaltDepth;
	IOLockUnlock( gPMHaltLock );

	while (me->depth >= 0)
	{
		PMHaltWorker::work( me );

		IOLockLock( gPMHaltLock );
		if (++gPMHaltIdleCount >= gPMHaltBusyCount)
		{
			// This is the last thread to finish work on this level,
			// inform everyone to start working on next lower level.
			gPMHaltDepth--;
			me->depth = gPMHaltDepth;
			gPMHaltIdleCount = 0;
			thread_wakeup((event_t) &gPMHaltIdleCount);
		}
		else
		{
			// One or more threads are still working on this level,
			// this thread must wait.
			me->depth = gPMHaltDepth - 1;
			do {
				IOLockSleep(gPMHaltLock, &gPMHaltIdleCount, THREAD_UNINT);
			} while (me->depth != gPMHaltDepth);
		}
		IOLockUnlock( gPMHaltLock );
	}

	// No more work to do, terminate thread
	DEBUG_LOG("All done for worker: %p (visits = %u)\n", me, me->visits);
	thread_wakeup( &gPMHaltDepth );
	me->release();
}

void PMHaltWorker::work( PMHaltWorker * me )
{
	IOService *		service;
	OSSet *			inner;
	AbsoluteTime	startTime;
	UInt32			deltaTime;
	bool			timeout;

	while (true)
	{
		service = 0;
		timeout = false;

		// Claim an unit of work from the shared pool
		IOLockLock( gPMHaltLock );
		inner = (OSSet *)gPMHaltArray->getObject(me->depth);
		if (inner)
		{
			service = (IOService *)inner->getAnyObject();
			if (service)
			{
				service->retain();
				inner->removeObject(service);
			}
		}
		IOLockUnlock( gPMHaltLock );	
		if (!service)
			break;  // no more work at this depth

		clock_get_uptime(&startTime);

		if (!service->isInactive() &&
			service->setProperty(gPMHaltClientAcknowledgeKey, me))
		{
			IOLockLock(me->lock);
			me->startTime = startTime;
			me->service   = service;
			me->timeout   = false;
			IOLockUnlock(me->lock);

			service->systemWillShutdown( gPMHaltEvent );

			// Wait for driver acknowledgement
			IOLockLock(me->lock);
			while (service->getProperty(gPMHaltClientAcknowledgeKey))
			{
				IOLockSleep(me->lock, me, THREAD_UNINT);			
			}
			me->service = 0;
			timeout = me->timeout;
			IOLockUnlock(me->lock);
		}

		deltaTime = computeDeltaTimeMS(&startTime);
		if ((deltaTime > kPMHaltTimeoutMS) || timeout ||
			(gIOKitDebug & kIOLogDebugPower))
		{
			HaltRestartLog("%s driver %s (%p) took %lu ms\n",
				(gPMHaltEvent == kIOMessageSystemWillPowerOff) ?
					"PowerOff" : "Restart",
				service->getName(), service,
				deltaTime );
		}

		service->release();
		me->visits++;
	}
}

void PMHaltWorker::checkTimeout( PMHaltWorker * me, AbsoluteTime * now )
{
	UInt64			nano;
	AbsoluteTime	startTime;
	AbsoluteTime	endTime;

	endTime = *now;

	IOLockLock(me->lock);
	if (me->service && !me->timeout)
	{
		startTime = me->startTime;
		nano = 0;
	    if (CMP_ABSOLUTETIME(&endTime, &startTime) > 0)
	    {
			SUB_ABSOLUTETIME(&endTime, &startTime);
			absolutetime_to_nanoseconds(endTime, &nano);
	    }
		if (nano > 3000000000ULL)
		{
			me->timeout = true;
			HaltRestartLog("%s still waiting on %s\n",
				(gPMHaltEvent == kIOMessageSystemWillPowerOff) ?
					"PowerOff" : "Restart",
				me->service->getName());
		}
	}
	IOLockUnlock(me->lock);
}

//*********************************************************************************
// acknowledgeSystemWillShutdown
//
// Acknowledgement from drivers that they have prepared for shutdown/restart.
//*********************************************************************************

void IOPMrootDomain::acknowledgeSystemWillShutdown( IOService * from )
{
	PMHaltWorker *	worker;
	OSObject *		prop;

	if (!from)
		return;

	//DEBUG_LOG("%s acknowledged\n", from->getName());
	prop = from->copyProperty( gPMHaltClientAcknowledgeKey );
	if (prop)
	{
		worker = (PMHaltWorker *) prop;
		IOLockLock(worker->lock);
		from->removeProperty( gPMHaltClientAcknowledgeKey );
		thread_wakeup((event_t) worker);
		IOLockUnlock(worker->lock);
		worker->release();
	}
	else
	{
		DEBUG_LOG("%s acknowledged without worker property\n",
			from->getName());
	}
}

//*********************************************************************************
// notifySystemShutdown
//
// Notify all objects in PM tree that system will shutdown or restart
//*********************************************************************************

static void
notifySystemShutdown( IOService * root, unsigned long event )
{
#define PLACEHOLDER ((OSSet *)gPMHaltArray)
	IORegistryIterator *	iter;
	IORegistryEntry *		entry;
	IOService *				node;
	OSSet *					inner;
	PMHaltWorker *			workers[kPMHaltMaxWorkers];
	AbsoluteTime			deadline;
	unsigned int			totalNodes = 0;
	unsigned int			depth;
	unsigned int			rootDepth;
	unsigned int			numWorkers;
	unsigned int			count;
	int						waitResult;
	void *					baseFunc;
	bool					ok;

	DEBUG_LOG("%s event = %lx\n", __FUNCTION__, event);

	baseFunc = OSMemberFunctionCast(void *, root, &IOService::systemWillShutdown);

	// Iterate the entire PM tree starting from root

	rootDepth = root->getDepth( gIOPowerPlane );
	if (!rootDepth) goto done;

	// debug - for repeated test runs
	while (PMHaltWorker::metaClass->getInstanceCount())
		IOSleep(1);

	if (!gPMHaltArray)
	{
		gPMHaltArray = OSArray::withCapacity(40);
		if (!gPMHaltArray) goto done;
	}
	else // debug
		gPMHaltArray->flushCollection();

	if (!gPMHaltLock)
	{
		gPMHaltLock = IOLockAlloc();
		if (!gPMHaltLock) goto done;
	}

	if (!gPMHaltClientAcknowledgeKey)
	{
		gPMHaltClientAcknowledgeKey =
			OSSymbol::withCStringNoCopy("PMShutdown");
		if (!gPMHaltClientAcknowledgeKey) goto done;
	}

	gPMHaltEvent = event;

	// Depth-first walk of PM plane

	iter = IORegistryIterator::iterateOver(
		root, gIOPowerPlane, kIORegistryIterateRecursively);

	if (iter)
	{
		while ((entry = iter->getNextObject()))
		{
			node = OSDynamicCast(IOService, entry);
			if (!node)
				continue;

			if (baseFunc == 
				OSMemberFunctionCast(void *, node, &IOService::systemWillShutdown))
				continue;

			depth = node->getDepth( gIOPowerPlane );
			if (depth <= rootDepth)
				continue;

			ok = false;

			// adjust to zero based depth
			depth -= (rootDepth + 1);

			// gPMHaltArray is an array of containers, each container
			// refers to nodes with the same depth.

			count = gPMHaltArray->getCount();
			while (depth >= count)
			{
				// expand array and insert placeholders
				gPMHaltArray->setObject(PLACEHOLDER);
				count++;
			}
			count = gPMHaltArray->getCount();
			if (depth < count)
			{
				inner = (OSSet *)gPMHaltArray->getObject(depth);
				if (inner == PLACEHOLDER)
				{
					inner = OSSet::withCapacity(40);
					if (inner)
					{
						gPMHaltArray->replaceObject(depth, inner);
						inner->release();
					}
				}

				// PM nodes that appear more than once in the tree will have
				// the same depth, OSSet will refuse to add the node twice.
				if (inner)
					ok = inner->setObject(node);
			}
			if (!ok)
				DEBUG_LOG("Skipped PM node %s\n", node->getName());
		}
		iter->release();
	}

	// debug only
	for (int i = 0; (inner = (OSSet *)gPMHaltArray->getObject(i)); i++)
	{
		count = 0;
		if (inner != PLACEHOLDER)
			count = inner->getCount();
		DEBUG_LOG("Nodes at depth %u = %u\n", i, count);
	}

	// strip placeholders (not all depths are populated)
	numWorkers = 0;
	for (int i = 0; (inner = (OSSet *)gPMHaltArray->getObject(i)); )
	{
		if (inner == PLACEHOLDER)
		{
			gPMHaltArray->removeObject(i);
			continue;
		}
		count = inner->getCount();
		if (count > numWorkers)
			numWorkers = count;
		totalNodes += count;
		i++;
	}

	if (gPMHaltArray->getCount() == 0 || !numWorkers)
		goto done;

	gPMHaltBusyCount = 0;
	gPMHaltIdleCount = 0;
	gPMHaltDepth = gPMHaltArray->getCount() - 1;

	// Create multiple workers (and threads)

	if (numWorkers > kPMHaltMaxWorkers)
		numWorkers = kPMHaltMaxWorkers;

	DEBUG_LOG("PM nodes = %u, maxDepth = %u, workers = %u\n",
		totalNodes, gPMHaltArray->getCount(), numWorkers);

	for (unsigned int i = 0; i < numWorkers; i++)
		workers[i] = PMHaltWorker::worker();

	// Wait for workers to exhaust all available work

	IOLockLock(gPMHaltLock);
	while (gPMHaltDepth >= 0)
	{
		clock_interval_to_deadline(1000, kMillisecondScale, &deadline);

		waitResult = IOLockSleepDeadline(
			gPMHaltLock, &gPMHaltDepth, deadline, THREAD_UNINT);
		if (THREAD_TIMED_OUT == waitResult)
		{
			AbsoluteTime now;
			clock_get_uptime(&now);

			IOLockUnlock(gPMHaltLock);
			for (unsigned int i = 0 ; i < numWorkers; i++)
			{
				if (workers[i])
					PMHaltWorker::checkTimeout(workers[i], &now);
			}
			IOLockLock(gPMHaltLock);
		}
	}
	IOLockUnlock(gPMHaltLock);

	// Release all workers

	for (unsigned int i = 0; i < numWorkers; i++)
	{
		if (workers[i])
			workers[i]->release();
		// worker also retained by it's own thread
	}

done:
	DEBUG_LOG("%s done\n", __FUNCTION__);
	return;
}

#if DEBUG_TEST
// debug - exercise notifySystemShutdown()
bool IOPMrootDomain::serializeProperties( OSSerialize * s ) const
{
	IOPMrootDomain * root = (IOPMrootDomain *) this;
	notifySystemShutdown( root, kIOMessageSystemWillPowerOff );
    return( super::serializeProperties(s) );
}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



#undef super
#define super OSObject
OSDefineMetaClassAndStructors(PMSettingObject, OSObject)

void PMSettingObject::setPMSetting(const OSSymbol *type, OSObject *obj)
{
        (*func)(target, type, obj, refcon);
}

/* 
 * Static constructor/initializer for PMSettingObject
 */
PMSettingObject *PMSettingObject::pmSettingObject(
    IOPMrootDomain                      *parent_arg,
    IOPMSettingControllerCallback       handler_arg,
    OSObject                            *target_arg,
    uintptr_t                           refcon_arg,
    uint32_t                            supportedPowerSources,
    const OSSymbol *                    settings[])
{
    uint32_t                            objCount = 0;
    PMSettingObject                     *pmso;

    if( !parent_arg || !handler_arg || !settings ) return NULL;

     // count OSSymbol entries in NULL terminated settings array
    while( settings[objCount] ) {
        objCount++;
    }
    if(0 == objCount) return NULL;

    pmso = new PMSettingObject;
    if(!pmso || !pmso->init()) return NULL;

    pmso->parent = parent_arg;
    pmso->func = handler_arg;
    pmso->target = target_arg;
    pmso->refcon = refcon_arg;
    pmso->releaseAtCount = objCount + 1; // release when it has count+1 retains
 
    pmso->publishedFeatureID = (uint32_t *)IOMalloc(sizeof(uint32_t)*objCount);
    if(pmso->publishedFeatureID) {
        for(unsigned int i=0; i<objCount; i++) {
            // Since there is now at least one listener to this setting, publish
            // PM root domain support for it.
            parent_arg->publishFeature( settings[i]->getCStringNoCopy(), 
                    supportedPowerSources, &pmso->publishedFeatureID[i] );
        }
    }
    
    return pmso;
}

void PMSettingObject::free(void)
{
    OSCollectionIterator    *settings_iter;
    OSSymbol                *sym;
    OSArray                 *arr;
    int                     arr_idx;
    int                     i;
    int                     objCount = releaseAtCount - 1;
    
    if(publishedFeatureID) {
        for(i=0; i<objCount; i++) {
            if(0 != publishedFeatureID[i]) {
                parent->removePublishedFeature( publishedFeatureID[i] );
            }
        }
    
        IOFree(publishedFeatureID, sizeof(uint32_t) * objCount);
    }
            
    IORecursiveLockLock(parent->settingsCtrlLock);        
    
    // Search each PM settings array in the kernel.
    settings_iter = OSCollectionIterator::withCollection(parent->settingsCallbacks);
    if(settings_iter) 
    {
        while(( sym = OSDynamicCast(OSSymbol, settings_iter->getNextObject()) ))
        {
            arr = (OSArray *)parent->settingsCallbacks->getObject(sym);
            arr_idx = arr->getNextIndexOfObject(this, 0);
            if(-1 != arr_idx) {
                // 'this' was found in the array; remove it                
                arr->removeObject(arr_idx);
            }
        }
    
        settings_iter->release();
    }
    
    IORecursiveLockUnlock(parent->settingsCtrlLock);
    
    super::free();
}

void PMSettingObject::taggedRelease(const void *tag, const int when) const
{     
    // We have n+1 retains - 1 per array that this PMSettingObject is a member
    // of, and 1 retain to ourself. When we get a release with n+1 retains
    // remaining, we go ahead and free ourselves, cleaning up array pointers
    // in free();

    super::taggedRelease(tag, releaseAtCount);    
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
	youAreRoot();
    registerPowerDriver(this,patriarchPowerStates,number_of_power_states);
	wakeSystem();
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

IOReturn IORootParent::changePowerStateToPriv ( unsigned long ordinal )
{
    IOReturn        ret;

    if( (SLEEP_STATE == ordinal) && sleepSupportedPEFunction )
    {

        // Determine if the machine supports sleep, or must doze.
        ret = getPlatform()->callPlatformFunction(
                            sleepSupportedPEFunction, false,
                            NULL, NULL, NULL, NULL);
    
        // If the machine only supports doze, the callPlatformFunction call
        // boils down toIOPMrootDomain::setSleepSupported(kPCICantSleep), 
        // otherwise nothing.
    }

    return super::changePowerStateToPriv(ordinal);
}

