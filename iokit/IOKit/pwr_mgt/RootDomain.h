/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#ifndef _IOKIT_ROOTDOMAIN_H
#define _IOKIT_ROOTDOMAIN_H

#include <IOKit/IOService.h>
#include <IOKit/pwr_mgt/IOPM.h>

class IOPMPowerStateQueue;
class RootDomainUserClient;

enum {
    kRootDomainSleepNotSupported	= 0x00000000,
    kRootDomainSleepSupported 		= 0x00000001,
    kFrameBufferDeepSleepSupported	= 0x00000002,
    kPCICantSleep			= 0x00000004
};

/* 
 *IOPMrootDomain registry property keys
 */
#define kRootDomainSupportedFeatures        "Supported Features"
#define kRootDomainSleepReasonKey           "Last Sleep Reason"
#define kRootDomainSleepOptionsKey          "Last Sleep Options"

/*
 * Possible sleep reasons found under kRootDomainSleepReasonsKey
 */
#define kIOPMClamshellSleepKey              "Clamshell Sleep"
#define kIOPMPowerButtonSleepKey            "Power Button Sleep"
#define kIOPMSoftwareSleepKey               "Software Sleep"
#define kIOPMOSSwitchHibernationKey         "OS Switch Sleep"
#define kIOPMIdleSleepKey                   "Idle Sleep"
#define kIOPMLowPowerSleepKey               "Low Power Sleep"
#define kIOPMThermalEmergencySleepKey       "Thermal Emergency Sleep"

/*
 * String constants for communication with PM CPU
 */
#define kIOPMRootDomainLidCloseCString      "LidClose"
#define kIOPMRootDomainBatPowerCString      "BatPower"

// Supported Feature bitfields for IOPMrootDomain::publishFeature()
enum {
    kIOPMSupportedOnAC = 1<<0,
    kIOPMSupportedOnBatt = 1<<1,
    kIOPMSupportedOnUPS = 1<<2
};

typedef IOReturn (*IOPMSettingControllerCallback) \
                    (OSObject *target, const OSSymbol *type, \
                     OSObject *val, uintptr_t refcon);

extern "C"
{
    IONotifier * registerSleepWakeInterest(
               IOServiceInterestHandler, void *, void * = 0);
               
    IONotifier * registerPrioritySleepWakeInterest(
                IOServiceInterestHandler handler, 
                void * self, void * ref = 0);

    IOReturn acknowledgeSleepWakeNotification(void * );

    IOReturn vetoSleepWakeNotification(void * PMrefcon);

    IOReturn rootDomainRestart ( void );

    IOReturn rootDomainShutdown ( void );
}

#define IOPM_ROOTDOMAIN_REV		2

class IOPMrootDomain: public IOService
{
OSDeclareDefaultStructors(IOPMrootDomain)
    
public:

    class IOService * wrangler;			// we tickle the wrangler on button presses, etc

    static IOPMrootDomain * construct( void );
    virtual bool start( IOService * provider );
    virtual IOReturn setAggressiveness ( unsigned long, unsigned long );
    virtual IOReturn youAreRoot ( void );

    virtual IOReturn sleepSystem ( void );
    IOReturn sleepSystemOptions ( OSDictionary *options );

    virtual IOReturn setProperties ( OSObject * );
    IOReturn shutdownSystem ( void );
    IOReturn restartSystem ( void );
    virtual IOReturn receivePowerNotification (UInt32 msg);
    virtual void setSleepSupported( IOOptionBits flags );
    virtual IOOptionBits getSleepSupported();
    virtual IOReturn requestPowerDomainState ( IOPMPowerFlags, IOPowerConnection *, unsigned long );
    virtual void handleSleepTimerExpiration ( void );
    void stopIgnoringClamshellEventsDuringWakeup ( void );
    void wakeFromDoze( void );
    void broadcast_it (unsigned long, unsigned long );

    // KEXT driver announces support of power management feature
    void publishFeature( const char *feature );
    
    // KEXT driver announces support of power management feature
    // And specifies power sources with kIOPMSupportedOn{AC/Batt/UPS} bitfield.
    // Returns a unique uint32_t identifier for later removing support for this
    // feature. 
    // NULL is acceptable for uniqueFeatureID for kexts without plans to unload.
    void publishFeature( const char *feature, 
                            uint32_t supportedWhere,
                            uint32_t *uniqueFeatureID);

    // KEXT driver announces removal of a previously published power management 
    // feature. Pass 'uniqueFeatureID' returned from publishFeature()
    IOReturn removePublishedFeature( uint32_t removeFeatureID );

    void unIdleDevice( IOService *, unsigned long );
    void announcePowerSourceChange( void );

    // Override of these methods for logging purposes.
    virtual IOReturn changePowerStateTo ( unsigned long ordinal );
    virtual IOReturn changePowerStateToPriv ( unsigned long ordinal );

/*! @function copyPMSetting
    @abstract Copy the current value for a PM setting. Returns OSNumber or
        OSData depending on the setting.
    @param whichSetting Name of the desired setting. 
    @result OSObject *value if valid, NULL otherwise. */
    OSObject *copyPMSetting(OSSymbol *whichSetting);
    
/*! @function registerPMSettingController
    @abstract Register for callbacks on changes to certain PM settings.
    @param settings NULL terminated array of C strings, each string for a PM 
        setting that the caller is interested in and wants to get callbacks for. 
    @param callout C function ptr or member function cast as such.
    @param target The target of the callback, usually 'this'
    @param refcon Will be passed to caller in callback; for caller's use.
    @param handle Caller should keep the OSObject * returned here. If non-NULL,
        handle will have a retain count of 1 on return. To deregister, pass to
        unregisterPMSettingController()
    @result kIOReturnSuccess on success. */
    IOReturn registerPMSettingController(
                                 const OSSymbol *settings[],
                                 IOPMSettingControllerCallback callout,
                                 OSObject   *target,
                                 uintptr_t  refcon,
                                 OSObject   **handle);    // out param

/*! @function registerPMSettingController
    @abstract Register for callbacks on changes to certain PM settings.
    @param settings NULL terminated array of C strings, each string for a PM 
        setting that the caller is interested in and wants to get callbacks for. 
    @param supportedPowerSources bitfield indicating which power sources these
        settings are supported for (kIOPMSupportedOnAC, etc.)
    @param callout C function ptr or member function cast as such.
    @param target The target of the callback, usually 'this'
    @param refcon Will be passed to caller in callback; for caller's use.
    @param handle Caller should keep the OSObject * returned here. If non-NULL,
        handle will have a retain count of 1 on return. To deregister, pass to
        unregisterPMSettingController()
    @result kIOReturnSuccess on success. */
    IOReturn registerPMSettingController(
                                 const OSSymbol *settings[],
                                 uint32_t   supportedPowerSources,
                                 IOPMSettingControllerCallback callout,
                                 OSObject   *target,
                                 uintptr_t  refcon,
                                 OSObject   **handle);    // out param

/*! @function acknowledgeSystemWillShutdown
    @abstract Handle callbacks from IOService::systemWillShutdown().
    @param The IOService sender of the callback. */
	void acknowledgeSystemWillShutdown( IOService * from );

/*! @function handlePlatformHaltRestart
    @abstract Handle platform halt and restart notifications.
    @param kPEHaltCPU or kPERestartCPU. */
	void handlePlatformHaltRestart( UInt32 pe_type );

private:

    // Points to our parent
    class IORootParent * patriarch;

    // Pref: idle time before idle sleep
    long		sleepSlider;		
    long		idleSeconds;
    uint64_t		autoWakeStart;
    uint64_t		autoWakeEnd;

    // Pref: longest of other idle times (disk and display)
    long		longestNonSleepSlider;

    // Difference between sleepSlider and longestNonSleepSlider
    long		extraSleepDelay;		

    // Used to wait between say display idle and system idle
    thread_call_t	extraSleepTimer;		

    // Used to ignore clamshell close events while we're waking from sleep
    thread_call_t   clamshellWakeupIgnore;   
    
	// IOPMrootDomain internal sleep call
    IOReturn 	privateSleepSystem ( const char *sleepReason );

    
    virtual void powerChangeDone ( unsigned long );
    virtual void command_received ( void *, void * , void * , void *);
    virtual bool tellChangeDown ( unsigned long stateNum);
    virtual bool askChangeDown ( unsigned long stateNum);
    virtual void tellChangeUp ( unsigned long );
    virtual void tellNoChangeDown ( unsigned long );
    void reportUserInput ( void );
    static IOReturn sysPowerDownHandler( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize );

    static IOReturn displayWranglerNotification( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize );

    static bool displayWranglerPublished( void * target, void * refCon,
                                    IOService * newService);

    static bool batteryPublished( void * target, void * refCon,
                                    IOService * resourceService );

    void adjustPowerState ( void );
    void setQuickSpinDownTimeout ( void );
    void restoreUserSpinDownTimeout ( void );
    
    bool shouldSleepOnClamshellClosed (void );
    void sendClientClamshellNotification ( void );
    
    // Inform PMCPU of changes to state like lid, AC vs. battery
    void informCPUStateChange( uint32_t type, uint32_t value );
        
    IOLock                  *featuresDictLock;  // guards supportedFeatures
    IOPMPowerStateQueue     *pmPowerStateQueue;
    unsigned int user_spindown;       // User's selected disk spindown value

    unsigned int systemBooting:1;
    unsigned int systemShutdown:1;
    unsigned int ignoringClamshell:1;
    unsigned int allowSleep:1;
    unsigned int sleepIsSupported:1;
    unsigned int canSleep:1;
    unsigned int idleSleepPending:1;
    unsigned int sleepASAP:1;
    unsigned int desktopMode:1;
    unsigned int userDisabledAllSleep:1;

    unsigned int acAdaptorConnect:1;
    unsigned int ignoringClamshellDuringWakeup:1;
    unsigned int clamshellIsClosed:1;
    unsigned int clamshellExists:1;
    
    OSArray         *allowedPMSettings;
    
    // Settings controller info
    IORecursiveLock        *settingsCtrlLock;  
    OSDictionary           *settingsCallbacks;
    OSDictionary           *fPMSettingsDict;
    IOReturn setPMSetting(const OSSymbol *, OSObject *);

    thread_call_t           diskSyncCalloutEntry;
    IONotifier              *_batteryPublishNotifier;
    IONotifier              *_displayWranglerNotifier;

    // Info for communicating system state changes to PMCPU
    int32_t                idxPMCPUClamshell;
    int32_t                idxPMCPULimitedPower;

    struct ExpansionData {    
    };
    ExpansionData   *_reserved;
    IOOptionBits platformSleepSupport;
    
    friend class PMSettingObject;
};

class IORootParent: public IOService
{
OSDeclareDefaultStructors(IORootParent)

private:
    unsigned long mostRecentChange;
    
public:

    virtual IOReturn changePowerStateToPriv ( unsigned long ordinal );

    bool start ( IOService * nub );
    void shutDownSystem ( void );
    void restartSystem ( void );
    void sleepSystem ( void );
    void dozeSystem ( void );
    void sleepToDoze ( void );
    void wakeSystem ( void );
};


#endif /*  _IOKIT_ROOTDOMAIN_H */
