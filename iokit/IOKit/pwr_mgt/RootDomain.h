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
#ifndef _IOKIT_ROOTDOMAIN_H
#define _IOKIT_ROOTDOMAIN_H

#include <IOKit/IOService.h>
#include <IOKit/pwr_mgt/IOPM.h>

class IOPMPowerStateQueue;
class RootDomainUserClient;

#define kRootDomainSupportedFeatures "Supported Features"

enum {
    kRootDomainSleepNotSupported	= 0x00000000,
    kRootDomainSleepSupported 		= 0x00000001,
    kFrameBufferDeepSleepSupported	= 0x00000002,
    kPCICantSleep			= 0x00000004
};

// Constants for use as arguments to registerPMSettingsController
enum {
    kIOPMAutoWakeSetting = 1,
    kIOPMAutoPowerOnSetting,
    kIOPMWakeOnRingSetting,
    kIOPMAutoRestartOnPowerLossSetting,
    kIOPMWakeOnLidSetting,
    kIOPMWakeOnACChangeSetting
};
typedef int IOPMSystemSettingType;



typedef IOReturn (*IOPMSettingControllerCallback)(IOPMSystemSettingType arg_type, int arg_val, void *info);

extern "C"
{
	IONotifier * registerSleepWakeInterest(IOServiceInterestHandler, void *, void * = 0);
        IONotifier * registerPrioritySleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref = 0);
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
    void publishFeature( const char *feature );
    void unIdleDevice( IOService *, unsigned long );
    void announcePowerSourceChange( void );
        
    // Override of these methods for logging purposes.
    virtual IOReturn changePowerStateTo ( unsigned long ordinal );
    virtual IOReturn changePowerStateToPriv ( unsigned long ordinal );

    IOReturn registerPMSettingController(IOPMSettingControllerCallback, void *);
    IOReturn registerPlatformPowerProfiles(OSArray *);

private:

    class IORootParent * patriarch;			// points to our parent
    long		sleepSlider;			// pref: idle time before idle sleep
    long		longestNonSleepSlider;		// pref: longest of other idle times
    long		extraSleepDelay;		// sleepSlider - longestNonSleepSlider
    thread_call_t	extraSleepTimer;		// used to wait between say display idle and system idle
    thread_call_t   clamshellWakeupIgnore;   // Used to ignore clamshell close events while we're waking from sleep
    
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

    static bool batteryLocationPublished( void * target, void * refCon,
                                    IOService * resourceService );

    void setQuickSpinDownTimeout ( void );
    void adjustPowerState( void );
    void restoreUserSpinDownTimeout ( void );

    IOPMPowerStateQueue     *pmPowerStateQueue;
    unsigned int user_spindown;       // User's selected disk spindown value

    unsigned int systemBooting:1;
    unsigned int ignoringClamshell:1;
    unsigned int allowSleep:1;
    unsigned int sleepIsSupported:1;
    unsigned int canSleep:1;
    unsigned int idleSleepPending:1;
    unsigned int sleepASAP:1;
    unsigned int desktopMode:1;

    unsigned int acAdaptorConnect:1;
    unsigned int ignoringClamshellDuringWakeup:1;
    unsigned int reservedA:6;
    unsigned char reservedB[3];
    
    struct PMSettingCtrl {
        IOPMSettingControllerCallback       func;
        void                                *refcon;
    };

    // Private helper to call PM setting controller
    IOReturn setPMSetting(int type, OSNumber *);
 
    struct ExpansionData {    
        PMSettingCtrl           *_settingController;
        thread_call_t           diskSyncCalloutEntry;
        IONotifier              *_batteryLocationNotifier;
        IONotifier              *_displayWranglerNotifier;
    };
    ExpansionData   *_reserved;
    IOOptionBits platformSleepSupport;
};

class IORootParent: public IOService
{
OSDeclareDefaultStructors(IORootParent)

private:
    unsigned long mostRecentChange;
    
public:

    bool start ( IOService * nub );
    void shutDownSystem ( void );
    void restartSystem ( void );
    void sleepSystem ( void );
    void dozeSystem ( void );
    void sleepToDoze ( void );
    void wakeSystem ( void );
};


#endif /*  _IOKIT_ROOTDOMAIN_H */
