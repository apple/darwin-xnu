/*
 * Copyright (c) 1998-2008 Apple Inc. All rights reserved.
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
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/OSDebug.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/pwr_mgt/IOPMlog.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOReturn.h>
#include "RootDomainUserClient.h"
#include "IOKit/pwr_mgt/IOPowerConnection.h"
#include "IOPMPowerStateQueue.h"
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOCommand.h>    // IOServicePMPrivate
#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include "IOServicePrivate.h"	// _IOServiceInterestNotifier
#include "IOServicePMPrivate.h"

__BEGIN_DECLS
#include <mach/shared_region.h>
__END_DECLS

#if defined(__i386__) || defined(__x86_64__)
__BEGIN_DECLS
#include "IOPMrootDomainInternal.h"
__END_DECLS
#endif

#define kIOPMrootDomainClass    "IOPMrootDomain"

#define LOG_PREFIX  "PMRD: "

#define LOG(x...)   do { \
    kprintf(LOG_PREFIX x); IOLog(x); } while (false)

#define KLOG(x...)  do { \
    kprintf(LOG_PREFIX x); } while (false)

#define DLOG(x...)  do { \
	if (kIOLogPMRootDomain & gIOKitDebug) \
        kprintf(LOG_PREFIX x); } while (false)

#define CHECK_THREAD_CONTEXT
#ifdef  CHECK_THREAD_CONTEXT
static IOWorkLoop * gIOPMWorkLoop = 0;
#define ASSERT_GATED(x)                                     \
do {                                                        \
    if (gIOPMWorkLoop && gIOPMWorkLoop->inGate() != true) { \
        panic("RootDomain: not inside PM gate");               \
    }                                                       \
} while(false)
#else
#define ASSERT_GATED(x)
#endif /* CHECK_THREAD_CONTEXT */

// Event types for IOPMPowerStateQueue::submitPowerEvent()
enum {
    kPowerEventFeatureChanged = 1,
    kPowerEventReceivedPowerNotification,
    kPowerEventSystemBootCompleted,
    kPowerEventSystemShutdown,
    kPowerEventUserDisabledSleep,
    kPowerEventConfigdRegisteredInterest,
    kPowerEventAggressivenessChanged,
    kPowerEventAssertionCreate,                 // 8
    kPowerEventAssertionRelease,                // 9
    kPowerEventAssertionSetLevel                // 10
};

extern "C" {
IOReturn OSKextSystemSleepOrWake( UInt32 );
}

extern const IORegistryPlane * gIOPowerPlane;

static void idleSleepTimerExpired( thread_call_param_t, thread_call_param_t );
static void wakeupClamshellTimerExpired( thread_call_param_t us, thread_call_param_t );
static void notifySystemShutdown( IOService * root, unsigned long event );
static bool clientMessageFilter( OSObject * object, void * context );
static void handleAggressivesFunction( thread_call_param_t param1, thread_call_param_t param2 );
static void pmEventTimeStamp(uint64_t *recordTS);

// "IOPMSetSleepSupported"  callPlatformFunction name
static const OSSymbol *sleepSupportedPEFunction = NULL;
static const OSSymbol *sleepMessagePEFunction   = NULL;

#define kIOSleepSupportedKey  "IOSleepSupported"

#define kRD_AllPowerSources (kIOPMSupportedOnAC \
                           | kIOPMSupportedOnBatt \
                           | kIOPMSupportedOnUPS)

enum 
{
    // not idle around autowake time, secs
    kAutoWakePreWindow  = 45,
    kAutoWakePostWindow = 15
};

#define kLocalEvalClamshellCommand        (1 << 15)

enum {
    OFF_STATE       = 0,
    RESTART_STATE   = 1,
    SLEEP_STATE     = 2,
    DOZE_STATE      = 3,
    ON_STATE        = 4,
    NUM_POWER_STATES
};

#define ON_POWER        kIOPMPowerOn
#define RESTART_POWER   kIOPMRestart
#define SLEEP_POWER     kIOPMAuxPowerOn
#define DOZE_POWER      kIOPMDoze

static IOPMPowerState ourPowerStates[NUM_POWER_STATES] =
{
    {1, 0,                      0,              0,             0,0,0,0,0,0,0,0},
    {1, kIOPMRestartCapability,	kIOPMRestart,	RESTART_POWER, 0,0,0,0,0,0,0,0},	
    {1, kIOPMSleepCapability,   kIOPMSleep,     SLEEP_POWER,   0,0,0,0,0,0,0,0},
    {1, kIOPMDoze,              kIOPMDoze,      DOZE_POWER,    0,0,0,0,0,0,0,0},
    {1, kIOPMPowerOn,           kIOPMPowerOn,   ON_POWER,      0,0,0,0,0,0,0,0}
};

// Clients eligible to receive system power messages.
enum {
    kMessageClientNone = 0,
    kMessageClientAll,
    kMessageClientConfigd       
};

// Run states (R-state) defined within the ON power state.
enum {
    kRStateNormal = 0,
    kRStateDark,
    kRStateMaintenance,
    kRStateCount
};

// IOService in power plane can be tagged with following flags.
enum {
	kServiceFlagGraphics    = 0x01,
	kServiceFlagNoPowerUp   = 0x02,
    kServiceFlagTopLevelPCI = 0x04
};

// Flags describing R-state features and capabilities.
enum {
    kRStateFlagNone             = 0x00000000,
    kRStateFlagSuppressGraphics = 0x00000001,
    kRStateFlagSuppressMessages = 0x00000002,
    kRStateFlagSuppressPCICheck = 0x00000004,
    kRStateFlagDisableIdleSleep = 0x00000008
};

#if ROOT_DOMAIN_RUN_STATES

// Table of flags for each R-state.
static uint32_t gRStateFlags[ kRStateCount ] =
{
    kRStateFlagNone,

    /* Dark wake */
    kRStateFlagSuppressGraphics,

    /* Maintenance wake */
    kRStateFlagSuppressGraphics |
    kRStateFlagSuppressMessages |
    kRStateFlagSuppressPCICheck |
    kRStateFlagDisableIdleSleep
};

static IONotifier *     gConfigdNotifier = 0;

#define kIOPMRootDomainRunStateKey          "Run State"
#define kIOPMRootDomainWakeTypeMaintenance  "Maintenance"
#define kIOPMRootDomainWakeTypeSleepTimer   "SleepTimer"
#define kIOPMrootDomainWakeTypeLowBattery   "LowBattery"

#endif /* ROOT_DOMAIN_RUN_STATES */

// Special interest that entitles the interested client from receiving
// all system messages. Used by pmconfigd to support maintenance wake.
//
#define kIOPMPrivilegedPowerInterest        "IOPMPrivilegedPowerInterest"

static IONotifier *     gSysPowerDownNotifier = 0;

/*
 * Aggressiveness
 */
#define AGGRESSIVES_LOCK()      IOLockLock(featuresDictLock)
#define AGGRESSIVES_UNLOCK()    IOLockUnlock(featuresDictLock)

#define kAggressivesMinValue    1

static uint32_t gAggressivesState = 0;

enum {
    kAggressivesStateBusy           = 0x01,
    kAggressivesStateQuickSpindown  = 0x02
};

struct AggressivesRecord {
    uint32_t    flags;
    uint32_t    type;
    uint32_t    value;
};

struct AggressivesRequest {
    queue_chain_t           chain;
    uint32_t                options;
    uint32_t                dataType;
    union {
        IOService *         service;
        AggressivesRecord   record;
    } data;
};

enum {
    kAggressivesRequestTypeService  = 1,
    kAggressivesRequestTypeRecord
};

enum {
    kAggressivesOptionSynchronous          = 0x00000001,
    kAggressivesOptionQuickSpindownEnable  = 0x00000100,
    kAggressivesOptionQuickSpindownDisable = 0x00000200,
    kAggressivesOptionQuickSpindownMask    = 0x00000300
};

enum {
    kAggressivesRecordFlagModified         = 0x00000001,
    kAggressivesRecordFlagMinValue         = 0x00000002
    
};

static IOPMrootDomain * gRootDomain;
static UInt32           gSleepOrShutdownPending = 0;
static UInt32           gWillShutdown = 0;
static uint32_t         gMessageClientType = kMessageClientNone;
static UInt32           gSleepWakeUUIDIsSet = false;

struct timeval gIOLastSleepTime;
struct timeval gIOLastWakeTime;

// Constants used as arguments to IOPMrootDomain::informCPUStateChange
#define kCPUUnknownIndex    9999999
enum {
    kInformAC = 0,
    kInformLid = 1,
    kInformableCount = 2
};

const OSSymbol *gIOPMStatsApplicationResponseTimedOut;
const OSSymbol *gIOPMStatsApplicationResponseCancel;
const OSSymbol *gIOPMStatsApplicationResponseSlow;

class PMSettingObject : public OSObject
{
    OSDeclareFinalStructors(PMSettingObject)
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
 * PMAssertionsTracker
 * Tracks kernel and user space PM assertions
 */
class PMAssertionsTracker : public OSObject
{
    OSDeclareFinalStructors(PMAssertionsTracker)
public:
    static PMAssertionsTracker  *pmAssertionsTracker( IOPMrootDomain * );

    IOReturn                    createAssertion(IOPMDriverAssertionType, IOPMDriverAssertionLevel, IOService *, const char *, IOPMDriverAssertionID *);
    IOReturn                    releaseAssertion(IOPMDriverAssertionID);
    IOReturn                    setAssertionLevel(IOPMDriverAssertionID, IOPMDriverAssertionLevel);
    IOReturn                    setUserAssertionLevels(IOPMDriverAssertionType);

    OSArray                     *copyAssertionsArray(void);
    IOPMDriverAssertionType     getActivatedAssertions(void);
    IOPMDriverAssertionLevel    getAssertionLevel(IOPMDriverAssertionType);

    IOReturn                    handleCreateAssertion(OSData *);
    IOReturn                    handleReleaseAssertion(IOPMDriverAssertionID);
    IOReturn                    handleSetAssertionLevel(IOPMDriverAssertionID, IOPMDriverAssertionLevel);
    IOReturn                    handleSetUserAssertionLevels(void * arg0);
    void                        publishProperties(void);

private:
    typedef struct {
        IOPMDriverAssertionID       id;
        IOPMDriverAssertionType     assertionBits;
        uint64_t                    createdTime;
        uint64_t                    modifiedTime;
        const OSSymbol              *ownerString;
        IOService                   *ownerService;
        IOPMDriverAssertionLevel    level;
    } PMAssertStruct;
    
    uint32_t                    tabulateProducerCount;
    uint32_t                    tabulateConsumerCount;

    PMAssertStruct              *detailsForID(IOPMDriverAssertionID, int *);
    void                        tabulate(void);
 
    IOPMrootDomain              *owner;
    OSArray                     *assertionsArray;
    IOLock                      *assertionsArrayLock;
    IOPMDriverAssertionID       issuingUniqueID;
    IOPMDriverAssertionType     assertionsKernel;
    IOPMDriverAssertionType     assertionsUser;
    IOPMDriverAssertionType     assertionsCombined;
};

OSDefineMetaClassAndFinalStructors(PMAssertionsTracker, OSObject);

/*
 * PMTraceWorker
 * Internal helper object for logging trace points to RTC
 * IOPMrootDomain and only IOPMrootDomain should instantiate
 * exactly one of these.
 */

typedef void (*IOPMTracePointHandler)(
        void * target, uint32_t code, uint32_t data );

class PMTraceWorker : public OSObject
{
    OSDeclareDefaultStructors(PMTraceWorker)
public:
    typedef enum { kPowerChangeStart, kPowerChangeCompleted } change_t;

    static PMTraceWorker        *tracer( IOPMrootDomain * );
    void                        tracePCIPowerChange(change_t, IOService *, uint32_t, uint32_t);
    void                        tracePoint(uint8_t phase);
    void                        traceLoginWindowPhase(uint8_t phase);
    int                         recordTopLevelPCIDevice(IOService *);
    void                        RTC_TRACE(void);
    virtual bool				serialize(OSSerialize *s) const;

    IOPMTracePointHandler       tracePointHandler;
    void *                      tracePointTarget;
private:
    IOPMrootDomain              *owner;
    IOLock                      *pciMappingLock;
    OSArray                     *pciDeviceBitMappings;

    uint8_t                     tracePhase;
    uint8_t                     loginWindowPhase;
    uint8_t                     addedToRegistry;
    uint8_t                     unused0;
    uint32_t                    pciBusyBitMask;
};

/*
 * PMHaltWorker
 * Internal helper object for Shutdown/Restart notifications.
 */
#define kPMHaltMaxWorkers   8
#define kPMHaltTimeoutMS    100

class PMHaltWorker : public OSObject
{
    OSDeclareFinalStructors( PMHaltWorker )

public:
    IOService *  service;    // service being worked on
    AbsoluteTime startTime;  // time when work started
    int          depth;      // work on nubs at this PM-tree depth
    int          visits;     // number of nodes visited (debug)
    IOLock *     lock;
    bool         timeout;    // service took too long

    static  PMHaltWorker * worker( void );
    static  void main( void * arg, wait_result_t waitResult );
    static  void work( PMHaltWorker * me );
    static  void checkTimeout( PMHaltWorker * me, AbsoluteTime * now );
    virtual void free( void );
};

OSDefineMetaClassAndFinalStructors( PMHaltWorker, OSObject )


#define super IOService
OSDefineMetaClassAndFinalStructors(IOPMrootDomain, IOService)

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
	if (OSCompareAndSwap(0, 1, &gWillShutdown))
	{
	    OSKext::willShutdown();
	    for (int i = 0; i < 100; i++)
	    {
		if (OSCompareAndSwap(0, 1, &gSleepOrShutdownPending)) break;
		IOSleep( 100 );
	    }
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

//******************************************************************************

IOPMrootDomain * IOPMrootDomain::construct( void )
{
    IOPMrootDomain  *root;

    root = new IOPMrootDomain;
    if( root)
        root->init();

    return( root );
}

//******************************************************************************

static void disk_sync_callout( thread_call_param_t p0, thread_call_param_t p1 )
{
    IOService       *rootDomain = (IOService *) p0;
    unsigned long   pmRef = (unsigned long) p1;

    DLOG("disk_sync_callout start\n");

#if	HIBERNATION
    IOHibernateSystemSleep();
#endif
    sync_internal();
    rootDomain->allowPowerChange(pmRef);
    DLOG("disk_sync_callout finish\n");
}

//******************************************************************************

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

//******************************************************************************

static int
sysctl_sleepwaketime SYSCTL_HANDLER_ARGS
{
  struct timeval *swt = (struct timeval *)arg1;
  struct proc *p = req->p;

  if (p == kernproc) {
    return sysctl_io_opaque(req, swt, sizeof(*swt), NULL);    
  } else if(proc_is64bit(p)) {
    struct user64_timeval t;
    t.tv_sec = swt->tv_sec;
    t.tv_usec = swt->tv_usec;
    return sysctl_io_opaque(req, &t, sizeof(t), NULL);
  } else {
    struct user32_timeval t;
    t.tv_sec = swt->tv_sec;
    t.tv_usec = swt->tv_usec;
    return sysctl_io_opaque(req, &t, sizeof(t), NULL);
  }
}

static SYSCTL_PROC(_kern, OID_AUTO, sleeptime,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN,
	    &gIOLastSleepTime, 0, sysctl_sleepwaketime, "S,timeval", "");

static SYSCTL_PROC(_kern, OID_AUTO, waketime,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN,
	    &gIOLastWakeTime, 0, sysctl_sleepwaketime, "S,timeval", "");


static int
sysctl_willshutdown
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int new_value, changed;
    int error = sysctl_io_number(req, gWillShutdown, sizeof(int), &new_value, &changed);
    if (changed) {
	if (!gWillShutdown && (new_value == 1)) {
	    IOSystemShutdownNotification();
	} else
	    error = EINVAL;
    }
    return(error);
}

static SYSCTL_PROC(_kern, OID_AUTO, willshutdown,
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN,
	    0, 0, sysctl_willshutdown, "I", "");

#if !CONFIG_EMBEDDED

static int
sysctl_progressmeterenable
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int error;
    int new_value, changed;

    error = sysctl_io_number(req, vc_progress_meter_enable, sizeof(int), &new_value, &changed);

    if (changed)
	vc_enable_progressmeter(new_value);

    return (error);
}

static int
sysctl_progressmeter
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int error;
    int new_value, changed;

    error = sysctl_io_number(req, vc_progress_meter_value, sizeof(int), &new_value, &changed);

    if (changed)
	vc_set_progressmeter(new_value);

    return (error);
}

static SYSCTL_PROC(_kern, OID_AUTO, progressmeterenable,
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN,
	    0, 0, sysctl_progressmeterenable, "I", "");

static SYSCTL_PROC(_kern, OID_AUTO, progressmeter,
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN,
	    0, 0, sysctl_progressmeter, "I", "");

#endif

static const OSSymbol * gIOPMSettingAutoWakeSecondsKey;
static const OSSymbol * gIOPMSettingMaintenanceWakeCalendarKey;

//******************************************************************************
// start
//
//******************************************************************************

#define kRootDomainSettingsCount        16

bool IOPMrootDomain::start( IOService * nub )
{
    OSIterator      *psIterator;
    OSDictionary    *tmpDict;

    super::start(nub);

    gRootDomain = this;
    gIOPMSettingAutoWakeSecondsKey = OSSymbol::withCString(kIOPMSettingAutoWakeSecondsKey);
    gIOPMSettingMaintenanceWakeCalendarKey =
        OSSymbol::withCString(kIOPMSettingMaintenanceWakeCalendarKey);

    gIOPMStatsApplicationResponseTimedOut = OSSymbol::withCString(kIOPMStatsResponseTimedOut);
    gIOPMStatsApplicationResponseCancel = OSSymbol::withCString(kIOPMStatsResponseCancel);
    gIOPMStatsApplicationResponseSlow = OSSymbol::withCString(kIOPMStatsResponseSlow);

    sleepSupportedPEFunction = OSSymbol::withCString("IOPMSetSleepSupported");
    sleepMessagePEFunction = OSSymbol::withCString("IOPMSystemSleepMessage");

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

    queue_init(&aggressivesQueue);
    aggressivesThreadCall = thread_call_allocate(handleAggressivesFunction, this);
    aggressivesData = OSData::withCapacity(
                        sizeof(AggressivesRecord) * (kPMLastAggressivenessType + 4));

    featuresDictLock = IOLockAlloc();
    settingsCtrlLock = IORecursiveLockAlloc();
    setPMRootDomain(this);
    
    extraSleepTimer = thread_call_allocate(
                        idleSleepTimerExpired,
                        (thread_call_param_t) this);

    clamshellWakeupIgnore = thread_call_allocate(
                        wakeupClamshellTimerExpired,
                        (thread_call_param_t) this);

    diskSyncCalloutEntry = thread_call_allocate(
                        &disk_sync_callout,
                        (thread_call_param_t) this);
    
    canSleep = true;
    setProperty(kIOSleepSupportedKey, true);

    bzero(&pmStats, sizeof(pmStats));

    pmTracer = PMTraceWorker::tracer(this);

    pmAssertions = PMAssertionsTracker::pmAssertionsTracker(this);

    updateRunState(kRStateNormal);
    userDisabledAllSleep = false;
    allowSleep = true;
    sleepIsSupported = true;
    systemBooting = true;
    sleepSlider = 0;
    idleSleepTimerPending = false;
    wrangler = NULL;
    sleepASAP = false;
    clamshellIsClosed = false;
    clamshellExists = false;
    ignoringClamshell = true;
    ignoringClamshellOnWake = false;
    acAdaptorConnected = true;

    queuedSleepWakeUUIDString = NULL;
    pmStatsAppResponses     = OSArray::withCapacity(5);
    _statsNameKey           = OSSymbol::withCString(kIOPMStatsNameKey);
    _statsPIDKey            = OSSymbol::withCString(kIOPMStatsPIDKey);
    _statsTimeMSKey         = OSSymbol::withCString(kIOPMStatsTimeMSKey);
    _statsResponseTypeKey   = OSSymbol::withCString(kIOPMStatsApplicationResponseTypeKey);
    _statsMessageTypeKey    = OSSymbol::withCString(kIOPMStatsMessageTypeKey);

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

    PMinit();   // creates gIOPMWorkLoop

    // Create IOPMPowerStateQueue used to queue external power
    // events, and to handle those events on the PM work loop.
    pmPowerStateQueue = IOPMPowerStateQueue::PMPowerStateQueue(
        this, OSMemberFunctionCast(IOEventSource::Action, this,
                &IOPMrootDomain::dispatchPowerEvent));
    getPMworkloop()->addEventSource(pmPowerStateQueue);
#ifdef CHECK_THREAD_CONTEXT
    gIOPMWorkLoop = getPMworkloop();
#endif

    // create our power parent
    patriarch = new IORootParent;
    patriarch->init();
    patriarch->attach(this);
    patriarch->start(this);
    patriarch->addPowerChild(this);

    registerPowerDriver(this, ourPowerStates, NUM_POWER_STATES);

    // set a clamp until we sleep
    changePowerStateToPriv(ON_STATE);

    // install power change handler
    gSysPowerDownNotifier = registerPrioritySleepWakeInterest( &sysPowerDownHandler, this, 0);

#if !NO_KERNEL_HID
    // Register for a notification when IODisplayWrangler is published
    if ((tmpDict = serviceMatching("IODisplayWrangler")))
    {
        _displayWranglerNotifier = addMatchingNotification( 
                gIOPublishNotification, tmpDict, 
                (IOServiceMatchingNotificationHandler) &displayWranglerPublished,
                this, 0);
        tmpDict->release();
    }
#endif

    // Battery location published - ApplePMU support only
    if ((tmpDict = serviceMatching("IOPMPowerSource")))
    {
        _batteryPublishNotifier = addMatchingNotification( 
                gIOPublishNotification, tmpDict, 
                (IOServiceMatchingNotificationHandler) &batteryPublished,
                this, this);
        tmpDict->release();
    }

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
    sysctl_register_oid(&sysctl__kern_willshutdown);
#if !CONFIG_EMBEDDED
    sysctl_register_oid(&sysctl__kern_progressmeterenable);
    sysctl_register_oid(&sysctl__kern_progressmeter);
#endif /* !CONFIG_EMBEDDED */

#if	HIBERNATION
    IOHibernateSystemInit(this);
#endif

    registerService();						// let clients find us

    return true;
}


//******************************************************************************
// setProperties
//
// Receive a setProperty call
// The "System Boot" property means the system is completely booted.
//******************************************************************************

IOReturn IOPMrootDomain::setProperties( OSObject * props_obj )
{
    IOReturn        return_value = kIOReturnSuccess;
    OSDictionary    *dict = OSDynamicCast(OSDictionary, props_obj);
    OSBoolean       *b;
    OSNumber        *n;
    OSString        *str;
    OSSymbol        *type;
    OSObject        *obj;
    unsigned int    i;

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
    const OSSymbol *ondeck_sleepwake_uuid_string =
                OSSymbol::withCString(kIOPMSleepWakeUUIDKey);
    const OSSymbol *loginwindow_tracepoint_string = 
                OSSymbol::withCString(kIOPMLoginWindowSecurityDebugKey);
                
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

    if (boot_complete_string && dict->getObject(boot_complete_string)) 
    {
        pmPowerStateQueue->submitPowerEvent( kPowerEventSystemBootCompleted );
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
        pmPowerStateQueue->submitPowerEvent(kPowerEventSystemShutdown, (void *) b);
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
        pmPowerStateQueue->submitPowerEvent(kPowerEventUserDisabledSleep, (void *) b);
    }
    
    if (ondeck_sleepwake_uuid_string
        && (obj = dict->getObject(ondeck_sleepwake_uuid_string)))
    {
        // Clear the currently published UUID
        if (kOSBooleanFalse == obj) 
        {
            publishSleepWakeUUID(NULL);
        }

        // Cache UUID for an upcoming sleep/wake        
        if ((str = OSDynamicCast(OSString, obj))) 
        {
            if (queuedSleepWakeUUIDString) {
                queuedSleepWakeUUIDString->release();
                queuedSleepWakeUUIDString = NULL;
            }
            queuedSleepWakeUUIDString = str;
            queuedSleepWakeUUIDString->retain();
            DLOG("SleepWake UUID queued: %s\n",
                queuedSleepWakeUUIDString->getCStringNoCopy());
        }
    }
    
    if (loginwindow_tracepoint_string
        && (n = OSDynamicCast(OSNumber, dict->getObject(loginwindow_tracepoint_string)))
        && pmTracer)
    {
        pmTracer->traceLoginWindowPhase( n->unsigned8BitValue() );
    }

    if ((b = OSDynamicCast(OSBoolean, dict->getObject(kIOPMDeepSleepEnabledKey))))
    {
        setProperty(kIOPMDeepSleepEnabledKey, b);
    }
    if ((n = OSDynamicCast(OSNumber, dict->getObject(kIOPMDeepSleepDelayKey))))
    {
        setProperty(kIOPMDeepSleepDelayKey, n);
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
    if(boot_complete_string) boot_complete_string->release();
    if(sys_shutdown_string) sys_shutdown_string->release();
    if(stall_halt_string) stall_halt_string->release();
    if (battery_warning_disabled_string) battery_warning_disabled_string->release();
    if(idle_seconds_string) idle_seconds_string->release();
    if(sleepdisabled_string) sleepdisabled_string->release();
    if(ondeck_sleepwake_uuid_string) ondeck_sleepwake_uuid_string->release();
    if(loginwindow_tracepoint_string) loginwindow_tracepoint_string->release();
#if	HIBERNATION
    if(hibernatemode_string) hibernatemode_string->release();
    if(hibernatefile_string) hibernatefile_string->release();
    if(hibernatefreeratio_string) hibernatefreeratio_string->release();
    if(hibernatefreetime_string) hibernatefreetime_string->release();
#endif
    return return_value;
}


//******************************************************************************
// aggressivenessChanged
//
// We are behind the command gate to examine changes to aggressives.
//******************************************************************************

void IOPMrootDomain::aggressivenessChanged( void )
{
    unsigned long   minutesToSleep = 0;
    unsigned long   minutesToDisplayDim = 0;

    ASSERT_GATED();

    // Fetch latest display and system sleep slider values.
	getAggressiveness(kPMMinutesToSleep, &minutesToSleep);
	getAggressiveness(kPMMinutesToDim,   &minutesToDisplayDim);
    DLOG("aggressiveness changed system %u, display %u\n",
        (uint32_t) minutesToSleep, (uint32_t) minutesToDisplayDim);

    DLOG("idle time -> %ld secs (ena %d)\n",
        idleSeconds, (minutesToSleep != 0));

    if (0x7fffffff == minutesToSleep)
        minutesToSleep = idleSeconds;

    // How long to wait before sleeping the system once the displays turns
    // off is indicated by 'extraSleepDelay'.

    if ( minutesToSleep > minutesToDisplayDim ) {
        extraSleepDelay = minutesToSleep - minutesToDisplayDim;
    }
    else {
        extraSleepDelay = 0;
    }

    // system sleep timer was disabled, but not anymore.
    if ( (sleepSlider == 0) && (minutesToSleep != 0) ) {
        if (!wrangler)
        {
            sleepASAP = false;
            changePowerStateToPriv(ON_STATE);
            if (idleSeconds)
            {
                startIdleSleepTimer( idleSeconds );
            }
        }
        else
        {
            // Start idle sleep timer if wrangler went to sleep
            // while system sleep was disabled.

            sleepASAP = false;
            if (wranglerAsleep)
            {
                AbsoluteTime    now;
                uint64_t        nanos;
                uint32_t        minutesSinceDisplaySleep = 0;
                uint32_t        sleepDelay;

                clock_get_uptime(&now);
                if (CMP_ABSOLUTETIME(&now, &wranglerSleepTime) > 0)
                {
                    SUB_ABSOLUTETIME(&now, &wranglerSleepTime);
                    absolutetime_to_nanoseconds(now, &nanos);
                    minutesSinceDisplaySleep = nanos / (60000000000ULL);
                }

                if (extraSleepDelay > minutesSinceDisplaySleep)
                {
                    sleepDelay = extraSleepDelay - minutesSinceDisplaySleep;
                }
                else
                {
                    // 1 min idle sleep.
                    sleepDelay = 1;
                }

                startIdleSleepTimer(sleepDelay * 60);
                DLOG("display slept %u min, set idle timer to %u min\n",
                    minutesSinceDisplaySleep, sleepDelay);
            }
        }
    }

    sleepSlider = minutesToSleep;
    if ( sleepSlider == 0 ) {
        cancelIdleSleepTimer();
        // idle sleep is now disabled
        adjustPowerState();
        // make sure we're powered
        patriarch->wakeSystem();
    }
}


//******************************************************************************
// setAggressiveness
//
// Override IOService::setAggressiveness()
//******************************************************************************

IOReturn IOPMrootDomain::setAggressiveness(
    unsigned long   type,
    unsigned long   value )
{
    return setAggressiveness( type, value, 0 );
}

/*
 * Private setAggressiveness() with an internal options argument.
 */
IOReturn IOPMrootDomain::setAggressiveness(
    unsigned long   type,
    unsigned long   value,
    IOOptionBits    options )
{
    AggressivesRequest *    entry;
    AggressivesRequest *    request;
    bool                    found = false;

    DLOG("setAggressiveness 0x%x = %u, options 0x%x\n",
        (uint32_t) type, (uint32_t) value, (uint32_t) options);

    request = IONew(AggressivesRequest, 1);
    if (!request)
        return kIOReturnNoMemory;

    memset(request, 0, sizeof(*request));
    request->options  = options;
    request->dataType = kAggressivesRequestTypeRecord;
    request->data.record.type  = (uint32_t) type;
    request->data.record.value = (uint32_t) value;

    AGGRESSIVES_LOCK();

    // Update disk quick spindown flag used by getAggressiveness().
    // Never merge requests with quick spindown flags set.

    if (options & kAggressivesOptionQuickSpindownEnable)
        gAggressivesState |= kAggressivesStateQuickSpindown;
    else if (options & kAggressivesOptionQuickSpindownDisable)
        gAggressivesState &= ~kAggressivesStateQuickSpindown;
    else
    {
        // Coalesce requests with identical aggressives types.
        // Deal with callers that calls us too "aggressively".

        queue_iterate(&aggressivesQueue, entry, AggressivesRequest *, chain)
        {
            if ((entry->dataType == kAggressivesRequestTypeRecord) &&
                (entry->data.record.type == type) &&
                ((entry->options & kAggressivesOptionQuickSpindownMask) == 0))
            {
                entry->data.record.value = value;
                found = true;
                break;
            }
        }
    }

    if (!found)
    {
        queue_enter(&aggressivesQueue, request, AggressivesRequest *, chain);
    }

    AGGRESSIVES_UNLOCK();

    if (found)
        IODelete(request, AggressivesRequest, 1);

    if (options & kAggressivesOptionSynchronous)
        handleAggressivesRequests();   // not truly synchronous
    else
        thread_call_enter(aggressivesThreadCall);

    return kIOReturnSuccess;
}


//******************************************************************************
// getAggressiveness
//
// Override IOService::setAggressiveness()
// Fetch the aggressiveness factor with the given type.
//******************************************************************************

IOReturn IOPMrootDomain::getAggressiveness (
    unsigned long   type,
    unsigned long * outLevel )
{
    uint32_t    value  = 0;
    int         source = 0;

    if (!outLevel)
        return kIOReturnBadArgument;

    AGGRESSIVES_LOCK();

    // Disk quick spindown in effect, report value = 1

    if ((gAggressivesState & kAggressivesStateQuickSpindown) &&
        (type == kPMMinutesToSpinDown))
    {
        value  = kAggressivesMinValue;
        source = 1;
    }

    // Consult the pending request queue.

    if (!source)
    {
        AggressivesRequest * entry;

        queue_iterate(&aggressivesQueue, entry, AggressivesRequest *, chain)
        {
            if ((entry->dataType == kAggressivesRequestTypeRecord) &&
                (entry->data.record.type == type) &&
                ((entry->options & kAggressivesOptionQuickSpindownMask) == 0))
            {
                value  = entry->data.record.value;
                source = 2;
                break;
            }
        }
    }

    // Consult the backend records.

    if (!source && aggressivesData)
    {
        AggressivesRecord * record;
        int                 i, count;

        count  = aggressivesData->getLength() / sizeof(AggressivesRecord);
        record = (AggressivesRecord *) aggressivesData->getBytesNoCopy();

        for (i = 0; i < count; i++, record++)
        {
            if (record->type == type)
            {
                value  = record->value;
                source = 3;
                break;
            }
        }
    }

    AGGRESSIVES_UNLOCK();

    if (source)
    {
        DLOG("getAggressiveness 0x%x = %u, source %d\n",
            (uint32_t) type, value, source);
        *outLevel = (unsigned long) value;
        return kIOReturnSuccess;
    }
    else
    {
        DLOG("getAggressiveness type 0x%x not found\n", (uint32_t) type);
        *outLevel = 0;  // default return = 0, driver may not check for error
        return kIOReturnInvalid;
    }
}


//******************************************************************************
// joinAggressiveness
//
// Request from IOService to join future aggressiveness broadcasts.
//******************************************************************************

IOReturn IOPMrootDomain::joinAggressiveness(
    IOService * service )
{
    AggressivesRequest *    request;

    if (!service || (service == this))
        return kIOReturnBadArgument;

    DLOG("joinAggressiveness %s (%p)\n", service->getName(), service);

    request = IONew(AggressivesRequest, 1);
    if (!request)
        return kIOReturnNoMemory;

    service->retain();  // released by synchronizeAggressives()

    memset(request, 0, sizeof(*request));
    request->dataType = kAggressivesRequestTypeService;
    request->data.service = service;

    AGGRESSIVES_LOCK();
    queue_enter(&aggressivesQueue, request, AggressivesRequest *, chain);
    AGGRESSIVES_UNLOCK();

    thread_call_enter(aggressivesThreadCall);

    return kIOReturnSuccess;
}


//******************************************************************************
// handleAggressivesRequests
//
// Backend thread processes all incoming aggressiveness requests in the queue.
//******************************************************************************

static void
handleAggressivesFunction(
    thread_call_param_t param1,
    thread_call_param_t param2 )
{
    if (param1)
    {
        ((IOPMrootDomain *) param1)->handleAggressivesRequests();
    }
}

void IOPMrootDomain::handleAggressivesRequests( void )
{
    AggressivesRecord *     start;
    AggressivesRecord *     record;
    AggressivesRequest *    request;
    queue_head_t            joinedQueue;
    int                     i, count;
    bool                    broadcast;
    bool                    found;
    bool                    pingSelf = false;

    AGGRESSIVES_LOCK();

    if ((gAggressivesState & kAggressivesStateBusy) || !aggressivesData ||
        queue_empty(&aggressivesQueue))
        goto unlock_done;

    gAggressivesState |= kAggressivesStateBusy;
    count = aggressivesData->getLength() / sizeof(AggressivesRecord);
    start = (AggressivesRecord *) aggressivesData->getBytesNoCopy();

    do
    {
        broadcast = false;
        queue_init(&joinedQueue);

        do
        {
            // Remove request from the incoming queue in FIFO order.
            queue_remove_first(&aggressivesQueue, request, AggressivesRequest *, chain);
            switch (request->dataType)
            {
                case kAggressivesRequestTypeRecord:
                    // Update existing record if found.
                    found = false;
                    for (i = 0, record = start; i < count; i++, record++)
                    {
                        if (record->type == request->data.record.type)
                        {
                            found = true;

                            if (request->options & kAggressivesOptionQuickSpindownEnable)
                            {
                                if ((record->flags & kAggressivesRecordFlagMinValue) == 0)
                                {
                                    broadcast = true;
                                    record->flags |= (kAggressivesRecordFlagMinValue |
                                                      kAggressivesRecordFlagModified);
                                    DLOG("quick spindown accelerated, was %u min\n",
                                        record->value);
                                }
                            }
                            else if (request->options & kAggressivesOptionQuickSpindownDisable)
                            {
                                if (record->flags & kAggressivesRecordFlagMinValue)
                                {
                                    broadcast = true;
                                    record->flags |= kAggressivesRecordFlagModified;
                                    record->flags &= ~kAggressivesRecordFlagMinValue;
                                    DLOG("disk spindown restored to %u min\n",
                                        record->value);
                                }
                            }
                            else if (record->value != request->data.record.value)
                            {
                                record->value = request->data.record.value;
                                if ((record->flags & kAggressivesRecordFlagMinValue) == 0)
                                {
                                    broadcast = true;
                                    record->flags |= kAggressivesRecordFlagModified;
                                }
                            }
                            break;
                        }
                    }

                    // No matching record, append a new record.
                    if (!found &&
                        ((request->options & kAggressivesOptionQuickSpindownDisable) == 0))
                    {
                        AggressivesRecord   newRecord;

                        newRecord.flags = kAggressivesRecordFlagModified;
                        newRecord.type  = request->data.record.type;
                        newRecord.value = request->data.record.value;
                        if (request->options & kAggressivesOptionQuickSpindownEnable)
                        {
                            newRecord.flags |= kAggressivesRecordFlagMinValue;
                            DLOG("disk spindown accelerated\n");
                        }

                        aggressivesData->appendBytes(&newRecord, sizeof(newRecord));

                        // OSData may have switched to another (larger) buffer.
                        count = aggressivesData->getLength() / sizeof(AggressivesRecord);
                        start = (AggressivesRecord *) aggressivesData->getBytesNoCopy();
                        broadcast = true;
                    }

                    // Finished processing the request, release it.
                    IODelete(request, AggressivesRequest, 1);
                    break;

                case kAggressivesRequestTypeService:
                    // synchronizeAggressives() will free request.
                    queue_enter(&joinedQueue, request, AggressivesRequest *, chain);
                    break;

                default:
                    panic("bad aggressives request type %x\n", request->dataType);
                    break;
            }
        } while (!queue_empty(&aggressivesQueue));

        // Release the lock to perform work, with busy flag set.
        if (!queue_empty(&joinedQueue) || broadcast)
        {
            AGGRESSIVES_UNLOCK();
            if (!queue_empty(&joinedQueue))
                synchronizeAggressives(&joinedQueue, start, count);
            if (broadcast)
                broadcastAggressives(start, count);
            AGGRESSIVES_LOCK();
        }

        // Remove the modified flag from all records.
        for (i = 0, record = start; i < count; i++, record++)
        {
            if ((record->flags & kAggressivesRecordFlagModified) &&
                ((record->type == kPMMinutesToDim) ||
                 (record->type == kPMMinutesToSleep)))
                pingSelf = true;

            record->flags &= ~kAggressivesRecordFlagModified;
        }

        // Check the incoming queue again since new entries may have been
        // added while lock was released above.

    } while (!queue_empty(&aggressivesQueue));

    gAggressivesState &= ~kAggressivesStateBusy;

unlock_done:
    AGGRESSIVES_UNLOCK();

    // Root domain is interested in system and display sleep slider changes.
    // Submit a power event to handle those changes on the PM work loop.

    if (pingSelf && pmPowerStateQueue) {
        pmPowerStateQueue->submitPowerEvent( kPowerEventAggressivenessChanged );
    }
}


//******************************************************************************
// synchronizeAggressives
//
// Push all known aggressiveness records to one or more IOService.
//******************************************************************************

void IOPMrootDomain::synchronizeAggressives(
    queue_head_t *              joinedQueue,
    const AggressivesRecord *   array,
    int                         count )
{
    IOService *                 service;
    AggressivesRequest *        request;
    const AggressivesRecord *   record;
    uint32_t                    value;
    int                         i;

    while (!queue_empty(joinedQueue))
    {
        queue_remove_first(joinedQueue, request, AggressivesRequest *, chain);
        if (request->dataType == kAggressivesRequestTypeService)
            service = request->data.service;
        else
            service = 0;

        IODelete(request, AggressivesRequest, 1);
        request = 0;

        if (service)
        {
            if (service->assertPMThreadCall())
            {
                for (i = 0, record = array; i < count; i++, record++)
                {
                    value = record->value;
                    if (record->flags & kAggressivesRecordFlagMinValue)
                        value = kAggressivesMinValue;

                    DLOG("synchronizeAggressives 0x%x = %u to %s\n",
                        record->type, value, service->getName());
                    service->setAggressiveness(record->type, value);
                }
                service->deassertPMThreadCall();
            }
            service->release();     // retained by joinAggressiveness()
        }
    }
}


//******************************************************************************
// broadcastAggressives
//
// Traverse PM tree and call setAggressiveness() for records that have changed.
//******************************************************************************

void IOPMrootDomain::broadcastAggressives(
    const AggressivesRecord *   array,
    int                         count )
{
	IORegistryIterator *        iter;
	IORegistryEntry *           entry;
	IOPowerConnection *         connect;
    IOService *                 service;
    const AggressivesRecord *   record;
    uint32_t                    value;
    int                         i;

	iter = IORegistryIterator::iterateOver(
		this, gIOPowerPlane, kIORegistryIterateRecursively);
    if (iter)
	{
        do
        {
            iter->reset();
            while ((entry = iter->getNextObject()))
            {
                connect = OSDynamicCast(IOPowerConnection, entry);
                if (!connect || !connect->getReadyFlag())
                    continue;

                if ((service = (IOService *) connect->copyChildEntry(gIOPowerPlane)))
                {
                    if (service->assertPMThreadCall())
                    {
                        for (i = 0, record = array; i < count; i++, record++)
                        {
                            if (record->flags & kAggressivesRecordFlagModified)
                            {
                                value = record->value;
                                if (record->flags & kAggressivesRecordFlagMinValue)
                                    value = kAggressivesMinValue;
                                DLOG("broadcastAggressives %x = %u to %s\n",
                                    record->type, value, service->getName());
                                service->setAggressiveness(record->type, value);
                            }
                        }
                        service->deassertPMThreadCall();
                    }
                    service->release();
                }
            }
        }
        while (!entry && !iter->isValid());
        iter->release();
    }
}


//******************************************************************************
// startIdleSleepTimer
//
//******************************************************************************

void IOPMrootDomain::startIdleSleepTimer( uint32_t inSeconds )
{
    AbsoluteTime deadline;

    ASSERT_GATED();
    if (inSeconds)
    {
        clock_interval_to_deadline(inSeconds, kSecondScale, &deadline);	
        thread_call_enter_delayed(extraSleepTimer, deadline);
        idleSleepTimerPending = true;
        DLOG("idle timer set for %u seconds\n", inSeconds);
    }
}


//******************************************************************************
// cancelIdleSleepTimer
//
//******************************************************************************

void IOPMrootDomain::cancelIdleSleepTimer( void )
{
    ASSERT_GATED();
    if (idleSleepTimerPending) 
    {
        DLOG("idle timer cancelled\n");
        thread_call_cancel(extraSleepTimer);
        idleSleepTimerPending = false;
    }
}


//******************************************************************************
// idleSleepTimerExpired
//
//******************************************************************************

static void idleSleepTimerExpired(
    thread_call_param_t us, thread_call_param_t )
{
    ((IOPMrootDomain *)us)->handleSleepTimerExpiration();
}

static void wakeupClamshellTimerExpired(
    thread_call_param_t us, thread_call_param_t )
{
    ((IOPMrootDomain *)us)->stopIgnoringClamshellEventsDuringWakeup();
}


//******************************************************************************
// handleSleepTimerExpiration
//
// The time between the sleep idle timeout and the next longest one has elapsed.
// It's time to sleep. Start that by removing the clamp that's holding us awake.
//******************************************************************************

void IOPMrootDomain::handleSleepTimerExpiration( void )
{
    if (!getPMworkloop()->inGate())
    {
        getPMworkloop()->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, this,
                &IOPMrootDomain::handleSleepTimerExpiration),
            this);
        return;
    }

    AbsoluteTime time;

    DLOG("sleep timer expired\n");
    ASSERT_GATED();

    idleSleepTimerPending = false;

    clock_get_uptime(&time);
    if ((AbsoluteTime_to_scalar(&time) > autoWakeStart) &&
        (AbsoluteTime_to_scalar(&time) < autoWakeEnd))
    {
        thread_call_enter_delayed(extraSleepTimer, *((AbsoluteTime *) &autoWakeEnd));
        return;
    }

    // accelerate disk spin down if spin down timer is non-zero
    setQuickSpinDownTimeout();

    sleepASAP = true;
    adjustPowerState();
}


//******************************************************************************
// stopIgnoringClamshellEventsDuringWakeup
//
//******************************************************************************

void IOPMrootDomain::stopIgnoringClamshellEventsDuringWakeup( void )
{
    if (!getPMworkloop()->inGate())
    {
        getPMworkloop()->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, this,
                &IOPMrootDomain::stopIgnoringClamshellEventsDuringWakeup),
            this);
        return;
    }

    ASSERT_GATED();

    // Allow clamshell-induced sleep now
    ignoringClamshellOnWake = false;

    // Re-send clamshell event, in case it causes a sleep
    if (clamshellIsClosed)
        handlePowerNotification( kLocalEvalClamshellCommand );
}


//******************************************************************************
// sleepSystem
//
//******************************************************************************

/* public */
IOReturn IOPMrootDomain::sleepSystem( void )
{
    return sleepSystemOptions(NULL);
}

/* private */
IOReturn IOPMrootDomain::sleepSystemOptions( OSDictionary *options )
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
        return privateSleepSystem( kIOPMSleepReasonOSSwitchHibernation);

    } else {

        return privateSleepSystem( kIOPMSleepReasonSoftware);

    }
}

/* private */
IOReturn IOPMrootDomain::privateSleepSystem( uint32_t sleepReason )
{
    static const char * IOPMSleepReasons[kIOPMSleepReasonMax] = {
        "",
        kIOPMClamshellSleepKey,
        kIOPMPowerButtonSleepKey,
        kIOPMSoftwareSleepKey,
        kIOPMOSSwitchHibernationKey,
        kIOPMIdleSleepKey,
        kIOPMLowPowerSleepKey,
        kIOPMClamshellSleepKey,
        kIOPMThermalEmergencySleepKey
    };
    if ( userDisabledAllSleep )
    {
        LOG("Sleep prevented by user disable\n");

        /* Prevent sleep of all kinds if directed to by user space */
        return kIOReturnNotPermitted;
    }

    if ( systemBooting || systemShutdown || !allowSleep )
    {
        LOG("Sleep prevented by SB %d, SS %d, AS %d\n",
            systemBooting, systemShutdown, allowSleep);

        // Unable to sleep because system is in the process of booting or
        // shutting down, or sleep has otherwise been disallowed.
        return kIOReturnError;
    }

    // Record sleep cause in IORegistry
    lastSleepReason = sleepReason;
    if (sleepReason && (sleepReason < kIOPMSleepReasonMax)) {
        setProperty(kRootDomainSleepReasonKey, IOPMSleepReasons[sleepReason]);
    }

    patriarch->sleepSystem();
    return kIOReturnSuccess;
}


//******************************************************************************
// shutdownSystem
//
//******************************************************************************

IOReturn IOPMrootDomain::shutdownSystem( void )
{
    //patriarch->shutDownSystem();
    return kIOReturnUnsupported;
}


//******************************************************************************
// restartSystem
//
//******************************************************************************

IOReturn IOPMrootDomain::restartSystem( void )
{
    //patriarch->restartSystem();
    return kIOReturnUnsupported;
}


//******************************************************************************
// powerChangeDone
//
// This overrides powerChangeDone in IOService.
//
// Menu sleep and idle sleep move us from the ON state to the SLEEP_STATE.
// In this case:
// If we finished going to the SLEEP_STATE, and the platform is capable of
// true sleep, then sleep the kernel. Otherwise switch up to the DOZE_STATE
// which will keep almost everything as off as it can get.
//******************************************************************************

void IOPMrootDomain::powerChangeDone( unsigned long previousState )
{
    ASSERT_GATED();
    DLOG("PowerChangeDone: %u->%u\n",
        (uint32_t) previousState, (uint32_t) getPowerState());

    switch ( getPowerState() ) {
        case SLEEP_STATE:
			if ( previousState != ON_STATE )
				break;

            if ( canSleep )
            {
                // re-enable this timer for next sleep
                cancelIdleSleepTimer();
                wranglerTickled = true;

                clock_sec_t		secs;
				clock_usec_t	microsecs;
                clock_get_calendar_microtime(&secs, &microsecs);
                logtime(secs);
                gIOLastSleepTime.tv_sec  = secs;
                gIOLastSleepTime.tv_usec = microsecs;
                gIOLastWakeTime.tv_sec = 0;
                gIOLastWakeTime.tv_usec = 0;

#if	HIBERNATION
                LOG("System %sSleep\n", gIOHibernateState ? "Safe" : "");

                tracePoint(kIOPMTracePointSystemHibernatePhase);

                IOHibernateSystemHasSlept();

                evaluateSystemSleepPolicyFinal();
#else
                LOG("System Sleep\n");
#endif

                tracePoint(kIOPMTracePointSystemSleepPlatformPhase);

                getPlatform()->sleepKernel();

                // The CPU(s) are off at this point. When they're awakened by CPU interrupt,
                // code will resume execution here.

                // Now we're waking...
                tracePoint(kIOPMTracePointSystemWakeDriversPhase);
                
#if	HIBERNATION
                IOHibernateSystemWake();
#endif

                // sleep transition complete
                gSleepOrShutdownPending = 0;

                // trip the reset of the calendar clock
                clock_wakeup_calendar();

                // get us some power
                patriarch->wakeSystem();

                // Set indicator if UUID was set - allow it to be cleared.
                if (getProperty(kIOPMSleepWakeUUIDKey))
                    gSleepWakeUUIDIsSet = true;

#if !ROOT_DOMAIN_RUN_STATES
                tellClients(kIOMessageSystemWillPowerOn, clientMessageFilter);
#endif

#if	HIBERNATION
                LOG("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
#endif

                // log system wake
                getPlatform()->PMLog(kIOPMrootDomainClass, kPMLogSystemWake, 0, 0);
                lowBatteryCondition = false;

#ifndef __LP64__
                // tell the tree we're waking
                systemWake();
#endif


#if defined(__i386__) || defined(__x86_64__)
                sleepTimerMaintenance = false;
#if ROOT_DOMAIN_RUN_STATES
                OSString * wakeType = OSDynamicCast(
                    OSString, getProperty(kIOPMRootDomainWakeTypeKey));
                if (wakeType && wakeType->isEqualTo(kIOPMrootDomainWakeTypeLowBattery))
                {
                    lowBatteryCondition = true;
                    updateRunState(kRStateMaintenance);
                    wranglerTickled = false;
                }
                else if (wakeType && !hibernateAborted && wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepTimer))
                {
                    sleepTimerMaintenance = true;
                    updateRunState(kRStateMaintenance);
                    wranglerTickled = false;
                }
                else if (wakeType && !hibernateAborted && wakeType->isEqualTo(kIOPMRootDomainWakeTypeMaintenance))
                {
                    updateRunState(kRStateMaintenance);
                    wranglerTickled = false;
                }
                else
#endif  /* ROOT_DOMAIN_RUN_STATES */
                {
                    updateRunState(kRStateNormal);
                    reportUserInput();
                }
#else   /* !__i386__ && !__x86_64__ */
                // stay awake for at least 30 seconds
                startIdleSleepTimer(30);
                reportUserInput();
#endif

                changePowerStateToPriv(ON_STATE);
            } else {
                updateRunState(kRStateNormal);

                // allow us to step up a power state
                patriarch->sleepToDoze();

                // ignore children's request for higher power during doze.
                changePowerStateWithOverrideTo(DOZE_STATE);
            }
            break;

        case DOZE_STATE:
            if ( previousState != DOZE_STATE ) 
            {
                LOG("System Doze\n");
            }
            // re-enable this timer for next sleep
            cancelIdleSleepTimer();
            gSleepOrShutdownPending = 0;

            // Invalidate prior activity tickles to allow wake from doze.
            if (wrangler) wrangler->changePowerStateTo(0);
            break;

#if ROOT_DOMAIN_RUN_STATES
        case ON_STATE:
            // SLEEP -> ON (Maintenance)
            // Go back to sleep, unless cancelled by a HID event.

            if ((previousState == SLEEP_STATE) &&
                (runStateIndex == kRStateMaintenance) &&
                !wranglerTickled)
            {
                if (lowBatteryCondition)
                {
                    lastSleepReason = kIOPMSleepReasonLowPower;
                    setProperty(kRootDomainSleepReasonKey, kIOPMLowPowerSleepKey);
                }
                else
                {
                    lastSleepReason = kIOPMSleepReasonMaintenance;
                    setProperty(kRootDomainSleepReasonKey, kIOPMMaintenanceSleepKey);
                }
                changePowerStateWithOverrideTo(SLEEP_STATE);
            }

            // ON -> ON triggered by R-state changes.

            if ((previousState == ON_STATE) &&
                (runStateIndex != nextRunStateIndex) &&
                (nextRunStateIndex < kRStateCount))
            {
                LOG("R-state changed %u->%u\n",
                    runStateIndex, nextRunStateIndex);
                updateRunState(nextRunStateIndex);

                DLOG("kIOMessageSystemHasPoweredOn (%u)\n",
                    gMessageClientType);
                tellClients(kIOMessageSystemHasPoweredOn, clientMessageFilter);
            }
            
            break;
#endif  /* ROOT_DOMAIN_RUN_STATES */
    }
}


//******************************************************************************
// wakeFromDoze
//
// The Display Wrangler calls here when it switches to its highest state.
// If the  system is currently dozing, allow it to wake by making sure the
// parent is providing power.
//******************************************************************************

void IOPMrootDomain::wakeFromDoze( void )
{
    if ( getPowerState() == DOZE_STATE )
    {
        tracePoint(kIOPMTracePointSystemWakeDriversPhase);
        changePowerStateToPriv(ON_STATE);
        patriarch->wakeSystem();
    }
}


//******************************************************************************
// publishFeature
//
// Adds a new feature to the supported features dictionary
//******************************************************************************

void IOPMrootDomain::publishFeature( const char * feature )
{
    publishFeature(feature, kRD_AllPowerSources, NULL);
}


//******************************************************************************
// publishFeature (with supported power source specified)
//
// Adds a new feature to the supported features dictionary
//******************************************************************************

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

    feature_value = (uint32_t)next_feature_id;
    feature_value <<= 16;
    feature_value += supportedWhere;

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
        } else if(( existing_feature_arr = OSDynamicCast(OSArray, osObj) ))
        {
            // Add object to existing array        
            existing_feature_arr = OSArray::withArray(
                            existing_feature_arr,
                            existing_feature_arr->getCount() + 1);
        }

        if (existing_feature_arr)
        {
            existing_feature_arr->setObject(new_feature_data);
            features->setObject(feature, existing_feature_arr);
            existing_feature_arr->release();
            existing_feature_arr = 0;
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
        pmPowerStateQueue->submitPowerEvent( kPowerEventFeatureChanged );
    }
}


//******************************************************************************
// removePublishedFeature
//
// Removes previously published feature
//******************************************************************************

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
    OSArray                 *arrayMemberCopy;

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
                        // Otherwise remove the element from a copy of the array.
                        arrayMemberCopy = OSArray::withArray(arrayMember);
                        if (arrayMemberCopy)
                        {
                            arrayMemberCopy->removeObject(i);
                            features->setObject(dictKey, arrayMemberCopy);
                            arrayMemberCopy->release();
                        }
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
            pmPowerStateQueue->submitPowerEvent( kPowerEventFeatureChanged );
        }
    } else {
        ret = kIOReturnNotFound;
    }
    
exit:
    if(features)    features->release();
    if(featuresDictLock) IOLockUnlock(featuresDictLock);    
    return ret;
}


//******************************************************************************
// announcePowerSourceChange
//
// Notifies "interested parties" that the battery state has changed
//******************************************************************************

void IOPMrootDomain::announcePowerSourceChange( void )
{
#ifdef __ppc__
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
#endif
}


//******************************************************************************
// setPMSetting (private)
//
// Internal helper to relay PM settings changes from user space to individual
// drivers. Should be called only by IOPMrootDomain::setProperties.
//******************************************************************************

IOReturn IOPMrootDomain::setPMSetting(
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


//******************************************************************************
// copyPMSetting (public)
//
// Allows kexts to safely read setting values, without being subscribed to
// notifications.
//******************************************************************************

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


//******************************************************************************
// registerPMSettingController (public)
//
// direct wrapper to registerPMSettingController with uint32_t power source arg
//******************************************************************************

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


//******************************************************************************
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
//******************************************************************************

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

bool IOPMrootDomain::shouldSleepOnClamshellClosed( void )
{
    DLOG("clamshell state %d, EX %d, IG %d, IW %d, DT %d, AC %d\n",
        clamshellIsClosed, clamshellExists, ignoringClamshell,
        ignoringClamshellOnWake, desktopMode, acAdaptorConnected);

    return ( !ignoringClamshell 
          && !ignoringClamshellOnWake 
          && !(desktopMode && acAdaptorConnected) );
}

void IOPMrootDomain::sendClientClamshellNotification( void )
{
    /* Only broadcast clamshell alert if clamshell exists. */
    if (!clamshellExists)
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
#if defined(__i386__) || defined(__x86_64__)

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
    
#endif /* __i386__ || __x86_64__ */
}


#if HIBERNATION

//******************************************************************************
// evaluateSystemSleepPolicy
//******************************************************************************

struct IOPMSystemSleepPolicyEntry
{
    uint32_t    factorMask;
    uint32_t    factorBits;
    uint32_t    sleepFlags;
    uint32_t    wakeEvents;
};

struct IOPMSystemSleepPolicyTable
{
    uint8_t     signature[4];
    uint16_t    version;
    uint16_t    entryCount;
    IOPMSystemSleepPolicyEntry  entries[];
};

enum {
    kIOPMSleepFactorSleepTimerWake          = 0x00000001,
    kIOPMSleepFactorLidOpen                 = 0x00000002,
    kIOPMSleepFactorACPower                 = 0x00000004,
    kIOPMSleepFactorLowBattery              = 0x00000008,
    kIOPMSleepFactorDeepSleepNoDelay        = 0x00000010,
    kIOPMSleepFactorDeepSleepDemand         = 0x00000020,
    kIOPMSleepFactorDeepSleepDisable        = 0x00000040,
    kIOPMSleepFactorUSBExternalDevice       = 0x00000080,
    kIOPMSleepFactorBluetoothHIDDevice      = 0x00000100,
    kIOPMSleepFactorExternalMediaMounted    = 0x00000200,
    kIOPMSleepFactorDriverAssertBit5        = 0x00000400,
    kIOPMSleepFactorDriverAssertBit6        = 0x00000800,
    kIOPMSleepFactorDriverAssertBit7        = 0x00001000
};

bool IOPMrootDomain::evaluateSystemSleepPolicy( IOPMSystemSleepParameters * p )
{
    const IOPMSystemSleepPolicyTable * pt;
    OSObject *  prop = 0;
    OSData *    policyData;
    uint32_t    currentFactors;
    uint32_t    deepSleepDelay = 0;
    bool        success = false;

    if (getProperty(kIOPMDeepSleepEnabledKey) != kOSBooleanTrue)
        return false;

    getSleepOption(kIOPMDeepSleepDelayKey, &deepSleepDelay);

    prop = getServiceRoot()->copyProperty(kIOPlatformSystemSleepPolicyKey);
    if (!prop)
        return false;

    policyData = OSDynamicCast(OSData, prop);
    if (!policyData ||
        (policyData->getLength() < sizeof(IOPMSystemSleepPolicyTable)))
    {
        goto done;
    }

    pt = (const IOPMSystemSleepPolicyTable *) policyData->getBytesNoCopy();
    if ((pt->signature[0] != 'S') ||
        (pt->signature[1] != 'L') ||
        (pt->signature[2] != 'P') ||
        (pt->signature[3] != 'T') ||
        (pt->version      != 1)   ||
        (pt->entryCount   == 0))
    {
        goto done;
    }

    if ((policyData->getLength() - sizeof(IOPMSystemSleepPolicyTable)) !=
        (sizeof(IOPMSystemSleepPolicyEntry) * pt->entryCount))
    {
        goto done;
    }

    currentFactors = 0;
    if (getPMAssertionLevel(kIOPMDriverAssertionUSBExternalDeviceBit) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorUSBExternalDevice;
    if (getPMAssertionLevel(kIOPMDriverAssertionBluetoothHIDDevicePairedBit) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorBluetoothHIDDevice;
    if (getPMAssertionLevel(kIOPMDriverAssertionExternalMediaMountedBit) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorExternalMediaMounted;
    if (getPMAssertionLevel(kIOPMDriverAssertionReservedBit5) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorDriverAssertBit5;
    if (getPMAssertionLevel(kIOPMDriverAssertionReservedBit6) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorDriverAssertBit6;
    if (getPMAssertionLevel(kIOPMDriverAssertionReservedBit7) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorDriverAssertBit7;
    if (0 == deepSleepDelay)
        currentFactors |= kIOPMSleepFactorDeepSleepNoDelay;
    if (!clamshellIsClosed)
        currentFactors |= kIOPMSleepFactorLidOpen;
    if (acAdaptorConnected)
        currentFactors |= kIOPMSleepFactorACPower;
    if (lowBatteryCondition)
        currentFactors |= kIOPMSleepFactorLowBattery;
    if (sleepTimerMaintenance)
        currentFactors |= kIOPMSleepFactorSleepTimerWake;

    // pmset overrides
    if ((hibernateMode & kIOHibernateModeOn) == 0)
        currentFactors |= kIOPMSleepFactorDeepSleepDisable;
    else if ((hibernateMode & kIOHibernateModeSleep) == 0)
        currentFactors |= kIOPMSleepFactorDeepSleepDemand;
    
    DLOG("Sleep policy %u entries, current factors 0x%x\n",
        pt->entryCount, currentFactors);

    for (uint32_t i = 0; i < pt->entryCount; i++)
    {
        const IOPMSystemSleepPolicyEntry * policyEntry = &pt->entries[i];

        DLOG("factor mask 0x%08x, bits 0x%08x, flags 0x%08x, wake 0x%08x\n",
            policyEntry->factorMask, policyEntry->factorBits,
            policyEntry->sleepFlags, policyEntry->wakeEvents);

        if ((currentFactors ^ policyEntry->factorBits) & policyEntry->factorMask)
            continue;   // mismatch, try next

        if (p)
        {
            p->version    = 1;
            p->sleepFlags = policyEntry->sleepFlags;
            p->sleepTimer = 0;
            p->wakeEvents = policyEntry->wakeEvents;
            if (p->sleepFlags & kIOPMSleepFlagSleepTimerEnable)
            {
                p->sleepTimer = deepSleepDelay;
            }
        }

        DLOG("matched policy entry %u\n", i);
        success = true;
        break;
    }

done:
    if (prop)
        prop->release();

    return success;
}

void IOPMrootDomain::evaluateSystemSleepPolicyEarly( void )
{
    IOPMSystemSleepParameters   params;

    // Evaluate sleep policy before driver sleep phase.

    DLOG("%s\n", __FUNCTION__);
    removeProperty(kIOPMSystemSleepParametersKey);

    hibernateDisabled = false;
    hibernateMode = 0;
    getSleepOption(kIOHibernateModeKey, &hibernateMode);

    if (!hibernateNoDefeat &&
        evaluateSystemSleepPolicy(&params) &&
        ((params.sleepFlags & kIOPMSleepFlagHibernate) == 0))
    {
        hibernateDisabled = true;
    }
}

void IOPMrootDomain::evaluateSystemSleepPolicyFinal( void )
{
    IOPMSystemSleepParameters   params;
    OSData *                    paramsData;

    // Evaluate sleep policy after drivers but before platform sleep.

    DLOG("%s\n", __FUNCTION__);

    if (evaluateSystemSleepPolicy(&params))
    {
        if ((hibernateDisabled || hibernateAborted) &&
            (params.sleepFlags & kIOPMSleepFlagHibernate))
        {
            // Should hibernate but unable to or aborted.
            // Arm timer for a short sleep and retry or wake fully.

            params.sleepFlags &= ~kIOPMSleepFlagHibernate;
            params.sleepFlags |= kIOPMSleepFlagSleepTimerEnable;
            params.sleepTimer = 1;
            hibernateNoDefeat = true;
            DLOG("wake in %u secs for hibernateDisabled %d, hibernateAborted %d\n",
                        params.sleepTimer, hibernateDisabled, hibernateAborted);
        }
        else
            hibernateNoDefeat = false;

        paramsData = OSData::withBytes(&params, sizeof(params));
        if (paramsData)
        {
            setProperty(kIOPMSystemSleepParametersKey, paramsData);
            paramsData->release();
        }

        if (params.sleepFlags & kIOPMSleepFlagHibernate)
        {
            // Force hibernate
            gIOHibernateMode &= ~kIOHibernateModeSleep;
        }
    }
}

bool IOPMrootDomain::getHibernateSettings(
    uint32_t *  hibernateMode,
    uint32_t *  hibernateFreeRatio,
    uint32_t *  hibernateFreeTime )
{
    bool ok = getSleepOption(kIOHibernateModeKey, hibernateMode);
    getSleepOption(kIOHibernateFreeRatioKey, hibernateFreeRatio);
    getSleepOption(kIOHibernateFreeTimeKey, hibernateFreeTime);
    if (hibernateDisabled)
        *hibernateMode = 0;
    DLOG("hibernateMode 0x%x\n", *hibernateMode);
    return ok;
}

bool IOPMrootDomain::getSleepOption( const char * key, uint32_t * option )
{
    OSObject *      optionsProp;
    OSDictionary *  optionsDict;
    OSObject *      obj = 0;
    OSNumber *      num;
    bool            ok = false;

    optionsProp = copyProperty(kRootDomainSleepOptionsKey);
    optionsDict = OSDynamicCast(OSDictionary, optionsProp);
    
    if (optionsDict)
    {
        obj = optionsDict->getObject(key);
        if (obj) obj->retain();
    }
    if (!obj)
    {
        obj = copyProperty(key);
    }
    if (obj && (num = OSDynamicCast(OSNumber, obj)))
    {
        *option = num->unsigned32BitValue();
        ok = true;
    }

    if (obj)
        obj->release();
    if (optionsProp)
        optionsProp->release();

    return true;
}
#endif /* HIBERNATION */


//******************************************************************************
// dispatchPowerEvent
//
// IOPMPowerStateQueue callback function. Running on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::dispatchPowerEvent(
    uint32_t event, void * arg0, uint64_t arg1 )
{
    DLOG("power event %u args %p 0x%llx\n", event, arg0, arg1);
    ASSERT_GATED();

    switch (event)
    {
        case kPowerEventFeatureChanged:
            messageClients(kIOPMMessageFeatureChange, this);
            break;

        case kPowerEventReceivedPowerNotification:
            handlePowerNotification( (UInt32)(uintptr_t) arg0 );
            break;
        
        case kPowerEventSystemBootCompleted:
            if (systemBooting)
            {
                systemBooting = false;
                adjustPowerState();

                // If lid is closed, re-send lid closed notification
                // now that booting is complete.
                if( clamshellIsClosed )
                {
                    handlePowerNotification(kLocalEvalClamshellCommand);
                }
            }
            break;
        
        case kPowerEventSystemShutdown:
            if (kOSBooleanTrue == (OSBoolean *) arg0)
            {
                /* We set systemShutdown = true during shutdown
                   to prevent sleep at unexpected times while loginwindow is trying
                   to shutdown apps and while the OS is trying to transition to
                   complete power of.
                   
                   Set to true during shutdown, as soon as loginwindow shows
                   the "shutdown countdown dialog", through individual app
                   termination, and through black screen kernel shutdown.
                 */
                LOG("systemShutdown true\n");
                systemShutdown = true;
            } else {
                /*
                 A shutdown was initiated, but then the shutdown
                 was cancelled, clearing systemShutdown to false here.
                */
                LOG("systemShutdown false\n");
                systemShutdown = false;            
            }
            break;

        case kPowerEventUserDisabledSleep:
            userDisabledAllSleep = (kOSBooleanTrue == (OSBoolean *) arg0);
            break;

#if ROOT_DOMAIN_RUN_STATES
        case kPowerEventConfigdRegisteredInterest:
            if (gConfigdNotifier)
            {
                gConfigdNotifier->release();
                gConfigdNotifier = 0;
            }
            if (arg0)
            {
                gConfigdNotifier = (IONotifier *) arg0;
            }
            break;
#endif

        case kPowerEventAggressivenessChanged:
            aggressivenessChanged();
            break;

        case kPowerEventAssertionCreate:
            if (pmAssertions) {
                pmAssertions->handleCreateAssertion((OSData *)arg0);
            }
            break;

        case kPowerEventAssertionRelease:
            if (pmAssertions) {
                pmAssertions->handleReleaseAssertion(arg1);
            }
            break;

        case kPowerEventAssertionSetLevel:
            if (pmAssertions) {
                pmAssertions->handleSetAssertionLevel(arg1, (IOPMDriverAssertionLevel)(uintptr_t)arg0);
            }
            break;
    }
}


//******************************************************************************
// systemPowerEventOccurred
//
// The power controller is notifying us of a hardware-related power management
// event that we must handle. 
//
// systemPowerEventOccurred covers the same functionality that
// receivePowerNotification does; it simply provides a richer API for conveying
// more information.
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
// event that we must handle. This may be a result of an 'environment' interrupt
// from the power mgt micro.
//******************************************************************************

IOReturn IOPMrootDomain::receivePowerNotification( UInt32 msg )
{
    pmPowerStateQueue->submitPowerEvent(
        kPowerEventReceivedPowerNotification, (void *) msg );
    return kIOReturnSuccess;
}

void IOPMrootDomain::handlePowerNotification( UInt32 msg )
{
    bool        eval_clamshell = false;

    ASSERT_GATED();

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
        LOG("PowerManagement emergency overtemp signal. Going to sleep!");
        privateSleepSystem (kIOPMSleepReasonThermalEmergency);
    }

#ifdef __ppc__
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
#endif

    /*
     * Sleep Now!
     */
    if (msg & kIOPMSleepNow) 
    {
        privateSleepSystem (kIOPMSleepReasonSoftware);
    }
    
    /*
     * Power Emergency
     */
    if (msg & kIOPMPowerEmergency) 
    {
        lowBatteryCondition = true;
        privateSleepSystem (kIOPMSleepReasonLowPower);
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

        bool aborting =  ((lastSleepReason == kIOPMSleepReasonClamshell)
                       || (lastSleepReason == kIOPMSleepReasonIdle) 
                       || (lastSleepReason == kIOPMSleepReasonMaintenance));
        if (aborting) userActivityCount++;
        DLOG("clamshell tickled %d lastSleepReason %d\n", userActivityCount, lastSleepReason);
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
        acAdaptorConnected = (0 != (msg & kIOPMSetValue));
        msg &= ~(kIOPMSetACAdaptorConnected | kIOPMSetValue);

        // Tell CPU PM
        informCPUStateChange(kInformAC, !acAdaptorConnected);

        // Tell BSD if AC is connected
        //      0 == external power source; 1 == on battery
        post_sys_powersource(acAdaptorConnected ? 0:1);

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
        privateSleepSystem (kIOPMSleepReasonClamshell);
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
#ifndef __LP64__
            // yes, tell the tree we're waking
            systemWake();
#endif
            // wake the Display Wrangler
            reportUserInput();
        }
        else {
            OSString *pbs = OSString::withCString("DisablePowerButtonSleep");
            // Check that power button sleep is enabled
            if( pbs ) {
                if( kOSBooleanTrue != getProperty(pbs))
                privateSleepSystem (kIOPMSleepReasonPowerButton);
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
#ifndef __LP64__
            // yes, tell the tree we're waking
            systemWake();
#endif
            adjustPowerState();
            // wake the Display Wrangler
            reportUserInput();
        } else {
            adjustPowerState();
            // make sure we have power to clamp
            patriarch->wakeSystem();
        }
    }
}


//******************************************************************************
// getSleepSupported
//
//******************************************************************************

IOOptionBits IOPMrootDomain::getSleepSupported( void )
{
    return( platformSleepSupport );
}


//******************************************************************************
// setSleepSupported
//
//******************************************************************************

void IOPMrootDomain::setSleepSupported( IOOptionBits flags )
{
    DLOG("setSleepSupported(%x)\n", (uint32_t) flags);
    OSBitOrAtomic(flags, &platformSleepSupport);
}


//******************************************************************************
// requestPowerDomainState
//
// The root domain intercepts this call to the superclass.
// Called on the PM work loop thread.
//
// If the clamp bit is not set in the desire, then the child doesn't need the power
// state it's requesting; it just wants it. The root ignores desires but not needs.
// If the clamp bit is not set, the root takes it that the child can tolerate no
// power and interprets the request accordingly. If all children can thus tolerate
// no power, we are on our way to idle sleep.
//******************************************************************************

IOReturn IOPMrootDomain::requestPowerDomainState (
    IOPMPowerFlags      desiredFlags,
    IOPowerConnection * whichChild,
    unsigned long       specification )
{
    OSIterator          *iter;
    OSObject            *next;
    IOPowerConnection   *connection;
    IOPMPowerFlags      powerRequestFlag = 0;
    IOPMPowerFlags      editedDesire;

    ASSERT_GATED();

    if (kIOLogPMRootDomain & gIOKitDebug)
    {
        IOService * powerChild =
            (IOService *) whichChild->getChildEntry(gIOPowerPlane);
        DLOG("child %p, flags %lx, spec %lx - %s\n",
            powerChild, desiredFlags, specification,
            powerChild ? powerChild->getName() : "?");
    }

    // Force the child's input power requirements to 0 unless the prevent
    // idle-sleep flag is set. No input power flags map to our state 0.
    // Our power clamp (deviceDesire) keeps the minimum power state at 2.

    if (desiredFlags & kIOPMPreventIdleSleep)
        editedDesire = kIOPMPreventIdleSleep | kIOPMPowerOn;
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

                if (connection == whichChild) 
                {
                    // OR in the child's input power requirements.
                    powerRequestFlag |= editedDesire;

                    if ( desiredFlags & kIOPMPreventSystemSleep )
                        sleepIsSupported = false;
                }
                else
                {
                    if (kIOLogPMRootDomain & gIOKitDebug)
                    {
                        IOService * powerChild =
                            (IOService *) connection->getChildEntry(gIOPowerPlane);
                        DLOG("child %p, state %ld, noIdle %d, noSleep %d - %s\n",
                            powerChild,
                            connection->getDesiredDomainState(),
                            connection->getPreventIdleSleepFlag(),
                            connection->getPreventSystemSleepFlag(),
                            powerChild ? powerChild->getName() : "?");
                    }

                    // OR in the child's desired power state (0 or ON_STATE).
                    powerRequestFlag |= connection->getDesiredDomainState();

                    if ( connection->getPreventSystemSleepFlag() )
                        sleepIsSupported = false;
                }
            }
        }
        iter->release();
    }

    DLOG("childPowerFlags 0x%lx, extraSleepDelay %ld\n",
        powerRequestFlag, extraSleepDelay);

    if ( !powerRequestFlag && !systemBooting ) 
    {
        if (!wrangler)
        {
            sleepASAP = false;
            changePowerStateToPriv(ON_STATE);
            if (idleSeconds)
            {
                // stay awake for at least idleSeconds
                startIdleSleepTimer(idleSeconds);        
            }
        }
        else if (!extraSleepDelay && !idleSleepTimerPending)
        {
            sleepASAP = true;
        }
    }

    // Drop our power clamp to SLEEP_STATE when all children became idle,
    // and the system sleep and display sleep values are equal.

    adjustPowerState();

    // If our power clamp has already dropped to SLEEP_STATE, and no child
    // is keeping us at ON_STATE, then this will trigger idle sleep.

    editedDesire |= (desiredFlags & kIOPMPreventSystemSleep);

    return super::requestPowerDomainState(
        editedDesire, whichChild, specification);
}


//******************************************************************************
// handlePlatformHaltRestart
//
//******************************************************************************

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
			KLOG("%s handler %p took %u ms\n",
				(ctx->MessageType == kIOMessageSystemWillPowerOff) ?
					"PowerOff" : "Restart",
				notifier->handler, (uint32_t) deltaTime );
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
        case kPEUPSDelayHaltCPU:
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

    // For UPS shutdown leave File Server Mode intact, otherwise turn it off.
    if (kPEUPSDelayHaltCPU != pe_type)
    {
        const OSSymbol * setting = OSSymbol::withCString(kIOPMSettingRestartOnPowerLossKey);
        OSNumber * num = OSNumber::withNumber((unsigned long long) 0, 32);
        if (setting && num)
        {
            setPMSetting(setting, num);
            setting->release();
            num->release();
        }
    }

	// Notify in power tree order
	notifySystemShutdown(this, ctx.MessageType);

	deltaTime = computeDeltaTimeMS(&startTime);
	KLOG("%s all drivers took %u ms\n",
		(ctx.MessageType == kIOMessageSystemWillPowerOff) ?
			"PowerOff" : "Restart",
		(uint32_t) deltaTime );
}


//******************************************************************************
// registerInterest
//
//******************************************************************************

IONotifier * IOPMrootDomain::registerInterest(
                const OSSymbol * typeOfInterest,
                IOServiceInterestHandler handler,
                void * target, void * ref )
{
    IONotifier *    notifier;
    bool            isConfigd;

    isConfigd = typeOfInterest &&
                typeOfInterest->isEqualTo(kIOPMPrivilegedPowerInterest);

    if (isConfigd)
        typeOfInterest = gIOAppPowerStateInterest;

    notifier = super::registerInterest(typeOfInterest, handler, target, ref);

#if ROOT_DOMAIN_RUN_STATES
    if (isConfigd && notifier && pmPowerStateQueue)
    {
        notifier->retain();
        if (pmPowerStateQueue->submitPowerEvent(
                kPowerEventConfigdRegisteredInterest, notifier) == false)
            notifier->release();
    }
#endif

    return notifier;
}

static bool clientMessageFilter( OSObject * object, void * arg )
{
#if ROOT_DOMAIN_RUN_STATES
#if LOG_INTEREST_CLIENTS
    IOPMInterestContext * context = (IOPMInterestContext *) arg;
#endif
    bool    allow = false;

    switch (gMessageClientType)
    {
        case kMessageClientNone:
            allow = false;
            break;
        
        case kMessageClientAll:
            allow = true;
            break;

        case kMessageClientConfigd:
            allow = ((object == (OSObject *) gConfigdNotifier) ||
                     (object == (OSObject *) gSysPowerDownNotifier));
            break;
    }

#if LOG_INTEREST_CLIENTS
    if (allow)
        DLOG("system message %x to %p\n",
            context->msgType, object);
#endif

    return allow;
#else
    return true;
#endif
}


//******************************************************************************
// tellChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//******************************************************************************

bool IOPMrootDomain::tellChangeDown( unsigned long stateNum )
{
    bool    done;

    DLOG("tellChangeDown %u->%u, R-state %u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum, runStateIndex);

    switch ( stateNum ) {
        case DOZE_STATE:
        case SLEEP_STATE:

            if (!ignoreChangeDown)
            {
                userActivityAtSleep = userActivityCount;
                hibernateAborted = false;
                DLOG("tellChangeDown::userActivityAtSleep %d\n", userActivityAtSleep);

                // Direct callout into OSKext so it can disable kext unloads
                // during sleep/wake to prevent deadlocks.
                OSKextSystemSleepOrWake( kIOMessageSystemWillSleep );

                if ( (SLEEP_STATE == stateNum) && sleepSupportedPEFunction )
                {
                    // Reset PCI prevent sleep flag before calling platform driver.
                    OSBitAndAtomic(~kPCICantSleep, &platformSleepSupport);

                    // Skip PCI check for maintenance sleep.
                    if ((runStateFlags & kRStateFlagSuppressPCICheck) == 0)
                    {
                        // Determine if the machine supports sleep, or must doze.
                        getPlatform()->callPlatformFunction(
                                        sleepSupportedPEFunction, false,
                                        NULL, NULL, NULL, NULL);
                    }

                    // If the machine only supports doze, the callPlatformFunction call
                    // boils down to IOPMrootDomain::setSleepSupported(kPCICantSleep), 
                    // otherwise nothing.
                }

                // Notify platform that sleep has begun
                getPlatform()->callPlatformFunction(
                                sleepMessagePEFunction, false,
                                (void *)(uintptr_t) kIOMessageSystemWillSleep,
                                NULL, NULL, NULL);

                // Update canSleep and kIOSleepSupportedKey property so drivers
                // can tell if platform is going to sleep versus doze. 

#if CONFIG_SLEEP
                canSleep = true;
#else
                canSleep = false;
#endif
                if (!sleepIsSupported)
                    canSleep = false;
                if (platformSleepSupport & kPCICantSleep)
                    canSleep = false;
                setProperty(kIOSleepSupportedKey, canSleep);
                DLOG("canSleep %d\n", canSleep);

                // Publish the new sleep-wake UUID
                publishSleepWakeUUID(true);

                // Two change downs are sent by IOServicePM. Ignore the 2nd.
                ignoreChangeDown = true;
                
                tracePoint( kIOPMTracePointSystemSleepAppsPhase);
            }

            DLOG("kIOMessageSystemWillSleep (%d)\n", gMessageClientType);
            done = super::tellClientsWithResponse(
                    kIOMessageSystemWillSleep, clientMessageFilter);
            break;

        default:
            done = super::tellChangeDown(stateNum);
            break;
    }
    return done;
}


//******************************************************************************
// askChangeDown
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//
// This must be idle sleep since we don't ask during any other power change.
//******************************************************************************

bool IOPMrootDomain::askChangeDown( unsigned long stateNum )
{
    DLOG("askChangeDown %u->%u, R-state %u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum, runStateIndex);
    DLOG("kIOMessageCanSystemSleep (%d)\n", gMessageClientType);

    return super::tellClientsWithResponse(
                    kIOMessageCanSystemSleep,
                    clientMessageFilter);
}


//******************************************************************************
// tellNoChangeDown
//
// Notify registered applications and kernel clients that we are not dropping
// power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//
// This must be a vetoed idle sleep, since no other power change can be vetoed.
//******************************************************************************

void IOPMrootDomain::tellNoChangeDown( unsigned long stateNum )
{
    DLOG("tellNoChangeDown %u->%u, R-state %u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum, runStateIndex);

	// Sleep canceled, clear the sleep trace point.
    tracePoint(kIOPMTracePointSystemUp);

    if (idleSeconds && !wrangler)
    {
        // stay awake for at least idleSeconds
        sleepASAP = false;
        startIdleSleepTimer(idleSeconds);
    }
    DLOG("kIOMessageSystemWillNotSleep (%d)\n", gMessageClientType);
    return tellClients(kIOMessageSystemWillNotSleep, clientMessageFilter);
}


//******************************************************************************
// tellChangeUp
//
// Notify registered applications and kernel clients that we are raising power.
//
// We override the superclass implementation so we can send a different message
// type to the client or application being notified.
//******************************************************************************

void IOPMrootDomain::tellChangeUp( unsigned long stateNum )
{
    OSData *publishPMStats = NULL;

    DLOG("tellChangeUp %u->%u, R-state %u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum, runStateIndex);

    ignoreChangeDown = false;

    if ( stateNum == ON_STATE )
    {
        // Direct callout into OSKext so it can disable kext unloads
        // during sleep/wake to prevent deadlocks.
        OSKextSystemSleepOrWake( kIOMessageSystemHasPoweredOn );

        // Notify platform that sleep was cancelled or resumed.
        getPlatform()->callPlatformFunction(
                        sleepMessagePEFunction, false,
                        (void *)(uintptr_t) kIOMessageSystemHasPoweredOn,
                        NULL, NULL, NULL);

        if (getPowerState() == ON_STATE)
        {
            // this is a quick wake from aborted sleep
            if (idleSeconds && !wrangler)
            {
                // stay awake for at least idleSeconds
                sleepASAP = false;
                startIdleSleepTimer(idleSeconds);
            }
            DLOG("kIOMessageSystemWillPowerOn (%d)\n", gMessageClientType);
            tellClients(kIOMessageSystemWillPowerOn, clientMessageFilter);
        }
#if	HIBERNATION
        else
        {
            IOHibernateSystemPostWake();
        }
#endif
 
        tracePoint(kIOPMTracePointSystemWakeAppsPhase);
        publishPMStats = OSData::withBytes(&pmStats, sizeof(pmStats));
        setProperty(kIOPMSleepStatisticsKey, publishPMStats);
        publishPMStats->release();
        bzero(&pmStats, sizeof(pmStats));

        if (pmStatsAppResponses) 
        {
            setProperty(kIOPMSleepStatisticsAppsKey, pmStatsAppResponses);
            pmStatsAppResponses->release();
            pmStatsAppResponses = OSArray::withCapacity(5);
        }
        
        DLOG("kIOMessageSystemHasPoweredOn (%d)\n", gMessageClientType);
        tellClients(kIOMessageSystemHasPoweredOn, clientMessageFilter);

        tracePoint(kIOPMTracePointSystemUp);
    }
}


//******************************************************************************
// reportUserInput
//
//******************************************************************************

void IOPMrootDomain::reportUserInput( void )
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


//******************************************************************************
// setQuickSpinDownTimeout
//
//******************************************************************************

void IOPMrootDomain::setQuickSpinDownTimeout( void )
{
    ASSERT_GATED();
    setAggressiveness(
        kPMMinutesToSpinDown, 0, kAggressivesOptionQuickSpindownEnable );
}


//******************************************************************************
// restoreUserSpinDownTimeout
//
//******************************************************************************

void IOPMrootDomain::restoreUserSpinDownTimeout( void )
{
    ASSERT_GATED();
    setAggressiveness(
        kPMMinutesToSpinDown, 0, kAggressivesOptionQuickSpindownDisable );
}


//******************************************************************************
// changePowerStateTo & changePowerStateToPriv
//
// Override of these methods for logging purposes.
//******************************************************************************

IOReturn IOPMrootDomain::changePowerStateTo( unsigned long ordinal )
{
    return kIOReturnUnsupported;    // ignored
}

IOReturn IOPMrootDomain::changePowerStateToPriv( unsigned long ordinal )
{
    DLOG("changePowerStateToPriv(%lu)\n", ordinal);

	if ( (getPowerState() == DOZE_STATE) && (ordinal != ON_STATE) )
	{
		return kIOReturnSuccess;
	}

    if ( (userDisabledAllSleep || systemBooting || systemShutdown) &&
         (ordinal == SLEEP_STATE) )
    {
        DLOG("SLEEP rejected, forced to ON state (UD %d, SB %d, SS %d)\n",
            userDisabledAllSleep, systemBooting, systemShutdown);

        super::changePowerStateToPriv(ON_STATE);
    }

    return super::changePowerStateToPriv(ordinal);
}

//******************************************************************************
// activity detect
//
//******************************************************************************

bool IOPMrootDomain::activitySinceSleep(void)
{
    return (userActivityCount != userActivityAtSleep);
}

bool IOPMrootDomain::abortHibernation(void)
{
    bool ret = activitySinceSleep();

    if (ret && !hibernateAborted)
    {
        DLOG("activitySinceSleep ABORT [%d, %d]\n", userActivityCount, userActivityAtSleep);
        hibernateAborted = true;
    }
    return (ret);
}

extern "C" int
hibernate_should_abort(void)
{
    if (gRootDomain)
        return (gRootDomain->abortHibernation());
    else
        return (0);
}

//******************************************************************************
// updateRunState
//
//******************************************************************************

void IOPMrootDomain::updateRunState( uint32_t inRunState )
{
#if ROOT_DOMAIN_RUN_STATES
    if (inRunState < kRStateCount)
    {
        runStateIndex = nextRunStateIndex = inRunState;
        runStateFlags = gRStateFlags[inRunState];

        setProperty(
            kIOPMRootDomainRunStateKey,
            (unsigned long long) inRunState, 32);
    }
#endif
}


#if ROOT_DOMAIN_RUN_STATES
//******************************************************************************
// tagPowerPlaneService
//
// Running on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::tagPowerPlaneService(
        IOService * service,
        uint32_t *  rdFlags )
{
    *rdFlags = 0;

    if (service->getProperty("IOPMStrictTreeOrder") ||
        service->metaCast("IODisplayWrangler") ||
        OSDynamicCast(OSNumber,
            service->getProperty("IOPMUnattendedWakePowerState")))
    {
        *rdFlags |= kServiceFlagGraphics;
        DLOG("tagged device %s %x\n", service->getName(), *rdFlags);
    }

    // Locate the first PCI host bridge.
    if (!pciHostBridgeDevice && service->metaCast("IOPCIBridge"))
    {
        IOService * provider = service->getProvider();
        if (OSDynamicCast(IOPlatformDevice, provider) &&
            provider->inPlane(gIODTPlane))
        {
            pciHostBridgeDevice = provider;
            DLOG("PMTrace found PCI host bridge %s->%s\n",
                provider->getName(), service->getName());
        }
    }

    // Tag top-level PCI devices. The order of PMinit() call does not
	// change across boots and is used as the PCI bit number.
    if (pciHostBridgeDevice && service->metaCast("IOPCIDevice"))
    {
        // Would prefer to check built-in property, but tagPowerPlaneService()
        // is called before pciDevice->registerService().
        IORegistryEntry * parent = service->getParentEntry(gIODTPlane);
        if ((parent == pciHostBridgeDevice) && service->getProperty("acpi-device"))
        {
            int bit = pmTracer->recordTopLevelPCIDevice( service );
            if (bit >= 0)
            {
				// Save the assigned bit for fast lookup.
                bit &= 0xff;
                *rdFlags |= (kServiceFlagTopLevelPCI | (bit << 8));
            }
        }
    }
}


//******************************************************************************
// handleActivityTickleForService
//
// Called by IOService::activityTickle() for a tickle that is requesting the
// service to raise power state. Called from driver thread.
//******************************************************************************

void IOPMrootDomain::handleActivityTickleForService( IOService * service, 
                                                     unsigned long type,
                                                     unsigned long currentPowerState,
                                                     uint32_t activityTickleCount )
{
    if ((service == wrangler) 
)
    {
        bool aborting = ((lastSleepReason == kIOPMSleepReasonIdle) 
                       || (lastSleepReason == kIOPMSleepReasonMaintenance));
        if (aborting) userActivityCount++;
        DLOG("display wrangler tickled1 %d lastSleepReason %d\n", userActivityCount, lastSleepReason);
    }

    // Tickle directed to IODisplayWrangler while graphics is disabled.
    // Bring graphics online.

    if ((!currentPowerState) &&
        (service == wrangler) &&
        (runStateIndex > kRStateNormal) &&
        (false == wranglerTickled) &&
        (false == lowBatteryCondition))
    {
        DLOG("display wrangler tickled\n");
        if (kIOLogPMRootDomain & gIOKitDebug)
            OSReportWithBacktrace("Display Tickle");
        wranglerTickled = true;
        synchronizePowerTree();
    }
}

//******************************************************************************
// handlePowerChangeStartForService
//
// Running on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::handlePowerChangeStartForService(
        IOService *     service,
        uint32_t *      rdFlags,
        uint32_t        newPowerState,
        uint32_t        changeFlags )
{
    if (service == this)
    {
        uint32_t currentPowerState = (uint32_t) getPowerState();
        uint32_t nextRunStateFlags;

        assert(nextRunStateIndex < kRStateCount);
        nextRunStateFlags = gRStateFlags[nextRunStateIndex];

        gMessageClientType = kMessageClientNone;

        // Transition towards or away from ON power state.

        if ((currentPowerState != newPowerState) &&
            ((ON_STATE == newPowerState) || (ON_STATE == currentPowerState)))
        {
            if ((runStateFlags & kRStateFlagSuppressMessages) == 0)
                gMessageClientType = kMessageClientAll;
            else
                gMessageClientType = kMessageClientConfigd;
        }

        // Transition caused by deassertion of system notification suppression.

        if ((ON_STATE == newPowerState) &&
            (ON_STATE == currentPowerState) &&
            ((runStateFlags ^ nextRunStateFlags) & kRStateFlagSuppressMessages))
        {
            gMessageClientType = kMessageClientAll;
        }

        if (ON_STATE == newPowerState)
        {
            DLOG("kIOMessageSystemWillPowerOn (%d)\n",
                gMessageClientType);
            tellClients(kIOMessageSystemWillPowerOn, clientMessageFilter);
        }
        
        if (SLEEP_STATE == newPowerState)
        {
            tracePoint(kIOPMTracePointSleepStarted);
        }
    }
    
    if (*rdFlags & kServiceFlagTopLevelPCI)
    {
        pmTracer->tracePCIPowerChange(
			PMTraceWorker::kPowerChangeStart,
			service, changeFlags,
            (*rdFlags >> 8) & 0xff);
    }
}


//******************************************************************************
// handlePowerChangeDoneForService
//
// Running on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::handlePowerChangeDoneForService(
        IOService *     service,
        uint32_t *      rdFlags,
        uint32_t        newPowerState,
        uint32_t        changeFlags )
{
    if (*rdFlags & kServiceFlagTopLevelPCI)
    {
        pmTracer->tracePCIPowerChange(
			PMTraceWorker::kPowerChangeCompleted,
            service, changeFlags,
            (*rdFlags >> 8) & 0xff);
    }
}


//******************************************************************************
// overridePowerStateForService
//
// Runs on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::overridePowerStateForService(
        IOService *     service,
        uint32_t *      rdFlags,
        unsigned long * powerState,
        uint32_t        changeFlags )
{
    uint32_t inPowerState = (uint32_t) *powerState;

    if ((service == this) && (inPowerState == ON_STATE) &&
        (changeFlags & kIOPMSynchronize))
    {
        DLOG("sync root domain %u->%u\n",
            (uint32_t) getPowerState(), inPowerState);

        // Root Domain is in a reduced R-state, and a HID tickle has
        // requested a PM tree sync. Begin R-state transition.

        if (runStateIndex != kRStateNormal)
        {
            sleepTimerMaintenance = false;
            hibernateNoDefeat = false;
            nextRunStateIndex = kRStateNormal;
            setProperty(
                kIOPMRootDomainRunStateKey,
                (unsigned long long) kRStateNormal, 32);            
        }
    }

    if (*rdFlags & kServiceFlagGraphics)
    {
        DLOG("graphics device %s %u->%u (flags 0x%x)\n",
            service->getName(), (uint32_t) service->getPowerState(),
            inPowerState, changeFlags);

        if (inPowerState == 0)
        {
            // Graphics device is powering down, apply limit preventing
            // device from powering back up later unless we consent.

            if ((*rdFlags & kServiceFlagNoPowerUp) == 0)
            {
                *rdFlags |= kServiceFlagNoPowerUp;
                DLOG("asserted power limit for %s\n",
                    service->getName());
            }
        }
        else
        {
            uint32_t nextRunStateFlags;

            assert(nextRunStateIndex < kRStateCount);
            nextRunStateFlags = gRStateFlags[nextRunStateIndex];
        
            // Graphics device is powering up. Release power limit at the
            // did-change machine state.

            if (changeFlags & kIOPMSynchronize)
            {
                if ((runStateFlags & kRStateFlagSuppressGraphics) &&
                    ((nextRunStateFlags & kRStateFlagSuppressGraphics) == 0) &&
                    (changeFlags & kIOPMDomainDidChange))
                {
                    // Woke up without graphics power, but
                    // HID event has tickled display wrangler.
                    *rdFlags &= ~kServiceFlagNoPowerUp;
                    DLOG("removed power limit for %s\n",
                        service->getName());
                }
            }
            else if ((runStateFlags & kRStateFlagSuppressGraphics) == 0)
            {
                *rdFlags &= ~kServiceFlagNoPowerUp;
            }

            if (*rdFlags & kServiceFlagNoPowerUp)
            {
                DLOG("limited %s to power state 0\n",
                    service->getName());
                *powerState = 0;
            }
        }
    }
}


//******************************************************************************
// setMaintenanceWakeCalendar
//
//******************************************************************************

IOReturn IOPMrootDomain::setMaintenanceWakeCalendar(
    const IOPMCalendarStruct * calendar )
{
    OSData * data;
    IOReturn ret;

    if (!calendar)
        return kIOReturnBadArgument;
    
    data = OSData::withBytesNoCopy((void *) calendar, sizeof(*calendar));
    if (!data)
        return kIOReturnNoMemory;
    
    ret = setPMSetting(gIOPMSettingMaintenanceWakeCalendarKey, data);

    data->release();
    return ret;
}
#endif /* ROOT_DOMAIN_RUN_STATES */


//******************************************************************************
// sysPowerDownHandler
//
// Receives a notification when the RootDomain changes state. 
//
// Allows us to take action on system sleep, power down, and restart after
// applications have received their power change notifications and replied,
// but before drivers have powered down. We perform a vfs sync on power down.
//******************************************************************************

IOReturn IOPMrootDomain::sysPowerDownHandler( void * target, void * refCon,
                                    UInt32 messageType, IOService * service,
                                    void * messageArgument, vm_size_t argSize )
{
    IOReturn                             ret;
    IOPowerStateChangeNotification      *params = (IOPowerStateChangeNotification *) messageArgument;
    IOPMrootDomain                      *rootDomain = OSDynamicCast(IOPMrootDomain, service);

    DLOG("sysPowerDownHandler message %x\n", (uint32_t) messageType);

    if(!rootDomain)
        return kIOReturnUnsupported;

    switch (messageType) {
        case kIOMessageSystemWillSleep:
            // Interested applications have been notified of an impending power
            // change and have acked (when applicable).
            // This is our chance to save whatever state we can before powering
            // down.
            // We call sync_internal defined in xnu/bsd/vfs/vfs_syscalls.c,
            // via callout
#if	HIBERNATION
            rootDomain->evaluateSystemSleepPolicyEarly();
            if (rootDomain->hibernateMode && !rootDomain->hibernateDisabled)
            {
                // We will ack within 240 seconds
                params->returnValue = 240 * 1000 * 1000;
            }
            else
#endif
            // We will ack within 20 seconds
            params->returnValue = 20 * 1000 * 1000;
            DLOG("sysPowerDownHandler timeout %d s\n", (int) (params->returnValue / 1000 / 1000));
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

//******************************************************************************
// publishSleepWakeUUID
//
// 
//******************************************************************************
void IOPMrootDomain::publishSleepWakeUUID( bool shouldPublish )
{
    if (shouldPublish) 
    {
        if (queuedSleepWakeUUIDString) 
        {
            if (OSCompareAndSwap(/*old*/ true, /*new*/ false, &gSleepWakeUUIDIsSet))
            {
                // Upon wake, it takes some time for userland to invalidate the
                // UUID. If another sleep is initiated during that period, force
                // a CLEAR message to balance the upcoming SET message.

                messageClients( kIOPMMessageSleepWakeUUIDChange,
                                kIOPMMessageSleepWakeUUIDCleared );

                DLOG("SleepWake UUID forced clear\n");
            }

            setProperty(kIOPMSleepWakeUUIDKey, queuedSleepWakeUUIDString);
            DLOG("SleepWake UUID published: %s\n", queuedSleepWakeUUIDString->getCStringNoCopy());
            queuedSleepWakeUUIDString->release();
            queuedSleepWakeUUIDString = NULL;
            messageClients(kIOPMMessageSleepWakeUUIDChange, 
                            kIOPMMessageSleepWakeUUIDSet);
        }
    } else {
        if (OSCompareAndSwap(/*old*/ true, /*new*/ false, &gSleepWakeUUIDIsSet))
        {
            DLOG("SleepWake UUID cleared\n");
            removeProperty(kIOPMSleepWakeUUIDKey);
            messageClients(kIOPMMessageSleepWakeUUIDChange, 
                            kIOPMMessageSleepWakeUUIDCleared);        
        }
    }
}


//******************************************************************************
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
//******************************************************************************

IOReturn IOPMrootDomain::displayWranglerNotification(
    void * target, void * refCon,
    UInt32 messageType, IOService * service,
    void * messageArgument, vm_size_t argSize )
{
#if !NO_KERNEL_HID
    int                                 displayPowerState;
    IOPowerStateChangeNotification *    params =
            (IOPowerStateChangeNotification *) messageArgument;

    if ((messageType != kIOMessageDeviceWillPowerOff) &&
        (messageType != kIOMessageDeviceHasPoweredOn))
        return kIOReturnUnsupported;

    ASSERT_GATED();
    if (!gRootDomain)
        return kIOReturnUnsupported;

    displayPowerState = params->stateNumber;
    DLOG("DisplayWrangler message 0x%x, new power state %d\n",
              (uint32_t) messageType, displayPowerState);

    switch (messageType) {
       case kIOMessageDeviceWillPowerOff:

            // The display wrangler has dropped power because of idle display sleep
            // or force system sleep.
            //
            // 4 Display ON
            // 3 Display Dim
            // 2 Display Sleep
            // 1 Not visible to user
            // 0 Not visible to user

            if (gRootDomain->wranglerAsleep || (displayPowerState > 2))
                break;

            // Record the time the display wrangler went to sleep.

            gRootDomain->wranglerAsleep = true;
            clock_get_uptime(&gRootDomain->wranglerSleepTime);

            // We start a timer here if the System Sleep timer is greater than the
            // Display Sleep timer. We kick off this timer when the display sleeps.
            //
            // Note that, although Display Dim timings may change adaptively accordingly
            // to the user's activity patterns, Display Sleep _always_ occurs at the
            // specified interval since last user activity.

            if ( gRootDomain->extraSleepDelay )
            {
                gRootDomain->startIdleSleepTimer(gRootDomain->extraSleepDelay * 60);            
            }
            else if ( gRootDomain->sleepSlider )
            {
                // Accelerate disk spindown if system sleep and display sleep
                // sliders are set to the same value (e.g. both set to 5 min),
                // and display is about to go dark. Check that spin down timer
                // is non-zero (zero = never spin down) and system sleep is
                // not set to never sleep.

                gRootDomain->setQuickSpinDownTimeout();
            }

            break;

        case kIOMessageDeviceHasPoweredOn:

            // The display wrangler has powered on either because of user activity 
            // or wake from sleep/doze.

            if ( 4 != displayPowerState )
                break;

            gRootDomain->wranglerAsleep = false;
            gRootDomain->adjustPowerState();
            gRootDomain->cancelIdleSleepTimer();

            // Change the spindown value back to the user's selection from our
            // accelerated setting.
            gRootDomain->restoreUserSpinDownTimeout();

            break;

         default:
             break;
     }
#endif
     return kIOReturnUnsupported;
}


//******************************************************************************
// displayWranglerPublished
//
// Receives a notification when the IODisplayWrangler is published.
// When it's published we install a power state change handler.
//******************************************************************************

bool IOPMrootDomain::displayWranglerPublished( 
    void * target, 
    void * refCon,
    IOService * newService)
{
#if !NO_KERNEL_HID
    if(!gRootDomain)
        return false;

    gRootDomain->wrangler = newService;

    // we found the display wrangler, now install a handler
    if( !gRootDomain->wrangler->registerInterest( gIOGeneralInterest, 
                            &displayWranglerNotification, target, 0) ) 
    {
        return false;
    }
#endif
    return true;
}


//******************************************************************************
// batteryPublished
//
// Notification on battery class IOPowerSource appearance
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


//******************************************************************************
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
// If the above conditions do not exist, and also the sleep timer has expired,
// we allow sleep or doze to occur with either changePowerStateToPriv(SLEEP) or
// changePowerStateToPriv(DOZE) depending on whether or not we already know the
// platform cannot sleep.
//
// In this case, sleep or doze will either occur immediately or at the next time
// that no children are holding the system out of idle sleep via the 
// kIOPMPreventIdleSleep flag in their power state arrays.
//******************************************************************************

void IOPMrootDomain::adjustPowerState( void )
{
    DLOG("adjustPowerState "
        "PS %u, ASAP %d, SL %ld, AS %d, SB %d, SS %d, UD %d\n",
        (uint32_t) getPowerState(), sleepASAP, sleepSlider,
        allowSleep, systemBooting, systemShutdown, userDisabledAllSleep);

    ASSERT_GATED();

    if ( (sleepSlider == 0) 
        || !allowSleep 
        || systemBooting 
        || systemShutdown
        || userDisabledAllSleep
        || (runStateFlags & kRStateFlagDisableIdleSleep) )
    {
        changePowerStateToPriv(ON_STATE);
    } else {
        if ( sleepASAP ) 
        {
            /* Convenient place to run any code at idle sleep time
             * IOPMrootDomain initiates an idle sleep here
             *
             * Set last sleep cause accordingly.
             */
            lastSleepReason = kIOPMSleepReasonIdle;
            setProperty(kRootDomainSleepReasonKey, kIOPMIdleSleepKey);

            sleepASAP = false;
            changePowerStateToPriv(SLEEP_STATE);
        }
    }
}

void IOPMrootDomain::pmStatsRecordEvent(
    int                 eventIndex,
    AbsoluteTime        timestamp)
{
    bool        starting = eventIndex & kIOPMStatsEventStartFlag ? true:false;
    bool        stopping = eventIndex & kIOPMStatsEventStopFlag ? true:false;
    uint64_t    delta;
    uint64_t    nsec;

    eventIndex &= ~(kIOPMStatsEventStartFlag | kIOPMStatsEventStopFlag);

    absolutetime_to_nanoseconds(timestamp, &nsec);

    switch (eventIndex) {
        case kIOPMStatsHibernateImageWrite:
            if (starting)
                pmStats.hibWrite.start = nsec;
            else if (stopping)
                pmStats.hibWrite.stop = nsec;

            if (stopping) {
                delta = pmStats.hibWrite.stop - pmStats.hibWrite.start;
                IOLog("PMStats: Hibernate write took %qd ms\n", delta/1000000ULL);
            }
            break;
        case kIOPMStatsHibernateImageRead:
            if (starting)
                pmStats.hibRead.start = nsec;
            else if (stopping)
                pmStats.hibRead.stop = nsec;

            if (stopping) {
                delta = pmStats.hibRead.stop - pmStats.hibRead.start;
                IOLog("PMStats: Hibernate read took %qd ms\n", delta/1000000ULL);
            }
            break;
    }
}

/*
 * Appends a record of the application response to
 * IOPMrootDomain::pmStatsAppResponses
 */
void IOPMrootDomain::pmStatsRecordApplicationResponse(
	const OSSymbol		*response,
	const char          *name,
	int                 messageType,
    uint32_t            delay_ms,
    int                 app_pid)
{
    OSDictionary    *responseDescription    = NULL;
    OSNumber        *delayNum               = NULL;
    OSNumber        *pidNum                 = NULL;
    OSNumber        *msgNum                 = NULL;
    const OSSymbol  *appname;
    const OSSymbol  *entryName;
    OSObject        *entryType;
    int             i;

    if (!pmStatsAppResponses || pmStatsAppResponses->getCount() > 50)
        return;

    i = 0;
    while ((responseDescription = (OSDictionary *) pmStatsAppResponses->getObject(i++)))
    {
        entryType = responseDescription->getObject(_statsResponseTypeKey);
        entryName = (OSSymbol *) responseDescription->getObject(_statsNameKey);
        if (entryName && (entryType == response) && entryName->isEqualTo(name))
        {
            OSNumber * entryValue;
            entryValue = (OSNumber *) responseDescription->getObject(_statsTimeMSKey);
            if (entryValue && (entryValue->unsigned32BitValue() < delay_ms))
                entryValue->setValue(delay_ms);
            return;
        }
    }

    responseDescription = OSDictionary::withCapacity(5);
    if (responseDescription) 
    {
        if (response) {
            responseDescription->setObject(_statsResponseTypeKey, response);
        }
        
        if (messageType != 0) {
            msgNum = OSNumber::withNumber(messageType, 32);
            if (msgNum) {
                responseDescription->setObject(_statsMessageTypeKey, msgNum);
                msgNum->release();
            }
        }

        if (name && (strlen(name) > 0))
        {
            appname = OSSymbol::withCString(name);
            if (appname) {
                responseDescription->setObject(_statsNameKey, appname);
                appname->release();
            }
        }

        if (app_pid != -1) {
            pidNum = OSNumber::withNumber(app_pid, 32);
            if (pidNum) {
                responseDescription->setObject(_statsPIDKey, pidNum);
                pidNum->release();
            }
        }

        delayNum = OSNumber::withNumber(delay_ms, 32);
        if (delayNum) {
            responseDescription->setObject(_statsTimeMSKey, delayNum);
            delayNum->release();
        }

        if (pmStatsAppResponses) {
            pmStatsAppResponses->setObject(responseDescription);
        }

        responseDescription->release();
    }
    return;
}


//******************************************************************************
// TracePoint support
//
//******************************************************************************

#define kIOPMRegisterNVRAMTracePointHandlerKey	\
		"IOPMRegisterNVRAMTracePointHandler"

IOReturn IOPMrootDomain::callPlatformFunction(
    const OSSymbol * functionName,
    bool waitForFunction,
    void * param1, void * param2,
    void * param3, void * param4 )
{
    if (pmTracer && functionName &&
        functionName->isEqualTo(kIOPMRegisterNVRAMTracePointHandlerKey) &&
        !pmTracer->tracePointHandler && !pmTracer->tracePointTarget)
    {
        uint32_t    tracePointPhases, tracePointPCI;
		uint64_t	statusCode;

        pmTracer->tracePointHandler = (IOPMTracePointHandler) param1;
        pmTracer->tracePointTarget  = (void *) param2;
        tracePointPCI				= (uint32_t)(uintptr_t) param3;
        tracePointPhases			= (uint32_t)(uintptr_t) param4;
        statusCode = (((uint64_t)tracePointPCI) << 32) | tracePointPhases;
		if ((tracePointPhases >> 24) != kIOPMTracePointSystemUp)
        {
            LOG("Sleep failure code 0x%08x 0x%08x\n",
                tracePointPCI, tracePointPhases);
        }
		setProperty(kIOPMSleepWakeFailureCodeKey, statusCode, 64);
        pmTracer->tracePointHandler( pmTracer->tracePointTarget, 0, 0 );

        return kIOReturnSuccess;
    }

    return super::callPlatformFunction(
        functionName, waitForFunction, param1, param2, param3, param4);
}

void IOPMrootDomain::tracePoint( uint8_t point )
{
    pmTracer->tracePoint(point);
}

//******************************************************************************
// PMTraceWorker Class
//
//******************************************************************************

#undef super
#define super OSObject
OSDefineMetaClassAndStructors(PMTraceWorker, OSObject)

#define kPMBestGuessPCIDevicesCount     25
#define kPMMaxRTCBitfieldSize           32

PMTraceWorker *PMTraceWorker::tracer(IOPMrootDomain *owner)
{
    PMTraceWorker           *me;
    
    me = OSTypeAlloc( PMTraceWorker );
    if (!me || !me->init())
    {
        return NULL;
    }

    DLOG("PMTraceWorker %p\n", me);

    // Note that we cannot instantiate the PCI device -> bit mappings here, since
    // the IODeviceTree has not yet been created by IOPlatformExpert. We create
    // this dictionary lazily.
    me->owner = owner;
    me->pciDeviceBitMappings = NULL;
    me->pciMappingLock = IOLockAlloc();
    me->tracePhase = kIOPMTracePointSystemUp;
    me->loginWindowPhase = 0;
    me->pciBusyBitMask = 0;
    return me;
}

void PMTraceWorker::RTC_TRACE(void)
{
	if (tracePointHandler && tracePointTarget)
	{
		uint32_t    wordA;

		wordA = tracePhase;			// destined for bits 24-31
		wordA <<= 8;
		wordA |= loginWindowPhase;	// destined for bits 16-23
		wordA <<= 16;

        tracePointHandler( tracePointTarget, pciBusyBitMask, wordA );
		DLOG("RTC_TRACE wrote 0x%08x 0x%08x\n", pciBusyBitMask, wordA);
	}
}

int PMTraceWorker::recordTopLevelPCIDevice(IOService * pciDevice)
{
    const OSSymbol *    deviceName;
    int                 index = -1;

    IOLockLock(pciMappingLock);

    if (!pciDeviceBitMappings)
    {
        pciDeviceBitMappings = OSArray::withCapacity(kPMBestGuessPCIDevicesCount);
        if (!pciDeviceBitMappings)
            goto exit;
    }

    // Check for bitmask overflow.
    if (pciDeviceBitMappings->getCount() >= kPMMaxRTCBitfieldSize)
        goto exit;

    if ((deviceName = pciDevice->copyName()) &&
        (pciDeviceBitMappings->getNextIndexOfObject(deviceName, 0) == (unsigned int)-1) &&
        pciDeviceBitMappings->setObject(deviceName))
    {
        index = pciDeviceBitMappings->getCount() - 1;
        DLOG("PMTrace PCI array: set object %s => %d\n",
            deviceName->getCStringNoCopy(), index);
    }
    if (deviceName)
        deviceName->release();
    if (!addedToRegistry && (index >= 0))
        addedToRegistry = owner->setProperty("PCITopLevel", this);

exit:
    IOLockUnlock(pciMappingLock);
    return index;
}

bool PMTraceWorker::serialize(OSSerialize *s) const
{
    bool ok = false;
    if (pciDeviceBitMappings)
    {
        IOLockLock(pciMappingLock);
        ok = pciDeviceBitMappings->serialize(s);
        IOLockUnlock(pciMappingLock);
    }
    return ok;
}

void PMTraceWorker::tracePoint(uint8_t phase)
{
    tracePhase = phase;

    DLOG("IOPMrootDomain: trace point 0x%02x\n", tracePhase);
    RTC_TRACE();
}

void PMTraceWorker::traceLoginWindowPhase(uint8_t phase)
{
    loginWindowPhase = phase;

    DLOG("IOPMrootDomain: loginwindow tracepoint 0x%02x\n", loginWindowPhase);
    RTC_TRACE();
}

void PMTraceWorker::tracePCIPowerChange(
	change_t type, IOService *service, uint32_t changeFlags, uint32_t bitNum)
{
    uint32_t	bitMask;
	uint32_t	expectedFlag;

	// Ignore PCI changes outside of system sleep/wake.
    if ((kIOPMTracePointSystemSleepDriversPhase != tracePhase) &&
        (kIOPMTracePointSystemWakeDriversPhase  != tracePhase))
        return;

	// Only record the WillChange transition when going to sleep,
	// and the DidChange on the way up.
	changeFlags &= (kIOPMDomainWillChange | kIOPMDomainDidChange);
	expectedFlag = (kIOPMTracePointSystemSleepDriversPhase == tracePhase) ?
					kIOPMDomainWillChange : kIOPMDomainDidChange;
	if (changeFlags != expectedFlag)
		return;

    // Mark this device off in our bitfield
    if (bitNum < kPMMaxRTCBitfieldSize)
    {
        bitMask = (1 << bitNum);

        if (kPowerChangeStart == type)
        {
            pciBusyBitMask |= bitMask;
            DLOG("PMTrace: Device %s started  - bit %2d mask 0x%08x => 0x%08x\n",
                service->getName(), bitNum, bitMask, pciBusyBitMask);
        }
        else
        {
            pciBusyBitMask &= ~bitMask;
            DLOG("PMTrace: Device %s finished - bit %2d mask 0x%08x => 0x%08x\n",
                service->getName(), bitNum, bitMask, pciBusyBitMask);
        }

        RTC_TRACE();        
    }
}


//******************************************************************************
// PMHaltWorker Class
//
//******************************************************************************

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

		DLOG("PMHaltWorker %p\n", me);
		me->retain();	// thread holds extra retain
		if (KERN_SUCCESS != kernel_thread_start(&PMHaltWorker::main, (void *) me, &thread))
		{
			me->release();
			break;
		}
		thread_deallocate(thread);
		return me;

	} while (false);

	if (me) me->release();
	return 0;
}

void PMHaltWorker::free( void )
{
	DLOG("PMHaltWorker free %p\n", this);
	if (lock)
	{
		IOLockFree(lock);
		lock = 0;
	}
	return OSObject::free();
}

void PMHaltWorker::main( void * arg, wait_result_t waitResult )
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
	DLOG("All done for worker: %p (visits = %u)\n", me, me->visits);
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
			(gIOKitDebug & (kIOLogDebugPower | kIOLogPMRootDomain)))
		{
			KLOG("%s driver %s (%p) took %u ms\n",
				(gPMHaltEvent == kIOMessageSystemWillPowerOff) ?
					"PowerOff" : "Restart",
				service->getName(), service,
				(uint32_t) deltaTime );
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
			LOG("%s still waiting on %s\n",
				(gPMHaltEvent == kIOMessageSystemWillPowerOff) ?
					"PowerOff" : "Restart",
				me->service->getName());
		}
	}
	IOLockUnlock(me->lock);
}


//******************************************************************************
// acknowledgeSystemWillShutdown
//
// Acknowledgement from drivers that they have prepared for shutdown/restart.
//******************************************************************************

void IOPMrootDomain::acknowledgeSystemWillShutdown( IOService * from )
{
	PMHaltWorker *	worker;
	OSObject *		prop;

	if (!from)
		return;

	//DLOG("%s acknowledged\n", from->getName());
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
		DLOG("%s acknowledged without worker property\n",
			from->getName());
	}
}


//******************************************************************************
// notifySystemShutdown
//
// Notify all objects in PM tree that system will shutdown or restart
//******************************************************************************

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

	DLOG("%s event = %lx\n", __FUNCTION__, event);

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
				DLOG("Skipped PM node %s\n", node->getName());
		}
		iter->release();
	}

	// debug only
	for (int i = 0; (inner = (OSSet *)gPMHaltArray->getObject(i)); i++)
	{
		count = 0;
		if (inner != PLACEHOLDER)
			count = inner->getCount();
		DLOG("Nodes at depth %u = %u\n", i, count);
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

	DLOG("PM nodes = %u, maxDepth = %u, workers = %u\n",
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
	DLOG("%s done\n", __FUNCTION__);
	return;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOPMDriverAssertionID IOPMrootDomain::createPMAssertion(
    IOPMDriverAssertionType whichAssertionBits,
    IOPMDriverAssertionLevel assertionLevel,
    IOService *ownerService,
    const char *ownerDescription)
{
    IOReturn            ret;
    IOPMDriverAssertionID     newAssertion;
 
    if (!pmAssertions)
        return 0;
 
    ret = pmAssertions->createAssertion(whichAssertionBits, assertionLevel, ownerService, ownerDescription, &newAssertion);

    if (kIOReturnSuccess == ret)
        return newAssertion;
    else
        return 0;
}

IOReturn IOPMrootDomain::releasePMAssertion(IOPMDriverAssertionID releaseAssertion)
{
    if (!pmAssertions)
        return kIOReturnInternalError;
    
    return pmAssertions->releaseAssertion(releaseAssertion);
}

IOReturn IOPMrootDomain::setPMAssertionLevel(
    IOPMDriverAssertionID assertionID, 
    IOPMDriverAssertionLevel assertionLevel)
{
    return pmAssertions->setAssertionLevel(assertionID, assertionLevel);
}

IOPMDriverAssertionLevel IOPMrootDomain::getPMAssertionLevel(IOPMDriverAssertionType whichAssertion)
{
    IOPMDriverAssertionType       sysLevels;

    if (!pmAssertions || whichAssertion == 0) 
        return kIOPMDriverAssertionLevelOff;

    sysLevels = pmAssertions->getActivatedAssertions();
    
    // Check that every bit set in argument 'whichAssertion' is asserted
    // in the aggregate bits.
    if ((sysLevels & whichAssertion) == whichAssertion)
        return kIOPMDriverAssertionLevelOn;
    else
        return kIOPMDriverAssertionLevelOff;
}

IOReturn IOPMrootDomain::setPMAssertionUserLevels(IOPMDriverAssertionType inLevels)
{
    if (!pmAssertions)
        return kIOReturnNotFound;

    return pmAssertions->setUserAssertionLevels(inLevels);
}

bool IOPMrootDomain::serializeProperties( OSSerialize * s ) const
{
    if (pmAssertions)
    {
        pmAssertions->publishProperties();
    }
    return( IOService::serializeProperties(s) );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#undef super
#define super OSObject
OSDefineMetaClassAndFinalStructors(PMSettingObject, OSObject)

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

// MARK: -
// MARK: PMAssertionsTracker

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************
// class PMAssertionsTracker Implementation

#define kAssertUniqueIDStart    500

PMAssertionsTracker *PMAssertionsTracker::pmAssertionsTracker( IOPMrootDomain *rootDomain )
{
    PMAssertionsTracker    *myself;
    
    myself = new PMAssertionsTracker;
 
    if (myself) {
        myself->init();
        myself->owner = rootDomain;
        myself->issuingUniqueID = kAssertUniqueIDStart; 
        myself->assertionsArray = OSArray::withCapacity(5);
        myself->assertionsKernel = 0;
        myself->assertionsUser = 0;
        myself->assertionsCombined = 0;
        myself->assertionsArrayLock = IOLockAlloc();
        myself->tabulateProducerCount = myself->tabulateConsumerCount = 0;
    
        if (!myself->assertionsArray || !myself->assertionsArrayLock)
            myself = NULL;
    }

    return myself;
}

/* tabulate
 * - Update assertionsKernel to reflect the state of all
 * assertions in the kernel.
 * - Update assertionsCombined to reflect both kernel & user space.
 */
void PMAssertionsTracker::tabulate(void)
{
    int i;
    int count;
    PMAssertStruct      *_a = NULL;
    OSData              *_d = NULL;

    IOPMDriverAssertionType oldKernel = assertionsKernel;
    IOPMDriverAssertionType oldCombined = assertionsCombined;

    ASSERT_GATED();

    assertionsKernel = 0;
    assertionsCombined = 0;

    if (!assertionsArray)
        return;

    if ((count = assertionsArray->getCount()))
    {
        for (i=0; i<count; i++)
        {
            _d = OSDynamicCast(OSData, assertionsArray->getObject(i));
            if (_d)
            {
                _a = (PMAssertStruct *)_d->getBytesNoCopy();
                if (_a && (kIOPMDriverAssertionLevelOn == _a->level))
                    assertionsKernel |= _a->assertionBits;
            }
        }
    }

    tabulateProducerCount++;
    assertionsCombined = assertionsKernel | assertionsUser;

    if ((assertionsKernel != oldKernel) ||
        (assertionsCombined != oldCombined))
    {
        owner->messageClients(kIOPMMessageDriverAssertionsChanged);
    }
}

void PMAssertionsTracker::publishProperties( void )
{
    OSArray             *assertionsSummary = NULL;

    if (tabulateConsumerCount != tabulateProducerCount)
    {
        IOLockLock(assertionsArrayLock);

        tabulateConsumerCount = tabulateProducerCount;

        /* Publish the IOPMrootDomain property "DriverPMAssertionsDetailed"
         */
        assertionsSummary = copyAssertionsArray();
        if (assertionsSummary)
        {
            owner->setProperty(kIOPMAssertionsDriverDetailedKey, assertionsSummary);
            assertionsSummary->release();
        }
        else
        {
            owner->removeProperty(kIOPMAssertionsDriverDetailedKey);
        }

        /* Publish the IOPMrootDomain property "DriverPMAssertions"
         */
        owner->setProperty(kIOPMAssertionsDriverKey, assertionsKernel, 64);

        IOLockUnlock(assertionsArrayLock);
    }
}

PMAssertionsTracker::PMAssertStruct *PMAssertionsTracker::detailsForID(IOPMDriverAssertionID _id, int *index)
{
    PMAssertStruct      *_a = NULL;
    OSData              *_d = NULL;
    int                 found = -1;
    int                 count = 0;
    int                 i = 0;

    if (assertionsArray
        && (count = assertionsArray->getCount()))
    {
        for (i=0; i<count; i++)
        {
            _d = OSDynamicCast(OSData, assertionsArray->getObject(i));
            if (_d)
            {
                _a = (PMAssertStruct *)_d->getBytesNoCopy();
                if (_a && (_id == _a->id)) {
                    found = i;
                    break;
                }
            }
        }
    }

    if (-1 == found) {
        return NULL;
    } else {
        if (index)
            *index = found;
        return _a;
    }
}

/* PMAssertionsTracker::handleCreateAssertion
 * Perform assertion work on the PM workloop. Do not call directly.
 */
IOReturn PMAssertionsTracker::handleCreateAssertion(OSData *newAssertion)
{
    ASSERT_GATED();

    if (newAssertion)
    {
        IOLockLock(assertionsArrayLock);
        assertionsArray->setObject(newAssertion);
        IOLockUnlock(assertionsArrayLock);
        newAssertion->release();

        tabulate();
    }
    return kIOReturnSuccess;
}

/* PMAssertionsTracker::createAssertion
 * createAssertion allocates memory for a new PM assertion, and affects system behavior, if 
 * appropiate.
 */
IOReturn PMAssertionsTracker::createAssertion(
    IOPMDriverAssertionType which,
    IOPMDriverAssertionLevel level,
    IOService *serviceID, 
    const char *whoItIs, 
    IOPMDriverAssertionID *outID)
{
    OSData          *dataStore = NULL;
    PMAssertStruct  track;

    // Warning: trillions and trillions of created assertions may overflow the unique ID.
#ifdef __ppc__
    track.id = issuingUniqueID++;  // FIXME: need OSIncrementAtomic64() for ppc
#else
    track.id = OSIncrementAtomic64((SInt64*) &issuingUniqueID);
#endif
    track.level = level;
    track.assertionBits = which;
    track.ownerString = whoItIs ? OSSymbol::withCString(whoItIs) : 0;
    track.ownerService = serviceID;
    track.modifiedTime = 0;
    pmEventTimeStamp(&track.createdTime);

    dataStore = OSData::withBytes(&track, sizeof(PMAssertStruct));
    if (!dataStore)
    {
        if (track.ownerString)
            track.ownerString->release();
        return kIOReturnNoMemory;
    }

    *outID = track.id;
    
    if (owner && owner->pmPowerStateQueue) {
        owner->pmPowerStateQueue->submitPowerEvent(kPowerEventAssertionCreate, (void *)dataStore);
    }
    
    return kIOReturnSuccess;
}

/* PMAssertionsTracker::handleReleaseAssertion
 * Runs in PM workloop. Do not call directly.
 */
IOReturn PMAssertionsTracker::handleReleaseAssertion(
    IOPMDriverAssertionID _id)
{
    ASSERT_GATED();

    int             index;
    PMAssertStruct  *assertStruct = detailsForID(_id, &index);
    
    if (!assertStruct)
        return kIOReturnNotFound;

    IOLockLock(assertionsArrayLock);
    if (assertStruct->ownerString) 
        assertStruct->ownerString->release();

    assertionsArray->removeObject(index);
    IOLockUnlock(assertionsArrayLock);
    
    tabulate();
    return kIOReturnSuccess;
}

/* PMAssertionsTracker::releaseAssertion
 * Releases an assertion and affects system behavior if appropiate.
 * Actual work happens on PM workloop.
 */
IOReturn PMAssertionsTracker::releaseAssertion(
    IOPMDriverAssertionID _id)
{
    if (owner && owner->pmPowerStateQueue) {
        owner->pmPowerStateQueue->submitPowerEvent(kPowerEventAssertionRelease, 0, _id);
    }
    return kIOReturnSuccess;
}

/* PMAssertionsTracker::handleSetAssertionLevel
 * Runs in PM workloop. Do not call directly.
 */
IOReturn PMAssertionsTracker::handleSetAssertionLevel(
    IOPMDriverAssertionID    _id, 
    IOPMDriverAssertionLevel _level)
{
    PMAssertStruct      *assertStruct = detailsForID(_id, NULL);

    ASSERT_GATED();

    if (!assertStruct) {
        return kIOReturnNotFound;
    }

    IOLockLock(assertionsArrayLock);
    pmEventTimeStamp(&assertStruct->modifiedTime);
    assertStruct->level = _level;
    IOLockUnlock(assertionsArrayLock);

    tabulate();
    return kIOReturnSuccess;
}

/* PMAssertionsTracker::setAssertionLevel
 */
IOReturn PMAssertionsTracker::setAssertionLevel(
    IOPMDriverAssertionID    _id, 
    IOPMDriverAssertionLevel _level)
{
    if (owner && owner->pmPowerStateQueue) {
        owner->pmPowerStateQueue->submitPowerEvent(kPowerEventAssertionSetLevel,
                (void *)_level, _id);
    }

    return kIOReturnSuccess;    
}

IOReturn PMAssertionsTracker::handleSetUserAssertionLevels(void * arg0)
{
    IOPMDriverAssertionType new_user_levels = *(IOPMDriverAssertionType *) arg0;

    ASSERT_GATED();

    if (new_user_levels != assertionsUser)
    {
        assertionsUser = new_user_levels;
        DLOG("assertionsUser 0x%llx\n", assertionsUser);
    }

    tabulate();
    return kIOReturnSuccess;
}

IOReturn PMAssertionsTracker::setUserAssertionLevels(
    IOPMDriverAssertionType new_user_levels)
{
    if (gIOPMWorkLoop) {
        gIOPMWorkLoop->runAction(
            OSMemberFunctionCast(
                IOWorkLoop::Action,
                this,
                &PMAssertionsTracker::handleSetUserAssertionLevels),
            this,
            (void *) &new_user_levels, 0, 0, 0);
    }

    return kIOReturnSuccess;
}


OSArray *PMAssertionsTracker::copyAssertionsArray(void)
{
    int count;
    int i;
    OSArray     *outArray = NULL;

    if (!assertionsArray ||
        (0 == (count = assertionsArray->getCount())) ||
        (NULL == (outArray = OSArray::withCapacity(count))))
    {
        goto exit;
    }

    for (i=0; i<count; i++)
    {
        PMAssertStruct  *_a = NULL;
        OSData          *_d = NULL;
        OSDictionary    *details = NULL;

        _d = OSDynamicCast(OSData, assertionsArray->getObject(i));
        if (_d && (_a = (PMAssertStruct *)_d->getBytesNoCopy()))
        {
            OSNumber        *_n = NULL;

            details = OSDictionary::withCapacity(7);
            if (!details)
                continue;

            outArray->setObject(details);
            details->release();
            
            _n = OSNumber::withNumber(_a->id, 64);
            if (_n) {            
                details->setObject(kIOPMDriverAssertionIDKey, _n);
                _n->release();
            }
            _n = OSNumber::withNumber(_a->createdTime, 64);
            if (_n) {            
                details->setObject(kIOPMDriverAssertionCreatedTimeKey, _n);
                _n->release();
            }
            _n = OSNumber::withNumber(_a->modifiedTime, 64);
            if (_n) {            
                details->setObject(kIOPMDriverAssertionModifiedTimeKey, _n);
                _n->release();
            }
            _n = OSNumber::withNumber((uintptr_t)_a->ownerService, 64);
            if (_n) {            
                details->setObject(kIOPMDriverAssertionOwnerServiceKey, _n);
                _n->release();
            }
            _n = OSNumber::withNumber(_a->level, 64);
            if (_n) {            
                details->setObject(kIOPMDriverAssertionLevelKey, _n);
                _n->release();
            }
            _n = OSNumber::withNumber(_a->assertionBits, 64);
            if (_n) {            
                details->setObject(kIOPMDriverAssertionAssertedKey, _n);
                _n->release();
            }
            
            if (_a->ownerString) {
                details->setObject(kIOPMDriverAssertionOwnerStringKey, _a->ownerString);
            }
        }
    }

exit:
    return outArray;
}

IOPMDriverAssertionType PMAssertionsTracker::getActivatedAssertions(void)
{
    return assertionsCombined;
}

IOPMDriverAssertionLevel PMAssertionsTracker::getAssertionLevel(
    IOPMDriverAssertionType type)
{
    if (type && ((type & assertionsKernel) == assertionsKernel))
    {
        return kIOPMDriverAssertionLevelOn;
    } else {
        return kIOPMDriverAssertionLevelOff;
    }
}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

static void pmEventTimeStamp(uint64_t *recordTS)
{
    clock_sec_t     tsec;
    clock_usec_t    tusec;

    if (!recordTS)
        return;
    
    // We assume tsec fits into 32 bits; 32 bits holds enough
    // seconds for 136 years since the epoch in 1970.
    clock_get_calendar_microtime(&tsec, &tusec);


    // Pack the sec & microsec calendar time into a uint64_t, for fun.
    *recordTS = 0;
    *recordTS |= (uint32_t)tusec;
    *recordTS |= ((uint64_t)tsec << 32);

    return;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef  super
#define super IOService

OSDefineMetaClassAndFinalStructors(IORootParent, IOService)

// This array exactly parallels the state array for the root domain.
// Power state changes initiated by a device can be vetoed by a client of the device, and
// power state changes initiated by the parent of a device cannot be vetoed by a client of the device,
// so when the root domain wants a power state change that cannot be vetoed (e.g. demand sleep), it asks
// its parent to make the change.  That is the reason for this complexity.

static IOPMPowerState patriarchPowerStates[NUM_POWER_STATES] =
{
    {1,0,0,0,0,0,0,0,0,0,0,0},              // off   (not used)
    {1,0,RESTART_POWER,0,0,0,0,0,0,0,0,0},  // reset (not used)
    {1,0,SLEEP_POWER,0,0,0,0,0,0,0,0,0},    // sleep
    {1,0,DOZE_POWER,0,0,0,0,0,0,0,0,0},     // doze
    {1,0,ON_POWER,0,0,0,0,0,0,0,0,0},       // running
};

bool IORootParent::start( IOService * nub )
{
    mostRecentChange = ON_STATE;
    super::start(nub);
    attachToParent( getRegistryRoot(), gIOPowerPlane );
    PMinit();
    registerPowerDriver(this, patriarchPowerStates, NUM_POWER_STATES);
	wakeSystem();
    powerOverrideOnPriv();	
    return true;
}

void IORootParent::shutDownSystem( void )
{
}

void IORootParent::restartSystem( void )
{
}

void IORootParent::sleepSystem( void )
{
    mostRecentChange = SLEEP_STATE;
    changePowerStateToPriv(SLEEP_STATE);
}

void IORootParent::dozeSystem( void )
{
    mostRecentChange = DOZE_STATE;
    changePowerStateToPriv(DOZE_STATE);
}

// Called in demand sleep when sleep discovered to be impossible after actually attaining that state.
// This brings the parent to doze, which allows the root to step up from sleep to doze.

// In idle sleep, do nothing because the parent is still on and the root can freely change state.

void IORootParent::sleepToDoze( void )
{
    if ( mostRecentChange == SLEEP_STATE ) {
        changePowerStateToPriv(DOZE_STATE);
    }
}

void IORootParent::wakeSystem( void )
{
    mostRecentChange = ON_STATE;
    changePowerStateToPriv(ON_STATE);
}
