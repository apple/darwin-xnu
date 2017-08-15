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
#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOCPU.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/pwr_mgt/IOPMlog.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IONVRAM.h>
#include "RootDomainUserClient.h"
#include "IOKit/pwr_mgt/IOPowerConnection.h"
#include "IOPMPowerStateQueue.h"
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOReportMacros.h>
#include "IOKitKernelInternal.h"
#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <console/video_console.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>

#include <sys/time.h>
#include "IOServicePrivate.h"   // _IOServiceInterestNotifier
#include "IOServicePMPrivate.h"

__BEGIN_DECLS
#include <mach/shared_region.h>
#include <kern/clock.h>
__END_DECLS

#if defined(__i386__) || defined(__x86_64__)
__BEGIN_DECLS
#include "IOPMrootDomainInternal.h"
__END_DECLS
#endif

#define kIOPMrootDomainClass    "IOPMrootDomain"
#define LOG_PREFIX              "PMRD: "


#define MSG(x...) \
    do { kprintf(LOG_PREFIX x); IOLog(x); } while (false)

#define LOG(x...)    \
    do { kprintf(LOG_PREFIX x); } while (false)

#define DLOG(x...)  do { \
    if (kIOLogPMRootDomain & gIOKitDebug) \
        kprintf(LOG_PREFIX x); \
} while (false)

#define DMSG(x...)  do { \
    if (kIOLogPMRootDomain & gIOKitDebug) { \
        kprintf(LOG_PREFIX x); IOLog(x); \
    } \
} while (false)


#define _LOG(x...)

#define CHECK_THREAD_CONTEXT
#ifdef  CHECK_THREAD_CONTEXT
static IOWorkLoop * gIOPMWorkLoop = 0;
#define ASSERT_GATED()                                      \
do {                                                        \
    if (gIOPMWorkLoop && gIOPMWorkLoop->inGate() != true) { \
        panic("RootDomain: not inside PM gate");            \
    }                                                       \
} while(false)
#else
#define ASSERT_GATED()
#endif /* CHECK_THREAD_CONTEXT */

#define CAP_LOSS(c)  \
        (((_pendingCapability & (c)) == 0) && \
         ((_currentCapability & (c)) != 0))

#define CAP_GAIN(c)  \
        (((_currentCapability & (c)) == 0) && \
         ((_pendingCapability & (c)) != 0))

#define CAP_CHANGE(c)    \
        (((_currentCapability ^ _pendingCapability) & (c)) != 0)

#define CAP_CURRENT(c)  \
        ((_currentCapability & (c)) != 0)

#define CAP_HIGHEST(c)  \
        ((_highestCapability & (c)) != 0)

#if defined(__i386__) || defined(__x86_64__)
#define DARK_TO_FULL_EVALUATE_CLAMSHELL     1
#endif

// Event types for IOPMPowerStateQueue::submitPowerEvent()
enum {
    kPowerEventFeatureChanged = 1,              // 1
    kPowerEventReceivedPowerNotification,       // 2
    kPowerEventSystemBootCompleted,             // 3
    kPowerEventSystemShutdown,                  // 4
    kPowerEventUserDisabledSleep,               // 5
    kPowerEventRegisterSystemCapabilityClient,  // 6
    kPowerEventRegisterKernelCapabilityClient,  // 7
    kPowerEventPolicyStimulus,                  // 8
    kPowerEventAssertionCreate,                 // 9
    kPowerEventAssertionRelease,                // 10
    kPowerEventAssertionSetLevel,               // 11
    kPowerEventQueueSleepWakeUUID,              // 12
    kPowerEventPublishSleepWakeUUID,            // 13
    kPowerEventSetDisplayPowerOn                // 14
};

// For evaluatePolicy()
// List of stimuli that affects the root domain policy.
enum {
    kStimulusDisplayWranglerSleep,      // 0
    kStimulusDisplayWranglerWake,       // 1
    kStimulusAggressivenessChanged,     // 2
    kStimulusDemandSystemSleep,         // 3
    kStimulusAllowSystemSleepChanged,   // 4
    kStimulusDarkWakeActivityTickle,    // 5
    kStimulusDarkWakeEntry,             // 6
    kStimulusDarkWakeReentry,           // 7
    kStimulusDarkWakeEvaluate,          // 8
    kStimulusNoIdleSleepPreventers,     // 9
    kStimulusEnterUserActiveState,      // 10
    kStimulusLeaveUserActiveState       // 11
};

extern "C" {
IOReturn OSKextSystemSleepOrWake( UInt32 );
}
extern "C" ppnum_t      pmap_find_phys(pmap_t pmap, addr64_t va);
extern "C" addr64_t     kvtophys(vm_offset_t va);

static void idleSleepTimerExpired( thread_call_param_t, thread_call_param_t );
static void notifySystemShutdown( IOService * root, uint32_t messageType );
static void handleAggressivesFunction( thread_call_param_t, thread_call_param_t );
static void pmEventTimeStamp(uint64_t *recordTS);

// "IOPMSetSleepSupported"  callPlatformFunction name
static const OSSymbol *sleepSupportedPEFunction = NULL;
static const OSSymbol *sleepMessagePEFunction   = NULL;

#define kIOSleepSupportedKey        "IOSleepSupported"
#define kIOPMSystemCapabilitiesKey  "System Capabilities"

#define kIORequestWranglerIdleKey   "IORequestIdle"
#define kDefaultWranglerIdlePeriod  25 // in milliseconds

#define kIOSleepWakeDebugKey        "Persistent-memory-note"
#define kIOEFIBootRomFailureKey     "wake-failure"

#define kRD_AllPowerSources (kIOPMSupportedOnAC \
                           | kIOPMSupportedOnBatt \
                           | kIOPMSupportedOnUPS)

#define kLocalEvalClamshellCommand  (1 << 15)
#define kIdleSleepRetryInterval     (3 * 60)

enum {
    kWranglerPowerStateMin   = 0,
    kWranglerPowerStateSleep = 2,
    kWranglerPowerStateDim   = 3,
    kWranglerPowerStateMax   = 4
};

enum {
    OFF_STATE           = 0,
    RESTART_STATE       = 1,
    SLEEP_STATE         = 2,
    ON_STATE            = 3,
    NUM_POWER_STATES
};

#define ON_POWER        kIOPMPowerOn
#define RESTART_POWER   kIOPMRestart
#define SLEEP_POWER     kIOPMAuxPowerOn

static IOPMPowerState ourPowerStates[NUM_POWER_STATES] =
{
    {1, 0,                      0,              0,             0,0,0,0,0,0,0,0},
    {1, kIOPMRestartCapability, kIOPMRestart,   RESTART_POWER, 0,0,0,0,0,0,0,0},
    {1, kIOPMSleepCapability,   kIOPMSleep,     SLEEP_POWER,   0,0,0,0,0,0,0,0},
    {1, kIOPMPowerOn,           kIOPMPowerOn,   ON_POWER,      0,0,0,0,0,0,0,0}
};

#define kIOPMRootDomainWakeTypeSleepService     "SleepService"
#define kIOPMRootDomainWakeTypeMaintenance      "Maintenance"
#define kIOPMRootDomainWakeTypeSleepTimer       "SleepTimer"
#define kIOPMrootDomainWakeTypeLowBattery       "LowBattery"
#define kIOPMRootDomainWakeTypeUser             "User"
#define kIOPMRootDomainWakeTypeAlarm            "Alarm"
#define kIOPMRootDomainWakeTypeNetwork          "Network"
#define kIOPMRootDomainWakeTypeHIDActivity      "HID Activity"
#define kIOPMRootDomainWakeTypeNotification     "Notification"
#define kIOPMRootDomainWakeTypeHibernateError   "HibernateError"

// Special interest that entitles the interested client from receiving
// all system messages. Only used by powerd.
//
#define kIOPMSystemCapabilityInterest       "IOPMSystemCapabilityInterest"

#define WAKEEVENT_LOCK()        IOLockLock(wakeEventLock)
#define WAKEEVENT_UNLOCK()      IOLockUnlock(wakeEventLock)

/*
 * Aggressiveness
 */
#define AGGRESSIVES_LOCK()      IOLockLock(featuresDictLock)
#define AGGRESSIVES_UNLOCK()    IOLockUnlock(featuresDictLock)

#define kAggressivesMinValue    1

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

// gDarkWakeFlags
enum {
    kDarkWakeFlagHIDTickleEarly      = 0x01, // hid tickle before gfx suppression
    kDarkWakeFlagHIDTickleLate       = 0x02, // hid tickle after gfx suppression
    kDarkWakeFlagHIDTickleNone       = 0x03, // hid tickle is not posted
    kDarkWakeFlagHIDTickleMask       = 0x03,
    kDarkWakeFlagAlarmIsDark         = 0x0100,
    kDarkWakeFlagGraphicsPowerState1 = 0x0200,
    kDarkWakeFlagAudioNotSuppressed  = 0x0400
};

static IOPMrootDomain * gRootDomain;
static IONotifier *     gSysPowerDownNotifier = 0;
static UInt32           gSleepOrShutdownPending = 0;
static UInt32           gWillShutdown = 0;
static UInt32           gPagingOff = 0;
static UInt32           gSleepWakeUUIDIsSet = false;
static uint32_t         gAggressivesState = 0;

uuid_string_t bootsessionuuid_string;

static uint32_t         gDarkWakeFlags = kDarkWakeFlagHIDTickleNone;
static uint32_t         gNoIdleFlag = 0;
static PMStatsStruct    gPMStats;

#if HIBERNATION
static IOPMSystemSleepPolicyHandler     gSleepPolicyHandler = 0;
static IOPMSystemSleepPolicyVariables * gSleepPolicyVars = 0;
static void *                           gSleepPolicyTarget;
#endif

struct timeval gIOLastSleepTime;
struct timeval gIOLastWakeTime;

static char gWakeReasonString[128];
static bool gWakeReasonSysctlRegistered = false;
static AbsoluteTime gIOLastWakeAbsTime;
static AbsoluteTime gIOLastSleepAbsTime;

#if defined(__i386__) || defined(__x86_64__)
static bool gSpinDumpBufferFull = false;
#endif

static unsigned int     gPMHaltBusyCount;
static unsigned int     gPMHaltIdleCount;
static int              gPMHaltDepth;
static uint32_t         gPMHaltMessageType;
static IOLock *         gPMHaltLock  = 0;
static OSArray *        gPMHaltArray = 0;
static const OSSymbol * gPMHaltClientAcknowledgeKey = 0;
static bool             gPMQuiesced;

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
const OSSymbol *gIOPMStatsApplicationResponsePrompt;
const OSSymbol *gIOPMStatsDriverPSChangeSlow;

#define kBadPMFeatureID     0

/*
 * PMSettingHandle
 * Opaque handle passed to clients of registerPMSettingController()
 */
class PMSettingHandle : public OSObject
{
    OSDeclareFinalStructors( PMSettingHandle )
    friend class PMSettingObject;

private:
    PMSettingObject *pmso;
    void free(void) APPLE_KEXT_OVERRIDE;
};

/*
 * PMSettingObject
 * Internal object to track each PM setting controller
 */
class PMSettingObject : public OSObject
{
    OSDeclareFinalStructors( PMSettingObject )
    friend class IOPMrootDomain;

private:
    queue_head_t                    calloutQueue;
    thread_t                        waitThread;
    IOPMrootDomain                  *parent;
    PMSettingHandle                 *pmsh;
    IOPMSettingControllerCallback   func;
    OSObject                        *target;
    uintptr_t                       refcon;
    uint32_t                        *publishedFeatureID;
    uint32_t                        settingCount;
    bool                            disabled;

    void free(void) APPLE_KEXT_OVERRIDE;

public:
    static PMSettingObject *pmSettingObject(
                IOPMrootDomain                  *parent_arg,
                IOPMSettingControllerCallback   handler_arg,
                OSObject                        *target_arg,
                uintptr_t                       refcon_arg,
                uint32_t                        supportedPowerSources,
                const OSSymbol                  *settings[],
                OSObject                        **handle_obj);

    void dispatchPMSetting(const OSSymbol *type, OSObject *object);
    void clientHandleFreed(void);
};

struct PMSettingCallEntry {
    queue_chain_t   link;
    thread_t        thread;
};

#define PMSETTING_LOCK()    IOLockLock(settingsCtrlLock)
#define PMSETTING_UNLOCK()  IOLockUnlock(settingsCtrlLock)
#define PMSETTING_WAIT(p)   IOLockSleep(settingsCtrlLock, p, THREAD_UNINT)
#define PMSETTING_WAKEUP(p) IOLockWakeup(settingsCtrlLock, p, true)

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
    void                        traceDetail(uint32_t detail);
    void                        traceComponentWakeProgress(uint32_t component, uint32_t data);
    int                         recordTopLevelPCIDevice(IOService *);
    void                        RTC_TRACE(void);
    virtual bool                serialize(OSSerialize *s) const APPLE_KEXT_OVERRIDE;

    IOPMTracePointHandler       tracePointHandler;
    void *                      tracePointTarget;
    uint64_t                    getPMStatusCode();
    uint8_t                     getTracePhase();
    uint32_t                    getTraceData();
private:
    IOPMrootDomain              *owner;
    IOLock                      *pmTraceWorkerLock;
    OSArray                     *pciDeviceBitMappings;

    uint8_t                     addedToRegistry;
    uint8_t                     tracePhase;
    uint32_t                    traceData32;
    uint8_t                     loginWindowData;
    uint8_t                     coreDisplayData;
    uint8_t                     coreGraphicsData;
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
        uint64_t                    registryEntryID;
        IOPMDriverAssertionLevel    level;
    } PMAssertStruct;

    uint32_t                    tabulateProducerCount;
    uint32_t                    tabulateConsumerCount;

    PMAssertStruct              *detailsForID(IOPMDriverAssertionID, int *);
    void                        tabulate(void);

    IOPMrootDomain              *owner;
    OSArray                     *assertionsArray;
    IOLock                      *assertionsArrayLock;
    IOPMDriverAssertionID       issuingUniqueID __attribute__((aligned(8))); /* aligned for atomic access */
    IOPMDriverAssertionType     assertionsKernel;
    IOPMDriverAssertionType     assertionsUser;
    IOPMDriverAssertionType     assertionsCombined;
};

OSDefineMetaClassAndFinalStructors(PMAssertionsTracker, OSObject);

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
    virtual void free( void ) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndFinalStructors( PMHaltWorker, OSObject )


#define super IOService
OSDefineMetaClassAndFinalStructors(IOPMrootDomain, IOService)

static void IOPMRootDomainWillShutdown(void)
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

    void IOSystemShutdownNotification(void)
    {
        IOPMRootDomainWillShutdown();
#if HIBERNATION
        IOHibernateSystemPostWake();
#endif
        if (OSCompareAndSwap(0, 1, &gPagingOff))
        {
            gRootDomain->handlePlatformHaltRestart(kPEPagingOff);
        }
    }

    int sync_internal(void);
}

/*
A device is always in the highest power state which satisfies its driver,
its policy-maker, and any power children it has, but within the constraint
of the power state provided by its parent.  The driver expresses its desire by
calling changePowerStateTo(), the policy-maker expresses its desire by calling
changePowerStateToPriv(), and the children express their desires by calling
requestPowerDomainState().

The Root Power Domain owns the policy for idle and demand sleep for the system.
It is a power-managed IOService just like the others in the system.
It implements several power states which map to what we see as Sleep and On.

The sleep policy is as follows:
1. Sleep is prevented if the case is open so that nobody will think the machine
   is off and plug/unplug cards.
2. Sleep is prevented if the sleep timeout slider in the prefs panel is zero.
3. System cannot Sleep if some object in the tree is in a power state marked
   kIOPMPreventSystemSleep.

These three conditions are enforced using the "driver clamp" by calling
changePowerStateTo(). For example, if the case is opened,
changePowerStateTo(ON_STATE) is called to hold the system on regardless
of the desires of the children of the root or the state of the other clamp.

Demand Sleep is initiated by pressing the front panel power button, closing
the clamshell, or selecting the menu item. In this case the root's parent
actually initiates the power state change so that the root domain has no
choice and does not give applications the opportunity to veto the change.

Idle Sleep occurs if no objects in the tree are in a state marked
kIOPMPreventIdleSleep.  When this is true, the root's children are not holding
the root on, so it sets the "policy-maker clamp" by calling
changePowerStateToPriv(ON_STATE) to hold itself on until the sleep timer expires.
This timer is set for the difference between the sleep timeout slider and the
display dim timeout slider. When the timer expires, it releases its clamp and
now nothing is holding it awake, so it falls asleep.

Demand sleep is prevented when the system is booting.  When preferences are
transmitted by the loginwindow at the end of boot, a flag is cleared,
and this allows subsequent Demand Sleep.
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
// updateConsoleUsersCallout
//
//******************************************************************************

static void updateConsoleUsersCallout(thread_call_param_t p0, thread_call_param_t p1)
{
    IOPMrootDomain * rootDomain = (IOPMrootDomain *) p0;
    rootDomain->updateConsoleUsers();
}

void IOPMrootDomain::updateConsoleUsers(void)
{
    IOService::updateConsoleUsers(NULL, kIOMessageSystemHasPoweredOn);
    if (tasksSuspended)
    {
        tasksSuspended = FALSE;
        tasks_system_suspend(tasksSuspended);
    }
}

//******************************************************************************

static void swdDebugSetupCallout( thread_call_param_t p0, thread_call_param_t p1 )
{
    IOPMrootDomain * rootDomain = (IOPMrootDomain *) p0;
    uint32_t    notifyRef  = (uint32_t)(uintptr_t) p1;

    rootDomain->swdDebugSetup();

    if (p1) {
        rootDomain->allowPowerChange(notifyRef);
    }
    DLOG("swdDebugSetupCallout finish\n");
}

void IOPMrootDomain::swdDebugSetup( )
{
#if	HIBERNATION
    static int32_t mem_only = -1;
    if ((mem_only == -1) &&
        (PE_parse_boot_argn("swd_mem_only", &mem_only, sizeof(mem_only)) == false)) {
        mem_only = 0;
    }

   if ((mem_only == 1) || (gRootDomain->sleepWakeDebugIsWdogEnabled() == false)) {
       return;
   }
    DLOG("swdDebugSetup state:%d\n", swd_DebugImageSetup);
    if (swd_DebugImageSetup == FALSE) {
        swd_DebugImageSetup = TRUE;
        if (CAP_GAIN(kIOPMSystemCapabilityGraphics) ||
                (CAP_LOSS(kIOPMSystemCapabilityGraphics))) {
            IOHibernateSystemPostWakeTrim((void*)1, NULL);
        }
        IOOpenDebugDataFile(kSleepWakeStackBinFilename, SWD_BUF_SIZE);
    }
#endif


}

static void swdDebugTeardownCallout( thread_call_param_t p0, thread_call_param_t p1 )
{
    IOPMrootDomain * rootDomain = (IOPMrootDomain *) p0;
    uint32_t    notifyRef  = (uint32_t)(uintptr_t) p1;

    rootDomain->swdDebugTeardown();
    if (p1) {
        rootDomain->allowPowerChange(notifyRef);
    }
    DLOG("swdDebugTeardownCallout finish\n");
}

void IOPMrootDomain::swdDebugTeardown( )
{

#if	HIBERNATION
    DLOG("swdDebugTeardown state:%d\n", swd_DebugImageSetup);
    if (swd_DebugImageSetup == TRUE) {
        swd_DebugImageSetup = FALSE;
        IOCloseDebugDataFile();
    }
#endif


}
//******************************************************************************


static void disk_sync_callout( thread_call_param_t p0, thread_call_param_t p1 )
{
    IOService * rootDomain = (IOService *) p0;
    uint32_t    notifyRef  = (uint32_t)(uintptr_t) p1;
    uint32_t    powerState = rootDomain->getPowerState();

    DLOG("disk_sync_callout ps=%u\n", powerState);

    if (ON_STATE == powerState)
    {
        sync_internal();
        swdDebugSetupCallout(p0, NULL);
    }
#if HIBERNATION
    else
    {
        swdDebugTeardownCallout(p0, NULL);
        IOHibernateSystemPostWake();

        if (gRootDomain)
            gRootDomain->sleepWakeDebugSaveSpinDumpFile();
    }
#endif

    rootDomain->allowPowerChange(notifyRef);
    DLOG("disk_sync_callout finish\n");
}

//******************************************************************************
static UInt32 computeDeltaTimeMS( const AbsoluteTime * startTime )
{
    AbsoluteTime    endTime;
    UInt64          nano = 0;

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
        CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        &gIOLastSleepTime, 0, sysctl_sleepwaketime, "S,timeval", "");

static SYSCTL_PROC(_kern, OID_AUTO, waketime,
        CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        &gIOLastWakeTime, 0, sysctl_sleepwaketime, "S,timeval", "");

SYSCTL_QUAD(_kern, OID_AUTO, wake_abs_time, CTLFLAG_RD|CTLFLAG_LOCKED, &gIOLastWakeAbsTime, "");
SYSCTL_QUAD(_kern, OID_AUTO, sleep_abs_time, CTLFLAG_RD|CTLFLAG_LOCKED, &gIOLastSleepAbsTime, "");

static int
sysctl_willshutdown
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int new_value, changed;
    int error = sysctl_io_number(req, gWillShutdown, sizeof(int), &new_value, &changed);
    if (changed) {
    if (!gWillShutdown && (new_value == 1)) {
        IOPMRootDomainWillShutdown();
    } else
        error = EINVAL;
    }
    return(error);
}

static SYSCTL_PROC(_kern, OID_AUTO, willshutdown,
        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        0, 0, sysctl_willshutdown, "I", "");

extern struct sysctl_oid sysctl__kern_iokittest;


static int
sysctl_progressmeterenable
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int error;
    int new_value, changed;

    error = sysctl_io_number(req, vc_progressmeter_enable, sizeof(int), &new_value, &changed);

    if (changed) vc_enable_progressmeter(new_value);

    return (error);
}

static int
sysctl_progressmeter
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int error;
    int new_value, changed;

    error = sysctl_io_number(req, vc_progressmeter_value, sizeof(int), &new_value, &changed);

    if (changed) vc_set_progressmeter(new_value);

    return (error);
}

static SYSCTL_PROC(_kern, OID_AUTO, progressmeterenable,
        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        0, 0, sysctl_progressmeterenable, "I", "");

static SYSCTL_PROC(_kern, OID_AUTO, progressmeter,
        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        0, 0, sysctl_progressmeter, "I", "");




static int
sysctl_consoleoptions
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int error, changed;
    uint32_t new_value;

    error = sysctl_io_number(req, vc_user_options.options, sizeof(uint32_t), &new_value, &changed);

    if (changed) vc_user_options.options = new_value;

    return (error);
}

static SYSCTL_PROC(_kern, OID_AUTO, consoleoptions,
        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        0, 0, sysctl_consoleoptions, "I", "");


static int
sysctl_progressoptions SYSCTL_HANDLER_ARGS
{
    return sysctl_io_opaque(req, &vc_user_options, sizeof(vc_user_options), NULL);
}

static SYSCTL_PROC(_kern, OID_AUTO, progressoptions,
        CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
        NULL, 0, sysctl_progressoptions, "S,vc_progress_user_options", "");


static int
sysctl_wakereason SYSCTL_HANDLER_ARGS
{
    char wr[ sizeof(gWakeReasonString) ];

    wr[0] = '\0';
    if (gRootDomain)
        gRootDomain->copyWakeReasonString(wr, sizeof(wr));

    return sysctl_io_string(req, wr, 0, 0, NULL);
}

SYSCTL_PROC(_kern, OID_AUTO, wakereason,
    CTLTYPE_STRING| CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_wakereason, "A", "wakereason");

static int
sysctl_targettype SYSCTL_HANDLER_ARGS
{
    IOService * root;
    OSObject *  obj;
    OSData *    data;
    char        tt[32];

    tt[0] = '\0';
    root = IOService::getServiceRoot();
    if (root && (obj = root->copyProperty(gIODTTargetTypeKey)))
    {
	if ((data = OSDynamicCast(OSData, obj)))
	{
	    strlcpy(tt, (const char *) data->getBytesNoCopy(), sizeof(tt));
	}
	obj->release();
    }
    return sysctl_io_string(req, tt, 0, 0, NULL);
}

SYSCTL_PROC(_hw, OID_AUTO, targettype,
    CTLTYPE_STRING| CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_targettype, "A", "targettype");

static SYSCTL_INT(_debug, OID_AUTO, darkwake, CTLFLAG_RW, &gDarkWakeFlags, 0, "");
static SYSCTL_INT(_debug, OID_AUTO, noidle, CTLFLAG_RW, &gNoIdleFlag, 0, "");

static const OSSymbol * gIOPMSettingAutoWakeCalendarKey;
static const OSSymbol * gIOPMSettingAutoWakeSecondsKey;
static const OSSymbol * gIOPMSettingDebugWakeRelativeKey;
static const OSSymbol * gIOPMSettingMaintenanceWakeCalendarKey;
static const OSSymbol * gIOPMSettingSleepServiceWakeCalendarKey;
static const OSSymbol * gIOPMSettingSilentRunningKey;
static const OSSymbol * gIOPMUserTriggeredFullWakeKey;
static const OSSymbol * gIOPMUserIsActiveKey;

//******************************************************************************
// start
//
//******************************************************************************

#define kRootDomainSettingsCount        17

bool IOPMrootDomain::start( IOService * nub )
{
    OSIterator      *psIterator;
    OSDictionary    *tmpDict;
    IORootParent *   patriarch;
#if defined(__i386__) || defined(__x86_64__)
    IONotifier   *   notifier;
#endif

    super::start(nub);

    gRootDomain = this;
    gIOPMSettingAutoWakeCalendarKey = OSSymbol::withCString(kIOPMSettingAutoWakeCalendarKey);
    gIOPMSettingAutoWakeSecondsKey = OSSymbol::withCString(kIOPMSettingAutoWakeSecondsKey);
    gIOPMSettingDebugWakeRelativeKey = OSSymbol::withCString(kIOPMSettingDebugWakeRelativeKey);
    gIOPMSettingMaintenanceWakeCalendarKey = OSSymbol::withCString(kIOPMSettingMaintenanceWakeCalendarKey);
    gIOPMSettingSleepServiceWakeCalendarKey = OSSymbol::withCString(kIOPMSettingSleepServiceWakeCalendarKey);
    gIOPMSettingSilentRunningKey = OSSymbol::withCStringNoCopy(kIOPMSettingSilentRunningKey);
    gIOPMUserTriggeredFullWakeKey = OSSymbol::withCStringNoCopy(kIOPMUserTriggeredFullWakeKey);
    gIOPMUserIsActiveKey = OSSymbol::withCStringNoCopy(kIOPMUserIsActiveKey);

    gIOPMStatsApplicationResponseTimedOut = OSSymbol::withCString(kIOPMStatsResponseTimedOut);
    gIOPMStatsApplicationResponseCancel = OSSymbol::withCString(kIOPMStatsResponseCancel);
    gIOPMStatsApplicationResponseSlow = OSSymbol::withCString(kIOPMStatsResponseSlow);
    gIOPMStatsApplicationResponsePrompt = OSSymbol::withCString(kIOPMStatsResponsePrompt);
    gIOPMStatsDriverPSChangeSlow = OSSymbol::withCString(kIOPMStatsDriverPSChangeSlow);

    sleepSupportedPEFunction = OSSymbol::withCString("IOPMSetSleepSupported");
    sleepMessagePEFunction = OSSymbol::withCString("IOPMSystemSleepMessage");

    const OSSymbol  *settingsArr[kRootDomainSettingsCount] =
        {
            OSSymbol::withCString(kIOPMSettingSleepOnPowerButtonKey),
            gIOPMSettingAutoWakeSecondsKey,
            OSSymbol::withCString(kIOPMSettingAutoPowerSecondsKey),
            gIOPMSettingAutoWakeCalendarKey,
            OSSymbol::withCString(kIOPMSettingAutoPowerCalendarKey),
            gIOPMSettingDebugWakeRelativeKey,
            OSSymbol::withCString(kIOPMSettingDebugPowerRelativeKey),
            OSSymbol::withCString(kIOPMSettingWakeOnRingKey),
            OSSymbol::withCString(kIOPMSettingRestartOnPowerLossKey),
            OSSymbol::withCString(kIOPMSettingWakeOnClamshellKey),
            OSSymbol::withCString(kIOPMSettingWakeOnACChangeKey),
            OSSymbol::withCString(kIOPMSettingTimeZoneOffsetKey),
            OSSymbol::withCString(kIOPMSettingDisplaySleepUsesDimKey),
            OSSymbol::withCString(kIOPMSettingMobileMotionModuleKey),
            OSSymbol::withCString(kIOPMSettingGraphicsSwitchKey),
            OSSymbol::withCString(kIOPMStateConsoleShutdown),
            gIOPMSettingSilentRunningKey
        };

    PE_parse_boot_argn("darkwake", &gDarkWakeFlags, sizeof(gDarkWakeFlags));
    PE_parse_boot_argn("noidle", &gNoIdleFlag, sizeof(gNoIdleFlag));

    queue_init(&aggressivesQueue);
    aggressivesThreadCall = thread_call_allocate(handleAggressivesFunction, this);
    aggressivesData = OSData::withCapacity(
                        sizeof(AggressivesRecord) * (kPMLastAggressivenessType + 4));

    featuresDictLock = IOLockAlloc();
    settingsCtrlLock = IOLockAlloc();
    wakeEventLock = IOLockAlloc();
    setPMRootDomain(this);

    extraSleepTimer = thread_call_allocate(
                        idleSleepTimerExpired,
                        (thread_call_param_t) this);

    diskSyncCalloutEntry = thread_call_allocate(
                        &disk_sync_callout,
                        (thread_call_param_t) this);
    swdDebugSetupEntry = thread_call_allocate(
                        &swdDebugSetupCallout,
                        (thread_call_param_t) this);
    swdDebugTearDownEntry = thread_call_allocate(
                        &swdDebugTeardownCallout,
                        (thread_call_param_t) this);
    updateConsoleUsersEntry = thread_call_allocate(
                        &updateConsoleUsersCallout,
                        (thread_call_param_t) this);

#if DARK_TO_FULL_EVALUATE_CLAMSHELL
    fullWakeThreadCall = thread_call_allocate(
                            OSMemberFunctionCast(thread_call_func_t, this,
                                &IOPMrootDomain::fullWakeDelayedWork),
                            (thread_call_param_t) this);
#endif

    setProperty(kIOSleepSupportedKey, true);

    bzero(&gPMStats, sizeof(gPMStats));

    pmTracer = PMTraceWorker::tracer(this);

    pmAssertions = PMAssertionsTracker::pmAssertionsTracker(this);

    userDisabledAllSleep = false;
    systemBooting = true;
    idleSleepEnabled = false;
    sleepSlider = 0;
    idleSleepTimerPending = false;
    wrangler = NULL;
    clamshellClosed    = false;
    clamshellExists    = false;
    clamshellDisabled  = true;
    acAdaptorConnected = true;
    clamshellSleepDisabled = false;
    gWakeReasonString[0] = '\0';

    // Initialize to user active.
    // Will never transition to user inactive w/o wrangler.
    fullWakeReason = kFullWakeReasonLocalUser;
    userIsActive = userWasActive = true;
    setProperty(gIOPMUserIsActiveKey, kOSBooleanTrue);

    // Set the default system capabilities at boot.
    _currentCapability = kIOPMSystemCapabilityCPU      |
                         kIOPMSystemCapabilityGraphics |
                         kIOPMSystemCapabilityAudio    |
                         kIOPMSystemCapabilityNetwork;

    _pendingCapability = _currentCapability;
    _desiredCapability = _currentCapability;
    _highestCapability = _currentCapability;
    setProperty(kIOPMSystemCapabilitiesKey, _currentCapability, 64);

    queuedSleepWakeUUIDString = NULL;
    initializeBootSessionUUID();
    pmStatsAppResponses     = OSArray::withCapacity(5);
    _statsNameKey           = OSSymbol::withCString(kIOPMStatsNameKey);
    _statsPIDKey            = OSSymbol::withCString(kIOPMStatsPIDKey);
    _statsTimeMSKey         = OSSymbol::withCString(kIOPMStatsTimeMSKey);
    _statsResponseTypeKey   = OSSymbol::withCString(kIOPMStatsApplicationResponseTypeKey);
    _statsMessageTypeKey    = OSSymbol::withCString(kIOPMStatsMessageTypeKey);
    _statsPowerCapsKey      = OSSymbol::withCString(kIOPMStatsPowerCapabilityKey);
    assertOnWakeSecs        = -1;  // Invalid value to prevent updates

    pmStatsLock = IOLockAlloc();
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

    // List of PM settings that should not automatically publish itself
    // as a feature when registered by a listener.
    noPublishPMSettings = OSArray::withObjects(
                    (const OSObject **) &gIOPMSettingSilentRunningKey, 1, 0);

    fPMSettingsDict = OSDictionary::withCapacity(5);
    preventIdleSleepList = OSSet::withCapacity(8);
    preventSystemSleepList = OSSet::withCapacity(2);

    PMinit();   // creates gIOPMWorkLoop
    gIOPMWorkLoop = getIOPMWorkloop();

    // Create IOPMPowerStateQueue used to queue external power
    // events, and to handle those events on the PM work loop.
    pmPowerStateQueue = IOPMPowerStateQueue::PMPowerStateQueue(
        this, OSMemberFunctionCast(IOEventSource::Action, this,
                &IOPMrootDomain::dispatchPowerEvent));
    gIOPMWorkLoop->addEventSource(pmPowerStateQueue);

    // create our power parent
    patriarch = new IORootParent;
    patriarch->init();
    patriarch->attach(this);
    patriarch->start(this);
    patriarch->addPowerChild(this);

    registerPowerDriver(this, ourPowerStates, NUM_POWER_STATES);
    changePowerStateToPriv(ON_STATE);

    // install power change handler
    gSysPowerDownNotifier = registerPrioritySleepWakeInterest( &sysPowerDownHandler, this, 0);

#if !NO_KERNEL_HID
    // Register for a notification when IODisplayWrangler is published
    if ((tmpDict = serviceMatching("IODisplayWrangler")))
    {
        _displayWranglerNotifier = addMatchingNotification(
                gIOPublishNotification, tmpDict,
                (IOServiceMatchingNotificationHandler) &displayWranglerMatchPublished,
                this, 0);
        tmpDict->release();
    }
#endif

#if defined(__i386__) || defined(__x86_64__)

    if ((tmpDict = serviceMatching("IODTNVRAM")))
    {
        notifier = addMatchingNotification(
                gIOFirstPublishNotification, tmpDict,
                (IOServiceMatchingNotificationHandler) &IONVRAMMatchPublished,
                this, 0);
        tmpDict->release();
    }

    wranglerIdleSettings = NULL;
    OSNumber * wranglerIdlePeriod = NULL;
    wranglerIdleSettings = OSDictionary::withCapacity(1);
    wranglerIdlePeriod  = OSNumber::withNumber(kDefaultWranglerIdlePeriod, 32);

    if(wranglerIdleSettings && wranglerIdlePeriod)
        wranglerIdleSettings->setObject(kIORequestWranglerIdleKey,
                                        wranglerIdlePeriod);

    if(wranglerIdlePeriod)
        wranglerIdlePeriod->release();
#endif

    const OSSymbol *ucClassName = OSSymbol::withCStringNoCopy("RootDomainUserClient");
    setProperty(gIOUserClientClassKey, (OSObject *) ucClassName);
    ucClassName->release();

    // IOBacklightDisplay can take a long time to load at boot, or it may
    // not load at all if you're booting with clamshell closed. We publish
    // 'DisplayDims' here redundantly to get it published early and at all.
    OSDictionary * matching;
    matching = serviceMatching("IOPMPowerSource");
    psIterator = getMatchingServices( matching );
    if (matching) matching->release();
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
    sysctl_register_oid(&sysctl__kern_iokittest);
    sysctl_register_oid(&sysctl__hw_targettype);

    sysctl_register_oid(&sysctl__kern_progressmeterenable);
    sysctl_register_oid(&sysctl__kern_progressmeter);
    sysctl_register_oid(&sysctl__kern_wakereason);
    sysctl_register_oid(&sysctl__kern_consoleoptions);
    sysctl_register_oid(&sysctl__kern_progressoptions);

#if HIBERNATION
    IOHibernateSystemInit(this);
#endif

    registerService();                      // let clients find us

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
    const OSSymbol  *key;
    OSObject        *obj;
    OSCollectionIterator * iter = 0;

    const OSSymbol *publish_simulated_battery_string    = OSSymbol::withCString("SoftwareSimulatedBatteries");
    const OSSymbol *boot_complete_string                = OSSymbol::withCString("System Boot Complete");
    const OSSymbol *sys_shutdown_string                 = OSSymbol::withCString("System Shutdown");
    const OSSymbol *stall_halt_string                   = OSSymbol::withCString("StallSystemAtHalt");
    const OSSymbol *battery_warning_disabled_string     = OSSymbol::withCString("BatteryWarningsDisabled");
    const OSSymbol *idle_seconds_string                 = OSSymbol::withCString("System Idle Seconds");
    const OSSymbol *sleepdisabled_string                = OSSymbol::withCString("SleepDisabled");
    const OSSymbol *ondeck_sleepwake_uuid_string        = OSSymbol::withCString(kIOPMSleepWakeUUIDKey);
    const OSSymbol *loginwindow_progress_string         = OSSymbol::withCString(kIOPMLoginWindowProgressKey);
    const OSSymbol *coredisplay_progress_string         = OSSymbol::withCString(kIOPMCoreDisplayProgressKey);
    const OSSymbol *coregraphics_progress_string        = OSSymbol::withCString(kIOPMCoreGraphicsProgressKey);
#if HIBERNATION
    const OSSymbol *hibernatemode_string                = OSSymbol::withCString(kIOHibernateModeKey);
    const OSSymbol *hibernatefile_string                = OSSymbol::withCString(kIOHibernateFileKey);
    const OSSymbol *hibernatefilemin_string            = OSSymbol::withCString(kIOHibernateFileMinSizeKey);
    const OSSymbol *hibernatefilemax_string            = OSSymbol::withCString(kIOHibernateFileMaxSizeKey);
    const OSSymbol *hibernatefreeratio_string           = OSSymbol::withCString(kIOHibernateFreeRatioKey);
    const OSSymbol *hibernatefreetime_string            = OSSymbol::withCString(kIOHibernateFreeTimeKey);
#endif

    if (!dict)
    {
        return_value = kIOReturnBadArgument;
        goto exit;
    }

    iter = OSCollectionIterator::withCollection(dict);
    if (!iter)
    {
        return_value = kIOReturnNoMemory;
        goto exit;
    }

    while ((key = (const OSSymbol *) iter->getNextObject()) &&
           (obj = dict->getObject(key)))
    {
        if (key->isEqualTo(publish_simulated_battery_string))
        {
            if (OSDynamicCast(OSBoolean, obj))
                publishResource(key, kOSBooleanTrue);
        }
        else if (key->isEqualTo(idle_seconds_string))
        {
            if ((n = OSDynamicCast(OSNumber, obj)))
            {
                setProperty(key, n);
                idleSeconds = n->unsigned32BitValue();
            }
        }
        else if (key->isEqualTo(boot_complete_string))
        {
            pmPowerStateQueue->submitPowerEvent(kPowerEventSystemBootCompleted);
        }
        else if (key->isEqualTo(sys_shutdown_string))
        {
            if ((b = OSDynamicCast(OSBoolean, obj)))
                pmPowerStateQueue->submitPowerEvent(kPowerEventSystemShutdown, (void *) b);
        }
        else if (key->isEqualTo(battery_warning_disabled_string))
        {
            setProperty(key, obj);
        }
#if HIBERNATION
        else if (key->isEqualTo(hibernatemode_string) ||
                 key->isEqualTo(hibernatefilemin_string) ||
                 key->isEqualTo(hibernatefilemax_string) ||
                 key->isEqualTo(hibernatefreeratio_string) ||
                 key->isEqualTo(hibernatefreetime_string))
        {
            if ((n = OSDynamicCast(OSNumber, obj)))
                setProperty(key, n);
        }
        else if (key->isEqualTo(hibernatefile_string))
        {
            OSString * str = OSDynamicCast(OSString, obj);
            if (str) setProperty(key, str);
        }
#endif
        else if (key->isEqualTo(sleepdisabled_string))
        {
            if ((b = OSDynamicCast(OSBoolean, obj)))
            {
                setProperty(key, b);
                pmPowerStateQueue->submitPowerEvent(kPowerEventUserDisabledSleep, (void *) b);
            }
        }
        else if (key->isEqualTo(ondeck_sleepwake_uuid_string))
        {
            obj->retain();
            pmPowerStateQueue->submitPowerEvent(kPowerEventQueueSleepWakeUUID, (void *)obj);
        }
        else if (key->isEqualTo(loginwindow_progress_string))
        {
            if (pmTracer && (n = OSDynamicCast(OSNumber, obj))) {
                uint32_t data = n->unsigned32BitValue();
                pmTracer->traceComponentWakeProgress(kIOPMLoginWindowProgress, data);
                kdebugTrace(kPMLogComponentWakeProgress, 0, kIOPMLoginWindowProgress, data);
            }
        }
        else if (key->isEqualTo(coredisplay_progress_string))
        {
            if (pmTracer && (n = OSDynamicCast(OSNumber, obj))) {
                uint32_t data = n->unsigned32BitValue();
                pmTracer->traceComponentWakeProgress(kIOPMCoreDisplayProgress, data);
                kdebugTrace(kPMLogComponentWakeProgress, 0, kIOPMCoreDisplayProgress, data);
            }
        }
        else if (key->isEqualTo(coregraphics_progress_string))
        {
            if (pmTracer && (n = OSDynamicCast(OSNumber, obj))) {
                uint32_t data = n->unsigned32BitValue();
                pmTracer->traceComponentWakeProgress(kIOPMCoreGraphicsProgress, data);
                kdebugTrace(kPMLogComponentWakeProgress, 0, kIOPMCoreGraphicsProgress, data);
            }
        }
        else if (key->isEqualTo(kIOPMDeepSleepEnabledKey)       ||
                 key->isEqualTo(kIOPMDestroyFVKeyOnStandbyKey)  ||
                 key->isEqualTo(kIOPMAutoPowerOffEnabledKey)    ||
                 key->isEqualTo(stall_halt_string))
        {
            if ((b = OSDynamicCast(OSBoolean, obj)))
                setProperty(key, b);
        }
        else if (key->isEqualTo(kIOPMDeepSleepDelayKey) ||
                 key->isEqualTo(kIOPMAutoPowerOffDelayKey) ||
                 key->isEqualTo(kIOPMAutoPowerOffTimerKey))
        {
            if ((n = OSDynamicCast(OSNumber, obj)))
                setProperty(key, n);
        }
        else if (key->isEqualTo(kIOPMUserWakeAlarmScheduledKey))
        {
            if (kOSBooleanTrue == obj)
                OSBitOrAtomic(kIOPMAlarmBitCalendarWake, &_userScheduledAlarm);
            else
                OSBitAndAtomic(~kIOPMAlarmBitCalendarWake, &_userScheduledAlarm);
            DLOG("_userScheduledAlarm = 0x%x\n", (uint32_t) _userScheduledAlarm);
        }

        // Relay our allowed PM settings onto our registered PM clients
        else if ((allowedPMSettings->getNextIndexOfObject(key, 0) != (unsigned int) -1))
        {
            return_value = setPMSetting(key, obj);
            if (kIOReturnSuccess != return_value)
                break;

            if (gIOPMSettingDebugWakeRelativeKey == key)
            {
                if ((n = OSDynamicCast(OSNumber, obj)) &&
                    (_debugWakeSeconds = n->unsigned32BitValue()))
                {
                    OSBitOrAtomic(kIOPMAlarmBitDebugWake, &_scheduledAlarms);
                }
                else
                {
                    _debugWakeSeconds = 0;
                    OSBitAndAtomic(~kIOPMAlarmBitDebugWake, &_scheduledAlarms);
                }
                DLOG("_scheduledAlarms = 0x%x\n", (uint32_t) _scheduledAlarms);
            }
            else if (gIOPMSettingAutoWakeCalendarKey == key)
            {
                OSData * data;
                if ((data = OSDynamicCast(OSData, obj)) &&
                    (data->getLength() == sizeof(IOPMCalendarStruct)))
                {
                    const IOPMCalendarStruct * cs =
                        (const IOPMCalendarStruct *) data->getBytesNoCopy();

                    if (cs->year)
                        OSBitOrAtomic(kIOPMAlarmBitCalendarWake, &_scheduledAlarms);
                    else
                        OSBitAndAtomic(~kIOPMAlarmBitCalendarWake, &_scheduledAlarms);
                    DLOG("_scheduledAlarms = 0x%x\n", (uint32_t) _scheduledAlarms);
                }
            }
        }
        else
        {
            DLOG("setProperties(%s) not handled\n", key->getCStringNoCopy());
        }
    }

exit:
    if(publish_simulated_battery_string) publish_simulated_battery_string->release();
    if(boot_complete_string) boot_complete_string->release();
    if(sys_shutdown_string) sys_shutdown_string->release();
    if(stall_halt_string) stall_halt_string->release();
    if(battery_warning_disabled_string) battery_warning_disabled_string->release();
    if(idle_seconds_string) idle_seconds_string->release();
    if(sleepdisabled_string) sleepdisabled_string->release();
    if(ondeck_sleepwake_uuid_string) ondeck_sleepwake_uuid_string->release();
    if(loginwindow_progress_string) loginwindow_progress_string->release();
    if(coredisplay_progress_string) coredisplay_progress_string->release();
    if(coregraphics_progress_string) coregraphics_progress_string->release();
#if HIBERNATION
    if(hibernatemode_string) hibernatemode_string->release();
    if(hibernatefile_string) hibernatefile_string->release();
    if(hibernatefreeratio_string) hibernatefreeratio_string->release();
    if(hibernatefreetime_string) hibernatefreetime_string->release();
#endif
    if (iter) iter->release();
    return return_value;
}

// MARK: -
// MARK: Aggressiveness

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

    DLOG("setAggressiveness(%x) 0x%x = %u\n",
        (uint32_t) options, (uint32_t) type, (uint32_t) value);

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
        DLOG("getAggressiveness(%d) 0x%x = %u\n",
            source, (uint32_t) type, value);
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

    DLOG("joinAggressiveness %s %p\n", service->getName(), OBFUSCATE(service));

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
                                    DLOG("disk spindown accelerated, was %u min\n",
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
        pmPowerStateQueue->submitPowerEvent(
            kPowerEventPolicyStimulus,
            (void *) kStimulusAggressivenessChanged );
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
    IOPMDriverCallEntry         callEntry;
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
            if (service->assertPMDriverCall(&callEntry))
            {
                for (i = 0, record = array; i < count; i++, record++)
                {
                    value = record->value;
                    if (record->flags & kAggressivesRecordFlagMinValue)
                        value = kAggressivesMinValue;

                    _LOG("synchronizeAggressives 0x%x = %u to %s\n",
                        record->type, value, service->getName());
                    service->setAggressiveness(record->type, value);
                }
                service->deassertPMDriverCall(&callEntry);
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
    IOPMDriverCallEntry         callEntry;
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

                if ((service = OSDynamicCast(IOService, connect->copyChildEntry(gIOPowerPlane))))
                {
                    if (service->assertPMDriverCall(&callEntry))
                    {
                        for (i = 0, record = array; i < count; i++, record++)
                        {
                            if (record->flags & kAggressivesRecordFlagModified)
                            {
                                value = record->value;
                                if (record->flags & kAggressivesRecordFlagMinValue)
                                    value = kAggressivesMinValue;
                                _LOG("broadcastAggressives %x = %u to %s\n",
                                    record->type, value, service->getName());
                                service->setAggressiveness(record->type, value);
                            }
                        }
                        service->deassertPMDriverCall(&callEntry);
                    }
                    service->release();
                }
            }
        }
        while (!entry && !iter->isValid());
        iter->release();
    }
}

// MARK: -
// MARK: System Sleep

//******************************************************************************
// startIdleSleepTimer
//
//******************************************************************************

void IOPMrootDomain::startIdleSleepTimer( uint32_t inSeconds )
{
    AbsoluteTime deadline;

    ASSERT_GATED();
    if (gNoIdleFlag) {
        DLOG("idle timer not set (noidle=%d)\n", gNoIdleFlag);
        return;
    }
    if (inSeconds)
    {
        clock_interval_to_deadline(inSeconds, kSecondScale, &deadline);
        thread_call_enter_delayed(extraSleepTimer, deadline);
        idleSleepTimerPending = true;
    }
    else
    {
        thread_call_enter(extraSleepTimer);
    }
    DLOG("idle timer set for %u seconds\n", inSeconds);
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

        if (!assertOnWakeSecs && gIOLastWakeAbsTime) {
                AbsoluteTime    now;
                clock_usec_t    microsecs;
                clock_get_uptime(&now);
                SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
                absolutetime_to_microtime(now, &assertOnWakeSecs, &microsecs);
                if (assertOnWakeReport)  {
                    HISTREPORT_TALLYVALUE(assertOnWakeReport, (int64_t)assertOnWakeSecs);
                    DLOG("Updated assertOnWake %lu\n", (unsigned long)assertOnWakeSecs);
                }
        }
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

//******************************************************************************
// handleSleepTimerExpiration
//
// The time between the sleep idle timeout and the next longest one has elapsed.
// It's time to sleep. Start that by removing the clamp that's holding us awake.
//******************************************************************************

void IOPMrootDomain::handleSleepTimerExpiration( void )
{
    if (!gIOPMWorkLoop->inGate())
    {
        gIOPMWorkLoop->runAction(
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
    setQuickSpinDownTimeout();
    adjustPowerState(true);
}

//******************************************************************************
// getTimeToIdleSleep
//
// Returns number of seconds left before going into idle sleep.
// Caller has to make sure that idle sleep is allowed at the time of calling
// this function
//******************************************************************************

uint32_t IOPMrootDomain::getTimeToIdleSleep( void )
{

    AbsoluteTime    now, lastActivityTime;
    uint64_t        nanos;
    uint32_t        minutesSinceUserInactive = 0;
    uint32_t         sleepDelay = 0;

    if (!idleSleepEnabled)
        return 0xffffffff;

    if (userActivityTime)
        lastActivityTime = userActivityTime;
    else
        lastActivityTime = userBecameInactiveTime;

    clock_get_uptime(&now);
    if (CMP_ABSOLUTETIME(&now, &lastActivityTime) > 0)
    {
        SUB_ABSOLUTETIME(&now, &lastActivityTime);
        absolutetime_to_nanoseconds(now, &nanos);
        minutesSinceUserInactive = nanos / (60000000000ULL);

        if (minutesSinceUserInactive >= sleepSlider)
            sleepDelay = 0;
        else
            sleepDelay = sleepSlider - minutesSinceUserInactive;
    }
    else
    {
        sleepDelay = sleepSlider;
    }

    DLOG("user inactive %u min, time to idle sleep %u min\n",
        minutesSinceUserInactive, sleepDelay);

    return (sleepDelay * 60);
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
    OSObject *obj = NULL;
    OSString *reason = NULL;
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
        return privateSleepSystem( kIOPMSleepReasonOSSwitchHibernate);
    }

    if (options && (obj = options->getObject("Sleep Reason")))
    {
        reason = OSDynamicCast(OSString, obj);
        if (reason && reason->isEqualTo(kIOPMDarkWakeThermalEmergencyKey))
            return privateSleepSystem(kIOPMSleepReasonDarkWakeThermalEmergency);
    }

    return privateSleepSystem( kIOPMSleepReasonSoftware);
}

/* private */
IOReturn IOPMrootDomain::privateSleepSystem( uint32_t sleepReason )
{
    /* Called from both gated and non-gated context */

    if (!checkSystemSleepEnabled() || !pmPowerStateQueue)
    {
        return kIOReturnNotPermitted;
    }

    pmPowerStateQueue->submitPowerEvent(
                            kPowerEventPolicyStimulus,
                            (void *) kStimulusDemandSystemSleep,
                            sleepReason);

    return kIOReturnSuccess;
}

//******************************************************************************
// powerChangeDone
//
// This overrides powerChangeDone in IOService.
//******************************************************************************

void IOPMrootDomain::powerChangeDone( unsigned long previousPowerState )
{
    uint64_t    now;
    ASSERT_GATED();
    DLOG("PowerChangeDone: %u->%u\n",
        (uint32_t) previousPowerState, (uint32_t) getPowerState());

    switch ( getPowerState() )
    {
        case SLEEP_STATE: {
            if (previousPowerState != ON_STATE)
                break;

            acceptSystemWakeEvents(true);

            // re-enable this timer for next sleep
            cancelIdleSleepTimer();

            clock_sec_t     secs;
            clock_usec_t    microsecs;
            clock_get_calendar_absolute_and_microtime(&secs, &microsecs, &now);
            logtime(secs);
            gIOLastSleepTime.tv_sec  = secs;
            gIOLastSleepTime.tv_usec = microsecs;
            gIOLastWakeTime.tv_sec = 0;
            gIOLastWakeTime.tv_usec = 0;
            gIOLastSleepAbsTime = now;

            if (wake2DarkwakeDelay && sleepDelaysReport) {
                clock_usec_t    microsecs;
                clock_sec_t     wake2DarkwakeSecs, darkwake2SleepSecs;
                // Update 'wake2DarkwakeDelay' histogram if this is a fullwake->sleep transition

                SUB_ABSOLUTETIME(&now, &ts_sleepStart);
                absolutetime_to_microtime(now, &darkwake2SleepSecs, &microsecs);
                absolutetime_to_microtime(wake2DarkwakeDelay, &wake2DarkwakeSecs, &microsecs);
                HISTREPORT_TALLYVALUE(sleepDelaysReport, 
                                           (int64_t)(wake2DarkwakeSecs+darkwake2SleepSecs));

                DLOG("Updated sleepDelaysReport %lu %lu\n", (unsigned long)wake2DarkwakeSecs, (unsigned long)darkwake2SleepSecs);
                wake2DarkwakeDelay = 0;
            }
#if HIBERNATION
            LOG("System %sSleep\n", gIOHibernateState ? "Safe" : "");

            IOHibernateSystemHasSlept();

            evaluateSystemSleepPolicyFinal();
#else
            LOG("System Sleep\n");
#endif
            if (thermalWarningState) {
                const OSSymbol *event = OSSymbol::withCString(kIOPMThermalLevelWarningKey);
                if (event) {
                    systemPowerEventOccurred(event, kIOPMThermalLevelUnknown);
                    event->release();
                }
            }
            assertOnWakeSecs = 0;
            ((IOService *)this)->stop_watchdog_timer(); //14456299
            lowBatteryCondition = false;

            getPlatform()->sleepKernel();

            // The CPU(s) are off at this point,
            // Code will resume execution here upon wake.

            clock_get_uptime(&gIOLastWakeAbsTime);
            IOLog("gIOLastWakeAbsTime: %lld\n", gIOLastWakeAbsTime);
            _highestCapability = 0;

            ((IOService *)this)->start_watchdog_timer(); //14456299
#if HIBERNATION
            IOHibernateSystemWake();
#endif

            // sleep transition complete
            gSleepOrShutdownPending = 0;

			// trip the reset of the calendar clock
			{
				clock_sec_t  wakeSecs;
				clock_usec_t wakeMicrosecs;

				clock_initialize_calendar();

				clock_get_calendar_microtime(&wakeSecs, &wakeMicrosecs);
				gIOLastWakeTime.tv_sec  = wakeSecs;
				gIOLastWakeTime.tv_usec = wakeMicrosecs;
			}

#if HIBERNATION
            LOG("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
#endif

            lastSleepReason = 0;

            _lastDebugWakeSeconds = _debugWakeSeconds;
            _debugWakeSeconds = 0;
            _scheduledAlarms = 0;

#if defined(__i386__) || defined(__x86_64__)
            kdebugTrace(kPMLogSystemWake, 0, 0, 0);
            wranglerTickled         = false;
            graphicsSuppressed      = false;
            darkWakePostTickle      = false;
            darkWakeHibernateError  = false;
            darkWakeToSleepASAP     = true;
            logGraphicsClamp        = true;
            sleepTimerMaintenance   = false;
            sleepToStandby          = false;
            wranglerTickleLatched   = false;
            userWasActive           = false;
            fullWakeReason = kFullWakeReasonNone;

            OSString * wakeType = OSDynamicCast(
                OSString, getProperty(kIOPMRootDomainWakeTypeKey));
            OSString * wakeReason = OSDynamicCast(
                OSString, getProperty(kIOPMRootDomainWakeReasonKey));

            if (wakeReason && (wakeReason->getLength() >= 2) &&
                gWakeReasonString[0] == '\0')
            {
                // Until the platform driver can claim its wake reasons
                strlcat(gWakeReasonString, wakeReason->getCStringNoCopy(),
                        sizeof(gWakeReasonString));
            }

            if (wakeType && wakeType->isEqualTo(kIOPMrootDomainWakeTypeLowBattery))
            {
                lowBatteryCondition = true;
                darkWakeMaintenance = true;
            }
            else if ((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) != 0)
            {
#if HIBERNATION
                OSNumber * hibOptions = OSDynamicCast(
                    OSNumber, getProperty(kIOHibernateOptionsKey));
                if (hibernateAborted || ((hibOptions &&
                    !(hibOptions->unsigned32BitValue() & kIOHibernateOptionDarkWake))))
                {
                    // Hibernate aborted, or EFI brought up graphics
                    wranglerTickled = true;
                    DLOG("hibernation aborted %d, options 0x%x\n",
                        hibernateAborted,
                        hibOptions ? hibOptions->unsigned32BitValue() : 0);
                }
                else
#endif
                if (wakeType && (
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeUser) ||
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeAlarm)))
                {
                    // User wake or RTC alarm
                    wranglerTickled = true;
                }
                else
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepTimer))
                {
                    // SMC standby timer trumps SleepX
                    darkWakeMaintenance = true;
                    sleepTimerMaintenance = true;
                }
                else
                if ((_lastDebugWakeSeconds != 0) &&
                    ((gDarkWakeFlags & kDarkWakeFlagAlarmIsDark) == 0))
                {
                    // SleepX before maintenance
                    wranglerTickled = true;
                }
                else
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeMaintenance))
                {
                    darkWakeMaintenance = true;
                }
                else
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepService))
                {
                    darkWakeMaintenance = true;
                    darkWakeSleepService = true;
#if HIBERNATION
                    if (kIOHibernateStateWakingFromHibernate == gIOHibernateState) {
                        sleepToStandby = true;
                    }
#endif
                }
                else
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeHibernateError))
                {
                    darkWakeMaintenance = true;
                    darkWakeHibernateError = true;
                }
                else
                {
                    // Unidentified wake source, resume to full wake if debug
                    // alarm is pending.

                    if (_lastDebugWakeSeconds &&
                        (!wakeReason || wakeReason->isEqualTo("")))
                        wranglerTickled = true;
                }
            }
            else
            {
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepTimer))
                {
                    darkWakeMaintenance = true;
                    sleepTimerMaintenance = true;
                }
                else if (hibernateAborted || !wakeType ||
                    !wakeType->isEqualTo(kIOPMRootDomainWakeTypeMaintenance) ||
                    !wakeReason || !wakeReason->isEqualTo("RTC"))
                {
                    // Post a HID tickle immediately - except for RTC maintenance wake.
                    wranglerTickled = true;
                }
                else
                {
                    darkWakeMaintenance = true;
                }
            }

            if (wranglerTickled)
            {
                darkWakeToSleepASAP = false;
                fullWakeReason = kFullWakeReasonLocalUser;
                reportUserInput();
            }
            else if (displayPowerOnRequested && checkSystemCanSustainFullWake())
            {
                handleDisplayPowerOn();
            }
            else if (!darkWakeMaintenance)
            {
                // Early/late tickle for non-maintenance wake.
                if (((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) ==
                     kDarkWakeFlagHIDTickleEarly) ||
                    ((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) ==
                     kDarkWakeFlagHIDTickleLate))
                {
                    darkWakePostTickle = true;
                }
            }
#else   /* !__i386__ && !__x86_64__ */
            kdebugTrace(kPMLogSystemWake, 0, ml_get_wake_timebase() >> 32, ml_get_wake_timebase());
            // stay awake for at least 30 seconds
            wranglerTickled = true;
            fullWakeReason = kFullWakeReasonLocalUser;
            startIdleSleepTimer(30);
#endif
            sleepCnt++;

	    thread_call_enter(updateConsoleUsersEntry);

            changePowerStateToPriv(ON_STATE);
        }   break;
#if !__i386__ && !__x86_64__
        case ON_STATE: {
            if (previousPowerState != ON_STATE)
            {
                DLOG("Force re-evaluating aggressiveness\n");
                /* Force re-evaluate the aggressiveness values to set appropriate idle sleep timer */
                pmPowerStateQueue->submitPowerEvent(
                    kPowerEventPolicyStimulus,
                    (void *) kStimulusNoIdleSleepPreventers );
          }
          break;
        }

#endif

    }
}

//******************************************************************************
// requestPowerDomainState
//
// Extend implementation in IOService. Running on PM work loop thread.
//******************************************************************************

IOReturn IOPMrootDomain::requestPowerDomainState (
    IOPMPowerFlags      childDesire,
    IOPowerConnection * childConnection,
    unsigned long       specification )
{
    // Idle and system sleep prevention flags affects driver desire.
    // Children desire are irrelevant so they are cleared.

    return super::requestPowerDomainState(0, childConnection, specification);
}


//******************************************************************************
// updatePreventIdleSleepList
//
// Called by IOService on PM work loop.
// Returns true if PM policy recognized the driver's desire to prevent idle
// sleep and updated the list of idle sleep preventers. Returns false otherwise
//******************************************************************************

bool IOPMrootDomain::updatePreventIdleSleepList(
        IOService * service, bool addNotRemove )
{
    unsigned int oldCount, newCount;

    ASSERT_GATED();

#if defined(__i386__) || defined(__x86_64__)
    // Disregard disk I/O (besides the display wrangler) as a factor preventing
    // idle sleep, except in the case of legacy disk I/O
    if ((service != wrangler) && (service != this))
    {
        return false;
    }
#endif

    oldCount = preventIdleSleepList->getCount();
    if (addNotRemove)
    {
        preventIdleSleepList->setObject(service);
        DLOG("prevent idle sleep list: %s+ (%u)\n",
            service->getName(), preventIdleSleepList->getCount());
    }
    else if (preventIdleSleepList->member(service))
    {
        preventIdleSleepList->removeObject(service);
        DLOG("prevent idle sleep list: %s- (%u)\n",
            service->getName(), preventIdleSleepList->getCount());
    }
    newCount = preventIdleSleepList->getCount();

    if ((oldCount == 0) && (newCount != 0))
    {
        // Driver added to empty prevent list.
        // Update the driver desire to prevent idle sleep.
        // Driver desire does not prevent demand sleep.

        changePowerStateTo(ON_STATE);
    }
    else if ((oldCount != 0) && (newCount == 0))
    {
        // Last driver removed from prevent list.
        // Drop the driver clamp to allow idle sleep.

        changePowerStateTo(SLEEP_STATE);
        evaluatePolicy( kStimulusNoIdleSleepPreventers );
    }
    messageClient(kIOPMMessageIdleSleepPreventers, systemCapabilityNotifier,
        &newCount, sizeof(newCount));

#if defined(__i386__) || defined(__x86_64__)
    if (addNotRemove && (service == wrangler) && !checkSystemCanSustainFullWake())
    {
        return false;   // do not idle-cancel
    }
#endif

    MSG("prevent idle sleep list: %s%c (%u)\n",
        service->getName(),
        (addNotRemove) ? '+' : '-', newCount);
    return true;
}

//******************************************************************************
// preventSystemSleepListUpdate
//
// Called by IOService on PM work loop.
//******************************************************************************

void IOPMrootDomain::updatePreventSystemSleepList(
        IOService * service, bool addNotRemove )
{
    unsigned int oldCount, newCount;

    ASSERT_GATED();
    if (this == service)
        return;

    oldCount = preventSystemSleepList->getCount();
    if (addNotRemove)
    {
        preventSystemSleepList->setObject(service);
        DLOG("prevent system sleep list: %s+ (%u)\n",
            service->getName(), preventSystemSleepList->getCount());
        if (!assertOnWakeSecs && gIOLastWakeAbsTime) {
                AbsoluteTime    now;
                clock_usec_t    microsecs;
                clock_get_uptime(&now);
                SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
                absolutetime_to_microtime(now, &assertOnWakeSecs, &microsecs);
                if (assertOnWakeReport)  {
                    HISTREPORT_TALLYVALUE(assertOnWakeReport, (int64_t)assertOnWakeSecs);
                    DLOG("Updated assertOnWake %lu\n", (unsigned long)assertOnWakeSecs);
                }
        }
    }
    else if (preventSystemSleepList->member(service))
    {
        preventSystemSleepList->removeObject(service);
        DLOG("prevent system sleep list: %s- (%u)\n",
            service->getName(), preventSystemSleepList->getCount());

        if ((oldCount != 0) && (preventSystemSleepList->getCount() == 0))
        {
            // Lost all system sleep preventers.
            // Send stimulus if system sleep was blocked, and is in dark wake.
            evaluatePolicy( kStimulusDarkWakeEvaluate );
        }
    }
    newCount = preventSystemSleepList->getCount();
    messageClient(kIOPMMessageSystemSleepPreventers, systemCapabilityNotifier,
        &newCount, sizeof(newCount));
}

void IOPMrootDomain::copySleepPreventersList(OSArray **idleSleepList, OSArray **systemSleepList)
{

    OSCollectionIterator *iterator = NULL;
    OSObject    *object = NULL;
    OSArray     *array = NULL;

    if (!gIOPMWorkLoop->inGate())
    {
        gIOPMWorkLoop->runAction(
            OSMemberFunctionCast(IOWorkLoop::Action, this,
                &IOPMrootDomain::IOPMrootDomain::copySleepPreventersList),
            this, (void *)idleSleepList, (void *)systemSleepList);
        return;
    }

    if (idleSleepList && preventIdleSleepList && (preventIdleSleepList->getCount() != 0))
    {
        iterator = OSCollectionIterator::withCollection(preventIdleSleepList);
        array = OSArray::withCapacity(5);

        while ((object = iterator->getNextObject()))
        {
            IOService *service = OSDynamicCast(IOService, object);
            if (object)
            {
                array->setObject(OSSymbol::withCString(service->getName()));
            }
        }

        iterator->release();
        *idleSleepList = array;
    }

    if (systemSleepList && preventSystemSleepList && (preventSystemSleepList->getCount() != 0))
    {
        iterator = OSCollectionIterator::withCollection(preventSystemSleepList);
        array = OSArray::withCapacity(5);

        while ((object = iterator->getNextObject()))
        {
            IOService *service = OSDynamicCast(IOService, object);
            if (object)
            {
                array->setObject(OSSymbol::withCString(service->getName()));
            }
        }

        iterator->release();
        *systemSleepList = array;
    }
}

//******************************************************************************
// tellChangeDown
//
// Override the superclass implementation to send a different message type.
//******************************************************************************

bool IOPMrootDomain::tellChangeDown( unsigned long stateNum )
{
    DLOG("tellChangeDown %u->%u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum);

    if (SLEEP_STATE == stateNum)
    {
        // Legacy apps were already told in the full->dark transition
        if (!ignoreTellChangeDown)
            tracePoint( kIOPMTracePointSleepApplications );
        else
            tracePoint( kIOPMTracePointSleepPriorityClients );
    }

    if ((SLEEP_STATE == stateNum) && !ignoreTellChangeDown)
    {
        userActivityAtSleep = userActivityCount;
        hibernateAborted = false;
        DLOG("tellChangeDown::userActivityAtSleep %d\n", userActivityAtSleep);

        // Direct callout into OSKext so it can disable kext unloads
        // during sleep/wake to prevent deadlocks.
        OSKextSystemSleepOrWake( kIOMessageSystemWillSleep );

        IOService::updateConsoleUsers(NULL, kIOMessageSystemWillSleep);

        // Two change downs are sent by IOServicePM. Ignore the 2nd.
        // But tellClientsWithResponse() must be called for both.
        ignoreTellChangeDown = true;
    }

    return super::tellClientsWithResponse( kIOMessageSystemWillSleep );
}

//******************************************************************************
// askChangeDown
//
// Override the superclass implementation to send a different message type.
// This must be idle sleep since we don't ask during any other power change.
//******************************************************************************

bool IOPMrootDomain::askChangeDown( unsigned long stateNum )
{
    DLOG("askChangeDown %u->%u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum);

    // Don't log for dark wake entry
    if (kSystemTransitionSleep == _systemTransitionType)
        tracePoint( kIOPMTracePointSleepApplications );

    return super::tellClientsWithResponse( kIOMessageCanSystemSleep );
}

//******************************************************************************
// askChangeDownDone
//
// An opportunity for root domain to cancel the power transition,
// possibily due to an assertion created by powerd in response to
// kIOMessageCanSystemSleep.
//
// Idle sleep:
//   full -> dark wake transition
//     1. Notify apps and powerd with kIOMessageCanSystemSleep
//     2. askChangeDownDone()
//   dark -> sleep transition
//     1. Notify powerd with kIOMessageCanSystemSleep
//     2. askChangeDownDone()
//
// Demand sleep:
//   full -> dark wake transition
//     1. Notify powerd with kIOMessageCanSystemSleep
//     2. askChangeDownDone()
//   dark -> sleep transition
//     1. Notify powerd with kIOMessageCanSystemSleep
//     2. askChangeDownDone()
//******************************************************************************

void IOPMrootDomain::askChangeDownDone(
        IOPMPowerChangeFlags * inOutChangeFlags, bool * cancel )
{
    DLOG("askChangeDownDone(0x%x, %u) type %x, cap %x->%x\n",
        *inOutChangeFlags, *cancel,
        _systemTransitionType,
        _currentCapability, _pendingCapability);

    if ((false == *cancel) && (kSystemTransitionSleep == _systemTransitionType))
    {
        // Dark->Sleep transition.
        // Check if there are any deny sleep assertions.
        // lastSleepReason already set by handleOurPowerChangeStart()

        if (!checkSystemCanSleep(lastSleepReason))
        {
            // Cancel dark wake to sleep transition.
            // Must re-scan assertions upon entering dark wake.

            *cancel = true;
            DLOG("cancel dark->sleep\n");
        }
    }
}

//******************************************************************************
// systemDidNotSleep
//
// Work common to both canceled or aborted sleep.
//******************************************************************************

void IOPMrootDomain::systemDidNotSleep( void )
{
    // reset console lock state
    thread_call_enter(updateConsoleUsersEntry);

    if (!wrangler)
    {
        if (idleSleepEnabled)
        {
            // stay awake for at least idleSeconds
            startIdleSleepTimer(idleSeconds);
        }
    }
    else
    {
        if (idleSleepEnabled && !userIsActive)
        {
            // Manually start the idle sleep timer besides waiting for
            // the user to become inactive.
            startIdleSleepTimer( kIdleSleepRetryInterval );
        }
    }

    preventTransitionToUserActive(false);
    IOService::setAdvisoryTickleEnable( true );

    // After idle revert and cancel, send a did-change message to powerd
    // to balance the previous will-change message. Kernel clients do not
    // need this since sleep cannot be canceled once they are notified.

    if (toldPowerdCapWillChange && systemCapabilityNotifier &&
        (_pendingCapability != _currentCapability) &&
        ((_systemMessageClientMask & kSystemMessageClientPowerd) != 0))
    {
        // Differs from a real capability gain change where notifyRef != 0,
        // but it is zero here since no response is expected.

        IOPMSystemCapabilityChangeParameters params;

        bzero(&params, sizeof(params));
        params.fromCapabilities = _pendingCapability;
        params.toCapabilities = _currentCapability;
        params.changeFlags = kIOPMSystemCapabilityDidChange;

        DLOG("MESG cap %x->%x did change\n",
            params.fromCapabilities, params.toCapabilities);
        messageClient(kIOMessageSystemCapabilityChange, systemCapabilityNotifier,
            &params, sizeof(params));
    }
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
    DLOG("tellNoChangeDown %u->%u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum);

    // Sleep canceled, clear the sleep trace point.
    tracePoint(kIOPMTracePointSystemUp);

    systemDidNotSleep();
    return tellClients( kIOMessageSystemWillNotSleep );
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
    DLOG("tellChangeUp %u->%u\n",
        (uint32_t) getPowerState(), (uint32_t) stateNum);

    ignoreTellChangeDown = false;

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
            systemDidNotSleep();
            tellClients( kIOMessageSystemWillPowerOn );
        }

        tracePoint( kIOPMTracePointWakeApplications );
        tellClients( kIOMessageSystemHasPoweredOn );
    }
}

#define CAP_WILL_CHANGE_TO_OFF(params, flag) \
    (((params)->changeFlags & kIOPMSystemCapabilityWillChange) && \
     ((params)->fromCapabilities & (flag)) && \
     (((params)->toCapabilities & (flag)) == 0))

#define CAP_DID_CHANGE_TO_ON(params, flag) \
    (((params)->changeFlags & kIOPMSystemCapabilityDidChange) && \
     ((params)->toCapabilities & (flag)) && \
     (((params)->fromCapabilities & (flag)) == 0))

#define CAP_DID_CHANGE_TO_OFF(params, flag) \
    (((params)->changeFlags & kIOPMSystemCapabilityDidChange) && \
     ((params)->fromCapabilities & (flag)) && \
     (((params)->toCapabilities & (flag)) == 0))

#define CAP_WILL_CHANGE_TO_ON(params, flag) \
    (((params)->changeFlags & kIOPMSystemCapabilityWillChange) && \
     ((params)->toCapabilities & (flag)) && \
     (((params)->fromCapabilities & (flag)) == 0))

//******************************************************************************
// sysPowerDownHandler
//
// Perform a vfs sync before system sleep.
//******************************************************************************

IOReturn IOPMrootDomain::sysPowerDownHandler(
    void * target, void * refCon,
    UInt32 messageType, IOService * service,
    void * messageArgs, vm_size_t argSize )
{
    IOReturn    ret = 0;

    DLOG("sysPowerDownHandler message %s\n", getIOMessageString(messageType));

    if (!gRootDomain)
        return kIOReturnUnsupported;

    if (messageType == kIOMessageSystemWillSleep)
    {
#if HIBERNATION
        IOPowerStateChangeNotification *notify =
            (IOPowerStateChangeNotification *)messageArgs;

        notify->returnValue = 30 * 1000 * 1000;
        thread_call_enter1(
                           gRootDomain->swdDebugSetupEntry,
                           (thread_call_param_t)(uintptr_t) notify->powerRef);
#endif
    }
    else if (messageType == kIOMessageSystemCapabilityChange)
    {
        IOPMSystemCapabilityChangeParameters * params =
            (IOPMSystemCapabilityChangeParameters *) messageArgs;

        // Interested applications have been notified of an impending power
        // change and have acked (when applicable).
        // This is our chance to save whatever state we can before powering
        // down.
        // We call sync_internal defined in xnu/bsd/vfs/vfs_syscalls.c,
        // via callout

        DLOG("sysPowerDownHandler cap %x -> %x (flags %x)\n",
            params->fromCapabilities, params->toCapabilities,
            params->changeFlags);

        if (CAP_WILL_CHANGE_TO_OFF(params, kIOPMSystemCapabilityCPU))
        {
            // We will ack within 20 seconds
            params->maxWaitForReply = 20 * 1000 * 1000;

            // Remove EFI/BootRom's previous wake's failure data
            PERemoveNVRAMProperty(kIOEFIBootRomFailureKey);

#if HIBERNATION
            gRootDomain->evaluateSystemSleepPolicyEarly();

            // add in time we could spend freeing pages
            if (gRootDomain->hibernateMode && !gRootDomain->hibernateDisabled)
            {
                params->maxWaitForReply = kCapabilityClientMaxWait;
            }
            DLOG("sysPowerDownHandler max wait %d s\n",
                (int) (params->maxWaitForReply / 1000 / 1000));
#endif

            // Notify platform that sleep has begun, after the early
            // sleep policy evaluation.
            getPlatform()->callPlatformFunction(
                            sleepMessagePEFunction, false,
                            (void *)(uintptr_t) kIOMessageSystemWillSleep,
                            NULL, NULL, NULL);

            if ( !OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending ) )
            {
                // Purposely delay the ack and hope that shutdown occurs quickly.
                // Another option is not to schedule the thread and wait for
                // ack timeout...
                AbsoluteTime deadline;
                clock_interval_to_deadline( 30, kSecondScale, &deadline );
                thread_call_enter1_delayed(
                    gRootDomain->diskSyncCalloutEntry,
                    (thread_call_param_t)(uintptr_t) params->notifyRef,
                    deadline );
            }
            else
                thread_call_enter1(
                    gRootDomain->diskSyncCalloutEntry,
                    (thread_call_param_t)(uintptr_t) params->notifyRef);
        }
#if HIBERNATION
        else if (CAP_DID_CHANGE_TO_ON(params, kIOPMSystemCapabilityCPU))
        {
            // We will ack within 110 seconds
            params->maxWaitForReply = 110 * 1000 * 1000;

            thread_call_enter1(
                gRootDomain->diskSyncCalloutEntry,
                (thread_call_param_t)(uintptr_t) params->notifyRef);
        }
        else if (CAP_WILL_CHANGE_TO_OFF(params, kIOPMSystemCapabilityGraphics) ||
                 CAP_WILL_CHANGE_TO_ON(params, kIOPMSystemCapabilityGraphics))
        {
            // WillChange for Full wake -> Darkwake
           params->maxWaitForReply = 30 * 1000 * 1000;
           thread_call_enter1(
                              gRootDomain->swdDebugSetupEntry,
                              (thread_call_param_t)(uintptr_t) params->notifyRef);
        }
        else if (CAP_DID_CHANGE_TO_OFF(params, kIOPMSystemCapabilityGraphics) ||
                 CAP_DID_CHANGE_TO_ON(params, kIOPMSystemCapabilityGraphics))
        {
            // DidChange for Full wake -> Darkwake
           params->maxWaitForReply = 30 * 1000 * 1000;
           thread_call_enter1(
                              gRootDomain->swdDebugTearDownEntry,
                              (thread_call_param_t)(uintptr_t) params->notifyRef);

        }
#endif
        ret = kIOReturnSuccess;
    }

    return ret;
}

//******************************************************************************
// handleQueueSleepWakeUUID
//
// Called from IOPMrootDomain when we're initiating a sleep,
// or indirectly from PM configd when PM decides to clear the UUID.
// PM clears the UUID several minutes after successful wake from sleep,
// so that we might associate App spindumps with the immediately previous
// sleep/wake.
//
// @param   obj has a retain on it. We're responsible for releasing that retain.
//******************************************************************************

void IOPMrootDomain::handleQueueSleepWakeUUID(OSObject *obj)
{
    OSString    *str = NULL;

    if (kOSBooleanFalse == obj)
    {
        handlePublishSleepWakeUUID(NULL);
    }
    else if ((str = OSDynamicCast(OSString, obj)))
    {
        // This branch caches the UUID for an upcoming sleep/wake
        if (queuedSleepWakeUUIDString) {
            queuedSleepWakeUUIDString->release();
            queuedSleepWakeUUIDString = NULL;
        }
        queuedSleepWakeUUIDString = str;
        queuedSleepWakeUUIDString->retain();

        DLOG("SleepWake UUID queued: %s\n", queuedSleepWakeUUIDString->getCStringNoCopy());
    }

    if (obj) {
        obj->release();
    }
    return;

}
//******************************************************************************
// handlePublishSleepWakeUUID
//
// Called from IOPMrootDomain when we're initiating a sleep,
// or indirectly from PM configd when PM decides to clear the UUID.
// PM clears the UUID several minutes after successful wake from sleep,
// so that we might associate App spindumps with the immediately previous
// sleep/wake.
//******************************************************************************

void IOPMrootDomain::handlePublishSleepWakeUUID( bool shouldPublish )
{
   ASSERT_GATED();

   /*
    * Clear the current UUID
    */
   if (gSleepWakeUUIDIsSet)
   {
        DLOG("SleepWake UUID cleared\n");

        gSleepWakeUUIDIsSet = false;

        removeProperty(kIOPMSleepWakeUUIDKey);
        messageClients(kIOPMMessageSleepWakeUUIDChange, kIOPMMessageSleepWakeUUIDCleared);
    }

    /*
     * Optionally, publish a new UUID
     */
    if (queuedSleepWakeUUIDString && shouldPublish) {

        OSString  *publishThisUUID = NULL;

        publishThisUUID = queuedSleepWakeUUIDString;
        publishThisUUID->retain();

        if (publishThisUUID)
        {
            setProperty(kIOPMSleepWakeUUIDKey, publishThisUUID);
            publishThisUUID->release();
        }

        gSleepWakeUUIDIsSet = true;
        messageClients(kIOPMMessageSleepWakeUUIDChange, kIOPMMessageSleepWakeUUIDSet);

        queuedSleepWakeUUIDString->release();
        queuedSleepWakeUUIDString = NULL;
    }
}

//******************************************************************************
// initializeBootSessionUUID
//
// Initialize the boot session uuid at boot up and sets it into registry.
//******************************************************************************

void IOPMrootDomain::initializeBootSessionUUID(void)
{
    uuid_t          new_uuid;
    uuid_string_t   new_uuid_string;

    uuid_generate(new_uuid);
    uuid_unparse_upper(new_uuid, new_uuid_string);
    memcpy(bootsessionuuid_string, new_uuid_string, sizeof(uuid_string_t));

    setProperty(kIOPMBootSessionUUIDKey, new_uuid_string);
}

//******************************************************************************
// changePowerStateTo & changePowerStateToPriv
//
// Override of these methods for logging purposes.
//******************************************************************************

IOReturn IOPMrootDomain::changePowerStateTo( unsigned long ordinal )
{
    DLOG("changePowerStateTo(%lu)\n", ordinal);

    if ((ordinal != ON_STATE) && (ordinal != SLEEP_STATE))
        return kIOReturnUnsupported;

    return super::changePowerStateTo(ordinal);
}

IOReturn IOPMrootDomain::changePowerStateToPriv( unsigned long ordinal )
{
    DLOG("changePowerStateToPriv(%lu)\n", ordinal);

    if ((ordinal != ON_STATE) && (ordinal != SLEEP_STATE))
        return kIOReturnUnsupported;

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

    if (ret && !hibernateAborted && checkSystemCanSustainFullWake())
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
// willNotifyPowerChildren
//
// Called after all interested drivers have all acknowledged the power change,
// but before any power children is informed. Dispatched though a thread call,
// so it is safe to perform work that might block on a sleeping disk. PM state
// machine (not thread) will block w/o timeout until this function returns.
//******************************************************************************

void IOPMrootDomain::willNotifyPowerChildren( IOPMPowerStateIndex newPowerState )
{
    OSDictionary *dict;
    OSNumber *secs;

    if (SLEEP_STATE == newPowerState)
    {
        if (!tasksSuspended)
        {
	    AbsoluteTime deadline;
	    tasksSuspended = TRUE;
	    tasks_system_suspend(tasksSuspended);

	    clock_interval_to_deadline(10, kSecondScale, &deadline);
	    vm_pageout_wait(AbsoluteTime_to_scalar(&deadline));
        }

#if HIBERNATION
        IOHibernateSystemSleep();
        IOHibernateIOKitSleep();
#endif
        if (gRootDomain->activitySinceSleep()) {
            dict = OSDictionary::withCapacity(1);
            secs = OSNumber::withNumber(1, 32);

            if (dict && secs) {
                dict->setObject(gIOPMSettingDebugWakeRelativeKey, secs);
                gRootDomain->setProperties(dict);
                MSG("Reverting sleep with relative wake\n");
            }
            if (dict) dict->release();
            if (secs) secs->release();
        }

    }
}

//******************************************************************************
// sleepOnClamshellClosed
//
// contains the logic to determine if the system should sleep when the clamshell
// is closed.
//******************************************************************************

bool IOPMrootDomain::shouldSleepOnClamshellClosed( void )
{
    if (!clamshellExists)
        return false;

    DLOG("clamshell closed %d, disabled %d, desktopMode %d, ac %d sleepDisabled %d\n",
        clamshellClosed, clamshellDisabled, desktopMode, acAdaptorConnected, clamshellSleepDisabled);

    return ( !clamshellDisabled && !(desktopMode && acAdaptorConnected) && !clamshellSleepDisabled );
}

void IOPMrootDomain::sendClientClamshellNotification( void )
{
    /* Only broadcast clamshell alert if clamshell exists. */
    if (!clamshellExists)
        return;

    setProperty(kAppleClamshellStateKey,
        clamshellClosed ? kOSBooleanTrue : kOSBooleanFalse);

    setProperty(kAppleClamshellCausesSleepKey,
        shouldSleepOnClamshellClosed() ? kOSBooleanTrue : kOSBooleanFalse);

    /* Argument to message is a bitfiel of
     *      ( kClamshellStateBit | kClamshellSleepBit )
     */
    messageClients(kIOPMMessageClamshellStateChange,
        (void *)(uintptr_t) ( (clamshellClosed ? kClamshellStateBit : 0)
             | ( shouldSleepOnClamshellClosed() ? kClamshellSleepBit : 0)) );
}

//******************************************************************************
// getSleepSupported
//
// Deprecated
//******************************************************************************

IOOptionBits IOPMrootDomain::getSleepSupported( void )
{
    return( platformSleepSupport );
}

//******************************************************************************
// setSleepSupported
//
// Deprecated
//******************************************************************************

void IOPMrootDomain::setSleepSupported( IOOptionBits flags )
{
    DLOG("setSleepSupported(%x)\n", (uint32_t) flags);
    OSBitOrAtomic(flags, &platformSleepSupport);
}

//******************************************************************************
// setDisableClamShellSleep
//
//******************************************************************************

void IOPMrootDomain::setDisableClamShellSleep( bool val )
{
    if (gIOPMWorkLoop->inGate() == false) {

       gIOPMWorkLoop->runAction(
               OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::setDisableClamShellSleep),
               (OSObject *)this,
               (void *)val);

       return;
    }
    else {
       DLOG("setDisableClamShellSleep(%x)\n", (uint32_t) val);
       if ( clamshellSleepDisabled != val )
       {
           clamshellSleepDisabled = val;
           // If clamshellSleepDisabled is reset to 0, reevaluate if
           // system need to go to sleep due to clamshell state
           if ( !clamshellSleepDisabled && clamshellClosed)
              handlePowerNotification(kLocalEvalClamshellCommand);
       }
    }
}

//******************************************************************************
// wakeFromDoze
//
// Deprecated.
//******************************************************************************

void IOPMrootDomain::wakeFromDoze( void )
{
    // Preserve symbol for familes (IOUSBFamily and IOGraphics)
}

// MARK: -
// MARK: Features

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

    if (kBadPMFeatureID == removeFeatureID)
        return kIOReturnNotFound;

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
// publishPMSetting (private)
//
// Should only be called by PMSettingObject to publish a PM Setting as a
// supported feature.
//******************************************************************************

void IOPMrootDomain::publishPMSetting(
    const OSSymbol * feature, uint32_t where, uint32_t * featureID )
{
    if (noPublishPMSettings &&
        (noPublishPMSettings->getNextIndexOfObject(feature, 0) != (unsigned int)-1))
    {
        // Setting found in noPublishPMSettings array
        *featureID = kBadPMFeatureID;
        return;
    }

    publishFeature(
        feature->getCStringNoCopy(), where, featureID);
}

//******************************************************************************
// setPMSetting (private)
//
// Internal helper to relay PM settings changes from user space to individual
// drivers. Should be called only by IOPMrootDomain::setProperties.
//******************************************************************************

IOReturn IOPMrootDomain::setPMSetting(
    const OSSymbol  *type,
    OSObject        *object )
{
    PMSettingCallEntry  *entries = 0;
    OSArray             *chosen  = 0;
    const OSArray       *array;
    PMSettingObject     *pmso;
    thread_t            thisThread;
    int                 i, j, count, capacity;

    if (NULL == type)
        return kIOReturnBadArgument;

    PMSETTING_LOCK();

    // Update settings dict so changes are visible from copyPMSetting().
    fPMSettingsDict->setObject(type, object);

    // Prep all PMSetting objects with the given 'type' for callout.
    array = OSDynamicCast(OSArray, settingsCallbacks->getObject(type));
    if (!array || ((capacity = array->getCount()) == 0))
        goto unlock_exit;

    // Array to retain PMSetting objects targeted for callout.
    chosen = OSArray::withCapacity(capacity);
    if (!chosen)
        goto unlock_exit;   // error

    entries = IONew(PMSettingCallEntry, capacity);
    if (!entries)
        goto unlock_exit;   // error
    memset(entries, 0, sizeof(PMSettingCallEntry) * capacity);

    thisThread = current_thread();

    for (i = 0, j = 0; i<capacity; i++)
    {
        pmso = (PMSettingObject *) array->getObject(i);
        if (pmso->disabled)
            continue;
        entries[j].thread = thisThread;
        queue_enter(&pmso->calloutQueue, &entries[j], PMSettingCallEntry *, link);
        chosen->setObject(pmso);
        j++;
    }
    count = j;
    if (!count)
        goto unlock_exit;

    PMSETTING_UNLOCK();

    // Call each pmso in the chosen array.
    for (i=0; i<count; i++)
    {
        pmso = (PMSettingObject *) chosen->getObject(i);
        pmso->dispatchPMSetting(type, object);
    }

    PMSETTING_LOCK();
    for (i=0; i<count; i++)
    {
        pmso = (PMSettingObject *) chosen->getObject(i);
        queue_remove(&pmso->calloutQueue, &entries[i], PMSettingCallEntry *, link);
        if (pmso->waitThread)
        {
            PMSETTING_WAKEUP(pmso);
        }
    }
unlock_exit:
    PMSETTING_UNLOCK();

    if (chosen)  chosen->release();
    if (entries) IODelete(entries, PMSettingCallEntry, capacity);

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

    PMSETTING_LOCK();
    obj = fPMSettingsDict->getObject(whichSetting);
    if(obj) {
        obj->retain();
    }
    PMSETTING_UNLOCK();

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
    PMSettingObject *pmso = NULL;
    OSObject        *pmsh = NULL;
    OSArray         *list = NULL;
    int             i;

    if (NULL == settings ||
        NULL == func     ||
        NULL == handle)
    {
        return kIOReturnBadArgument;
    }

    pmso = PMSettingObject::pmSettingObject(
                (IOPMrootDomain *) this, func, target,
                refcon, supportedPowerSources, settings, &pmsh);

    if (!pmso) {
        *handle = NULL;
        return kIOReturnInternalError;
    }

    PMSETTING_LOCK();
    for (i=0; settings[i]; i++)
    {
        list = OSDynamicCast(OSArray, settingsCallbacks->getObject(settings[i]));
        if (!list) {
            // New array of callbacks for this setting
            list = OSArray::withCapacity(1);
            settingsCallbacks->setObject(settings[i], list);
            list->release();
        }

        // Add caller to the callback list
        list->setObject(pmso);
    }
    PMSETTING_UNLOCK();

    // Return handle to the caller, the setting object is private.
    *handle = pmsh;

    return kIOReturnSuccess;
}

//******************************************************************************
// deregisterPMSettingObject (private)
//
// Only called from PMSettingObject.
//******************************************************************************

void IOPMrootDomain::deregisterPMSettingObject( PMSettingObject * pmso )
{
    thread_t                thisThread = current_thread();
    PMSettingCallEntry      *callEntry;
    OSCollectionIterator    *iter;
    OSSymbol                *sym;
    OSArray                 *array;
    int                     index;
    bool                    wait;

    PMSETTING_LOCK();

    pmso->disabled = true;

    // Wait for all callout threads to finish.
    do {
        wait = false;
        queue_iterate(&pmso->calloutQueue, callEntry, PMSettingCallEntry *, link)
        {
            if (callEntry->thread != thisThread)
            {
                wait = true;
                break;
            }
        }
        if (wait)
        {
            assert(0 == pmso->waitThread);
            pmso->waitThread = thisThread;
            PMSETTING_WAIT(pmso);
            pmso->waitThread = 0;
        }
    } while (wait);

    // Search each PM settings array in the kernel.
    iter = OSCollectionIterator::withCollection(settingsCallbacks);
    if (iter)
    {
        while ((sym = OSDynamicCast(OSSymbol, iter->getNextObject())))
        {
            array = OSDynamicCast(OSArray, settingsCallbacks->getObject(sym));
            index = array->getNextIndexOfObject(pmso, 0);
            if (-1 != index) {
                array->removeObject(index);
            }
        }
        iter->release();
    }

    PMSETTING_UNLOCK();

    pmso->release();
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
    strlcpy( (char *)varInfoStruct.varName,
             (const char *)varNameStr,
             sizeof(varInfoStruct.varName));

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

// MARK: -
// MARK: Deep Sleep Policy

#if HIBERNATION

//******************************************************************************
// evaluateSystemSleepPolicy
//******************************************************************************

#define kIOPlatformSystemSleepPolicyKey     "IOPlatformSystemSleepPolicy"

// Sleep flags
enum {
    kIOPMSleepFlagHibernate         = 0x00000001,
    kIOPMSleepFlagSleepTimerEnable  = 0x00000002
};

struct IOPMSystemSleepPolicyEntry
{
    uint32_t    factorMask;
    uint32_t    factorBits;
    uint32_t    sleepFlags;
    uint32_t    wakeEvents;
} __attribute__((packed));

struct IOPMSystemSleepPolicyTable
{
    uint32_t    signature;
    uint16_t    version;
    uint16_t    entryCount;
    IOPMSystemSleepPolicyEntry  entries[];
} __attribute__((packed));

enum {
    kIOPMSleepAttributeHibernateSetup   = 0x00000001,
    kIOPMSleepAttributeHibernateSleep   = 0x00000002
};

static uint32_t
getSleepTypeAttributes( uint32_t sleepType )
{
    static const uint32_t sleepTypeAttributes[ kIOPMSleepTypeLast ] =
    {
    /* invalid   */ 0,
    /* abort     */ 0,
    /* normal    */ 0,
    /* safesleep */ kIOPMSleepAttributeHibernateSetup,
    /* hibernate */ kIOPMSleepAttributeHibernateSetup | kIOPMSleepAttributeHibernateSleep,
    /* standby   */ kIOPMSleepAttributeHibernateSetup | kIOPMSleepAttributeHibernateSleep,
    /* poweroff  */ kIOPMSleepAttributeHibernateSetup | kIOPMSleepAttributeHibernateSleep,
    /* deepidle  */ 0
    };

    if (sleepType >= kIOPMSleepTypeLast)
        return 0;

    return sleepTypeAttributes[sleepType];
}

bool IOPMrootDomain::evaluateSystemSleepPolicy(
    IOPMSystemSleepParameters * params, int sleepPhase, uint32_t * hibMode )
{
    const IOPMSystemSleepPolicyTable * pt;
    OSObject *  prop = 0;
    OSData *    policyData;
    uint64_t    currentFactors = 0;
    uint32_t    standbyDelay   = 0;
    uint32_t    powerOffDelay  = 0;
    uint32_t    powerOffTimer  = 0;
    uint32_t    mismatch;
    bool        standbyEnabled;
    bool        powerOffEnabled;
    bool        found = false;

    // Get platform's sleep policy table
    if (!gSleepPolicyHandler)
    {
        prop = getServiceRoot()->copyProperty(kIOPlatformSystemSleepPolicyKey);
        if (!prop) goto done;
    }

    // Fetch additional settings
    standbyEnabled = (getSleepOption(kIOPMDeepSleepDelayKey, &standbyDelay)
        && (getProperty(kIOPMDeepSleepEnabledKey) == kOSBooleanTrue));
    powerOffEnabled = (getSleepOption(kIOPMAutoPowerOffDelayKey, &powerOffDelay)
        && (getProperty(kIOPMAutoPowerOffEnabledKey) == kOSBooleanTrue));
    if (!getSleepOption(kIOPMAutoPowerOffTimerKey, &powerOffTimer))
        powerOffTimer = powerOffDelay;

    DLOG("phase %d, standby %d delay %u, poweroff %d delay %u timer %u, hibernate 0x%x\n",
        sleepPhase, standbyEnabled, standbyDelay,
        powerOffEnabled, powerOffDelay, powerOffTimer, *hibMode);

    // pmset level overrides
    if ((*hibMode & kIOHibernateModeOn) == 0)
    {
        if (!gSleepPolicyHandler)
        {
            standbyEnabled  = false;
            powerOffEnabled = false;
        }
    }
    else if (!(*hibMode & kIOHibernateModeSleep))
    {
        // Force hibernate (i.e. mode 25)
        // If standby is enabled, force standy.
        // If poweroff is enabled, force poweroff.
        if (standbyEnabled)
            currentFactors |= kIOPMSleepFactorStandbyForced;
        else if (powerOffEnabled)
            currentFactors |= kIOPMSleepFactorAutoPowerOffForced;
        else
            currentFactors |= kIOPMSleepFactorHibernateForced;
    }

    // Current factors based on environment and assertions
    if (sleepTimerMaintenance)
        currentFactors |= kIOPMSleepFactorSleepTimerWake;
    if (standbyEnabled && sleepToStandby && !gSleepPolicyHandler)
        currentFactors |= kIOPMSleepFactorSleepTimerWake;
    if (!clamshellClosed)
        currentFactors |= kIOPMSleepFactorLidOpen;
    if (acAdaptorConnected)
        currentFactors |= kIOPMSleepFactorACPower;
    if (lowBatteryCondition)
        currentFactors |= kIOPMSleepFactorBatteryLow;
    if (!standbyDelay)
        currentFactors |= kIOPMSleepFactorStandbyNoDelay;
    if (standbyNixed || !standbyEnabled)
        currentFactors |= kIOPMSleepFactorStandbyDisabled;
    if (resetTimers)
    {
        currentFactors |= kIOPMSleepFactorLocalUserActivity;
        currentFactors &= ~kIOPMSleepFactorSleepTimerWake;
    }
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
        currentFactors |= kIOPMSleepFactorThunderboltDevice;
    if (_scheduledAlarms != 0)
        currentFactors |= kIOPMSleepFactorRTCAlarmScheduled;
    if (getPMAssertionLevel(kIOPMDriverAssertionMagicPacketWakeEnabledBit) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorMagicPacketWakeEnabled;
#define TCPKEEPALIVE 1
#if TCPKEEPALIVE
    if (getPMAssertionLevel(kIOPMDriverAssertionNetworkKeepAliveActiveBit) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorNetworkKeepAliveActive;
#endif
    if (!powerOffEnabled)
        currentFactors |= kIOPMSleepFactorAutoPowerOffDisabled;
    if (desktopMode)
        currentFactors |= kIOPMSleepFactorExternalDisplay;
    if (userWasActive)
        currentFactors |= kIOPMSleepFactorLocalUserActivity;
    if (darkWakeHibernateError && !CAP_HIGHEST(kIOPMSystemCapabilityGraphics))
        currentFactors |= kIOPMSleepFactorHibernateFailed;
    if (thermalWarningState)
        currentFactors |= kIOPMSleepFactorThermalWarning;

    DLOG("sleep factors 0x%llx\n", currentFactors);

    if (gSleepPolicyHandler)
    {
        uint32_t    savedHibernateMode;
        IOReturn    result;

        if (!gSleepPolicyVars)
        {
            gSleepPolicyVars = IONew(IOPMSystemSleepPolicyVariables, 1);
            if (!gSleepPolicyVars)
                goto done;
            bzero(gSleepPolicyVars, sizeof(*gSleepPolicyVars));
        }
        gSleepPolicyVars->signature = kIOPMSystemSleepPolicySignature;
        gSleepPolicyVars->version   = kIOPMSystemSleepPolicyVersion;
        gSleepPolicyVars->currentCapability = _currentCapability;
        gSleepPolicyVars->highestCapability = _highestCapability;
        gSleepPolicyVars->sleepFactors      = currentFactors;
        gSleepPolicyVars->sleepReason       = lastSleepReason;
        gSleepPolicyVars->sleepPhase        = sleepPhase;
        gSleepPolicyVars->standbyDelay      = standbyDelay;
        gSleepPolicyVars->poweroffDelay     = powerOffDelay;
        gSleepPolicyVars->scheduledAlarms   = _scheduledAlarms | _userScheduledAlarm;
        gSleepPolicyVars->poweroffTimer     = powerOffTimer;

        if (kIOPMSleepPhase0 == sleepPhase)
        {
            // preserve hibernateMode
            savedHibernateMode = gSleepPolicyVars->hibernateMode;
            gSleepPolicyVars->hibernateMode = *hibMode;
        }
        else if (kIOPMSleepPhase1 == sleepPhase)
        {
            // use original hibernateMode for phase2
            gSleepPolicyVars->hibernateMode = *hibMode;
        }

        result = gSleepPolicyHandler(gSleepPolicyTarget, gSleepPolicyVars, params);

        if (kIOPMSleepPhase0 == sleepPhase)
        {
            // restore hibernateMode
            gSleepPolicyVars->hibernateMode = savedHibernateMode;
        }

        if ((result != kIOReturnSuccess) ||
             (kIOPMSleepTypeInvalid == params->sleepType) ||
             (params->sleepType >= kIOPMSleepTypeLast) ||
             (kIOPMSystemSleepParametersVersion != params->version))
        {
            MSG("sleep policy handler error\n");
            goto done;
        }

        if ((getSleepTypeAttributes(params->sleepType) &
             kIOPMSleepAttributeHibernateSetup) &&
            ((*hibMode & kIOHibernateModeOn) == 0))
        {
            *hibMode |= (kIOHibernateModeOn | kIOHibernateModeSleep);
        }

        DLOG("sleep params v%u, type %u, flags 0x%x, wake 0x%x, timer %u, poweroff %u\n",
            params->version, params->sleepType, params->sleepFlags,
            params->ecWakeEvents, params->ecWakeTimer, params->ecPoweroffTimer);
        found = true;
        goto done;
    }

    // Policy table is meaningless without standby enabled
    if (!standbyEnabled)
        goto done;

    // Validate the sleep policy table
    policyData = OSDynamicCast(OSData, prop);
    if (!policyData || (policyData->getLength() <= sizeof(IOPMSystemSleepPolicyTable)))
        goto done;

    pt = (const IOPMSystemSleepPolicyTable *) policyData->getBytesNoCopy();
    if ((pt->signature != kIOPMSystemSleepPolicySignature) ||
        (pt->version != 1) || (0 == pt->entryCount))
        goto done;

    if (((policyData->getLength() - sizeof(IOPMSystemSleepPolicyTable)) !=
         (sizeof(IOPMSystemSleepPolicyEntry) * pt->entryCount)))
        goto done;

    for (uint32_t i = 0; i < pt->entryCount; i++)
    {
        const IOPMSystemSleepPolicyEntry * entry = &pt->entries[i];
        mismatch = (((uint32_t)currentFactors ^ entry->factorBits) & entry->factorMask);

        DLOG("mask 0x%08x, bits 0x%08x, flags 0x%08x, wake 0x%08x, mismatch 0x%08x\n",
            entry->factorMask, entry->factorBits,
            entry->sleepFlags, entry->wakeEvents, mismatch);
        if (mismatch)
            continue;

        DLOG("^ found match\n");
        found = true;

        params->version = kIOPMSystemSleepParametersVersion;
        params->reserved1 = 1;
        if (entry->sleepFlags & kIOPMSleepFlagHibernate)
            params->sleepType = kIOPMSleepTypeStandby;
        else
            params->sleepType = kIOPMSleepTypeNormalSleep;

        params->ecWakeEvents = entry->wakeEvents;
        if (entry->sleepFlags & kIOPMSleepFlagSleepTimerEnable)
        {
            if (kIOPMSleepPhase2 == sleepPhase)
            {
                clock_sec_t now_secs = gIOLastSleepTime.tv_sec;

                if (!_standbyTimerResetSeconds ||
                    (now_secs <= _standbyTimerResetSeconds))
                {
                    // Reset standby timer adjustment
                    _standbyTimerResetSeconds = now_secs;
                    DLOG("standby delay %u, reset %u\n",
                        standbyDelay, (uint32_t) _standbyTimerResetSeconds);
                }
                else if (standbyDelay)
                {
                    // Shorten the standby delay timer
                    clock_sec_t elapsed = now_secs - _standbyTimerResetSeconds;
                    if (standbyDelay > elapsed)
                        standbyDelay -= elapsed;
                    else
                        standbyDelay = 1; // must be > 0

                    DLOG("standby delay %u, elapsed %u\n",
                        standbyDelay, (uint32_t) elapsed);
                }
            }
            params->ecWakeTimer = standbyDelay;
        }
        else if (kIOPMSleepPhase2 == sleepPhase)
        {
            // A sleep that does not enable the sleep timer will reset
            // the standby delay adjustment.
            _standbyTimerResetSeconds = 0;
        }
        break;
    }

done:
    if (prop)
        prop->release();

    return found;
}

static IOPMSystemSleepParameters gEarlySystemSleepParams;

void IOPMrootDomain::evaluateSystemSleepPolicyEarly( void )
{
    // Evaluate early (priority interest phase), before drivers sleep.

    DLOG("%s\n", __FUNCTION__);
    removeProperty(kIOPMSystemSleepParametersKey);

    // Full wake resets the standby timer delay adjustment
    if (_highestCapability & kIOPMSystemCapabilityGraphics)
        _standbyTimerResetSeconds = 0;

    hibernateDisabled = false;
    hibernateMode = 0;
    getSleepOption(kIOHibernateModeKey, &hibernateMode);

    // Save for late evaluation if sleep is aborted
    bzero(&gEarlySystemSleepParams, sizeof(gEarlySystemSleepParams));

    if (evaluateSystemSleepPolicy(&gEarlySystemSleepParams, kIOPMSleepPhase1,
                                  &hibernateMode))
    {
        if (!hibernateRetry &&
            ((getSleepTypeAttributes(gEarlySystemSleepParams.sleepType) &
              kIOPMSleepAttributeHibernateSetup) == 0))
        {
            // skip hibernate setup
            hibernateDisabled = true;
        }
    }

    // Publish IOPMSystemSleepType
    uint32_t sleepType = gEarlySystemSleepParams.sleepType;
    if (sleepType == kIOPMSleepTypeInvalid)
    {
        // no sleep policy
        sleepType = kIOPMSleepTypeNormalSleep;
        if (hibernateMode & kIOHibernateModeOn)
            sleepType = (hibernateMode & kIOHibernateModeSleep) ?
                        kIOPMSleepTypeSafeSleep : kIOPMSleepTypeHibernate;
    }
    else if ((sleepType == kIOPMSleepTypeStandby) &&
             (gEarlySystemSleepParams.ecPoweroffTimer))
    {
        // report the lowest possible sleep state
        sleepType = kIOPMSleepTypePowerOff;
    }

    setProperty(kIOPMSystemSleepTypeKey, sleepType, 32);
}

void IOPMrootDomain::evaluateSystemSleepPolicyFinal( void )
{
    IOPMSystemSleepParameters   params;
    OSData *                    paramsData;
    bool                        wakeNow;
    // Evaluate sleep policy after sleeping drivers but before platform sleep.

    DLOG("%s\n", __FUNCTION__);

    bzero(&params, sizeof(params));
    wakeNow = false;
    if (evaluateSystemSleepPolicy(&params, kIOPMSleepPhase2, &hibernateMode))
    {
        if ((kIOPMSleepTypeStandby == params.sleepType)
         && gIOHibernateStandbyDisabled
         && (!(kIOPMSleepFactorStandbyForced & gSleepPolicyVars->sleepFactors)))
        {
            standbyNixed = true;
            wakeNow = true;
        }
        if (wakeNow
        || ((hibernateDisabled || hibernateAborted) &&
            (getSleepTypeAttributes(params.sleepType) &
             kIOPMSleepAttributeHibernateSetup)))
        {
            // Final evaluation picked a state requiring hibernation,
            // but hibernate isn't going to proceed. Arm a short sleep using
            // the early non-hibernate sleep parameters.
            bcopy(&gEarlySystemSleepParams, &params, sizeof(params));
            params.sleepType = kIOPMSleepTypeAbortedSleep;
            params.ecWakeTimer = 1;
            if (standbyNixed)
            {
                resetTimers = true;
            }
            else
            {
                // Set hibernateRetry flag to force hibernate setup on the
                // next sleep.
                hibernateRetry = true;
            }
            DLOG("wake in %u secs for hibernateDisabled %d, hibernateAborted %d, standbyNixed %d\n",
               params.ecWakeTimer, hibernateDisabled, hibernateAborted, standbyNixed);
        }
        else
        {
            hibernateRetry = false;
        }

        if (kIOPMSleepTypeAbortedSleep != params.sleepType)
        {
            resetTimers = false;
        }

        paramsData = OSData::withBytes(&params, sizeof(params));
        if (paramsData)
        {
            setProperty(kIOPMSystemSleepParametersKey, paramsData);
            paramsData->release();
        }

        if (getSleepTypeAttributes(params.sleepType) &
            kIOPMSleepAttributeHibernateSleep)
        {
            // Disable sleep to force hibernation
            gIOHibernateMode &= ~kIOHibernateModeSleep;
        }
    }
}

bool IOPMrootDomain::getHibernateSettings(
    uint32_t *  hibernateModePtr,
    uint32_t *  hibernateFreeRatio,
    uint32_t *  hibernateFreeTime )
{
    // Called by IOHibernateSystemSleep() after evaluateSystemSleepPolicyEarly()
    // has updated the hibernateDisabled flag.

    bool ok = getSleepOption(kIOHibernateModeKey, hibernateModePtr);
    getSleepOption(kIOHibernateFreeRatioKey, hibernateFreeRatio);
    getSleepOption(kIOHibernateFreeTimeKey, hibernateFreeTime);
    if (hibernateDisabled)
        *hibernateModePtr = 0;
    else if (gSleepPolicyHandler)
        *hibernateModePtr = hibernateMode;
    DLOG("hibernateMode 0x%x\n", *hibernateModePtr);
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
    if (obj) 
    {
        if ((num = OSDynamicCast(OSNumber, obj)))
        {
            *option = num->unsigned32BitValue();
            ok = true;
        }
        else if (OSDynamicCast(OSBoolean, obj))
        {
            *option = (obj == kOSBooleanTrue) ? 1 : 0;
            ok = true;
        }
    }

    if (obj)
        obj->release();
    if (optionsProp)
        optionsProp->release();

    return true;
}
#endif /* HIBERNATION */

IOReturn IOPMrootDomain::getSystemSleepType( uint32_t * sleepType )
{
#if HIBERNATION
    IOPMSystemSleepParameters   params;
    uint32_t                    hibMode = 0;
    bool                        ok;

    if (gIOPMWorkLoop->inGate() == false)
    {
        IOReturn ret = gIOPMWorkLoop->runAction(
                        OSMemberFunctionCast(IOWorkLoop::Action, this,
                            &IOPMrootDomain::getSystemSleepType),
                        (OSObject *) this,
                        (void *) sleepType);
        return ret;
    }

    getSleepOption(kIOHibernateModeKey, &hibMode);
    bzero(&params, sizeof(params));

    ok = evaluateSystemSleepPolicy(&params, kIOPMSleepPhase0, &hibMode);
    if (ok)
    {
        *sleepType = params.sleepType;
        return kIOReturnSuccess;
    }
#endif

    return kIOReturnUnsupported;
}

// MARK: -
// MARK: Shutdown and Restart

//******************************************************************************
// handlePlatformHaltRestart
//
//******************************************************************************

struct HaltRestartApplierContext {
    IOPMrootDomain *    RootDomain;
    unsigned long       PowerState;
    IOPMPowerFlags      PowerFlags;
    UInt32              MessageType;
    UInt32              Counter;
    const char *        LogString;
};

static void
platformHaltRestartApplier( OSObject * object, void * context )
{
    IOPowerStateChangeNotification  notify;
    HaltRestartApplierContext *     ctx;
    AbsoluteTime                    startTime;
    uint32_t                        deltaTime;

    ctx = (HaltRestartApplierContext *) context;

    memset(&notify, 0, sizeof(notify));
    notify.powerRef    = (void *)(uintptr_t)ctx->Counter;
    notify.returnValue = 0;
    notify.stateNumber = ctx->PowerState;
    notify.stateFlags  = ctx->PowerFlags;

    clock_get_uptime(&startTime);
    ctx->RootDomain->messageClient( ctx->MessageType, object, (void *)&notify );
    deltaTime = computeDeltaTimeMS(&startTime);

    if ((deltaTime > kPMHaltTimeoutMS) ||
        (gIOKitDebug & kIOLogPMRootDomain))
    {
        _IOServiceInterestNotifier * notifier;
        notifier = OSDynamicCast(_IOServiceInterestNotifier, object);

        // IOService children of IOPMrootDomain are not instrumented.
        // Only IORootParent currently falls under that group.

        if (notifier)
        {
            LOG("%s handler %p took %u ms\n",
                ctx->LogString, OBFUSCATE(notifier->handler), deltaTime);
        }
    }

    ctx->Counter++;
}

static void quiescePowerTreeCallback( void * target, void * param )
{
    IOLockLock(gPMHaltLock);
    gPMQuiesced = true;
    thread_wakeup(param);
    IOLockUnlock(gPMHaltLock);
}

void IOPMrootDomain::handlePlatformHaltRestart( UInt32 pe_type )
{
    HaltRestartApplierContext   ctx;
    AbsoluteTime                startTime;
    uint32_t                    deltaTime;

    memset(&ctx, 0, sizeof(ctx));
    ctx.RootDomain = this;

    clock_get_uptime(&startTime);
    switch (pe_type)
    {
        case kPEHaltCPU:
        case kPEUPSDelayHaltCPU:
            ctx.PowerState  = OFF_STATE;
            ctx.MessageType = kIOMessageSystemWillPowerOff;
            ctx.LogString   = "PowerOff";
            break;

        case kPERestartCPU:
            ctx.PowerState  = RESTART_STATE;
            ctx.MessageType = kIOMessageSystemWillRestart;
            ctx.LogString   = "Restart";
            break;

        case kPEPagingOff:
            ctx.PowerState  = ON_STATE;
            ctx.MessageType = kIOMessageSystemPagingOff;
            ctx.LogString   = "PagingOff";
            IOService::updateConsoleUsers(NULL, kIOMessageSystemPagingOff);
#if HIBERNATION
            IOHibernateSystemRestart();
#endif
            break;

        default:
            return;
    }

    // Notify legacy clients
    applyToInterested(gIOPriorityPowerStateInterest, platformHaltRestartApplier, &ctx);

    // For normal shutdown, turn off File Server Mode.
    if (kPEHaltCPU == pe_type)
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

    if (kPEPagingOff != pe_type)
    {
        // Notify in power tree order
        notifySystemShutdown(this, ctx.MessageType);
    }

    IOCPURunPlatformHaltRestartActions(pe_type);

    // Wait for PM to quiesce
    if ((kPEPagingOff != pe_type) && gPMHaltLock)
    {
        AbsoluteTime quiesceTime = mach_absolute_time();

        IOLockLock(gPMHaltLock);
        gPMQuiesced = false;
        if (quiescePowerTree(this, &quiescePowerTreeCallback, &gPMQuiesced) ==
            kIOReturnSuccess)
        {
            while (!gPMQuiesced)
            {
                IOLockSleep(gPMHaltLock, &gPMQuiesced, THREAD_UNINT);
            }
        }
        IOLockUnlock(gPMHaltLock);

        deltaTime = computeDeltaTimeMS(&quiesceTime);
        DLOG("PM quiesce took %u ms\n", deltaTime);
    }

    deltaTime = computeDeltaTimeMS(&startTime);
    LOG("%s all drivers took %u ms\n", ctx.LogString, deltaTime);
}

//******************************************************************************
// shutdownSystem
//
//******************************************************************************

IOReturn IOPMrootDomain::shutdownSystem( void )
{
    return kIOReturnUnsupported;
}

//******************************************************************************
// restartSystem
//
//******************************************************************************

IOReturn IOPMrootDomain::restartSystem( void )
{
    return kIOReturnUnsupported;
}

// MARK: -
// MARK: System Capability

//******************************************************************************
// tagPowerPlaneService
//
// Running on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::tagPowerPlaneService(
        IOService *     service,
        IOPMActions *   actions )
{
    uint32_t    flags = 0;
    bool        isDisplayWrangler;

    memset(actions, 0, sizeof(*actions));
    actions->target = this;

    if (service == this)
    {
        actions->actionPowerChangeStart =
            OSMemberFunctionCast(
                IOPMActionPowerChangeStart, this,
                &IOPMrootDomain::handleOurPowerChangeStart);

        actions->actionPowerChangeDone =
            OSMemberFunctionCast(
                IOPMActionPowerChangeDone, this,
                &IOPMrootDomain::handleOurPowerChangeDone);

        actions->actionPowerChangeOverride =
            OSMemberFunctionCast(
                IOPMActionPowerChangeOverride, this,
                &IOPMrootDomain::overrideOurPowerChange);
        return;
    }

#if !NO_KERNEL_HID
    isDisplayWrangler = (0 != service->metaCast("IODisplayWrangler"));
    if (isDisplayWrangler)
    {
        wrangler = service;
    }
#else
    isDisplayWrangler = false;
#endif

#if defined(__i386__) || defined(__x86_64__)
    if (isDisplayWrangler)
        flags |= kPMActionsFlagIsDisplayWrangler;
    if (service->getProperty("IOPMStrictTreeOrder"))
        flags |= kPMActionsFlagIsGraphicsDevice;
    if (service->getProperty("IOPMUnattendedWakePowerState"))
        flags |= kPMActionsFlagIsAudioDevice;
#endif

    // Find the power connection object that is a child of the PCI host
    // bridge, and has a graphics/audio device attached below. Mark the
    // power branch for delayed child notifications.

    if (flags)
    {
        IORegistryEntry * child  = service;
        IORegistryEntry * parent = child->getParentEntry(gIOPowerPlane);

        while (child != this)
        {
            if ((parent == pciHostBridgeDriver) ||
                (parent == this))
            {
                if (OSDynamicCast(IOPowerConnection, child))
                {
                    IOPowerConnection * conn = (IOPowerConnection *) child;
                    conn->delayChildNotification = true;
                }
                break;
            }
            child = parent;
            parent = child->getParentEntry(gIOPowerPlane);
        }
    }

    if (flags)
    {
        DLOG("%s tag flags %x\n", service->getName(), flags);
        actions->parameter |= flags;
        actions->actionPowerChangeOverride =
            OSMemberFunctionCast(
                IOPMActionPowerChangeOverride, this,
                &IOPMrootDomain::overridePowerChangeForUIService);

        if (flags & kPMActionsFlagIsDisplayWrangler)
        {
            actions->actionActivityTickle =
                OSMemberFunctionCast(
                    IOPMActionActivityTickle, this,
                    &IOPMrootDomain::handleActivityTickleForDisplayWrangler);

            actions->actionUpdatePowerClient =
                OSMemberFunctionCast(
                    IOPMActionUpdatePowerClient, this,
                    &IOPMrootDomain::handleUpdatePowerClientForDisplayWrangler);
        }
        return;
    }

    // Locate the first PCI host bridge for PMTrace.
    if (!pciHostBridgeDevice && service->metaCast("IOPCIBridge"))
    {
        IOService * provider = service->getProvider();
        if (OSDynamicCast(IOPlatformDevice, provider) &&
            provider->inPlane(gIODTPlane))
        {
            pciHostBridgeDevice = provider;
            pciHostBridgeDriver = service;
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
                actions->parameter |= (bit & kPMActionsPCIBitNumberMask);

                actions->actionPowerChangeStart =
                    OSMemberFunctionCast(
                        IOPMActionPowerChangeStart, this,
                        &IOPMrootDomain::handlePowerChangeStartForPCIDevice);

                actions->actionPowerChangeDone =
                    OSMemberFunctionCast(
                        IOPMActionPowerChangeDone, this,
                        &IOPMrootDomain::handlePowerChangeDoneForPCIDevice);
            }
        }
    }
}

//******************************************************************************
// PM actions for root domain
//******************************************************************************

void IOPMrootDomain::overrideOurPowerChange(
    IOService *             service,
    IOPMActions *           actions,
    IOPMPowerStateIndex *   inOutPowerState,
    IOPMPowerChangeFlags *  inOutChangeFlags,
    IOPMRequestTag          requestTag )
{
    uint32_t powerState  = (uint32_t) *inOutPowerState;
    uint32_t changeFlags = *inOutChangeFlags;
    uint32_t currentPowerState = (uint32_t) getPowerState();

    if (changeFlags & kIOPMParentInitiated)
    {
        // Root parent is permanently pegged at max power,
        // a parent initiated power change is unexpected.
        *inOutChangeFlags |= kIOPMNotDone;
        return;
    }

    if (powerState < currentPowerState)
    {
        if (CAP_CURRENT(kIOPMSystemCapabilityGraphics))
        {
            // Root domain is dropping power state ON->SLEEP.
            // If system is in full wake, first enter dark wake by
            // converting the power drop to a capability change.
            // Once in dark wake, transition to sleep state ASAP.

            darkWakeToSleepASAP = true;

            // Drop graphics and audio capability
            _desiredCapability &= ~(
                kIOPMSystemCapabilityGraphics |
                kIOPMSystemCapabilityAudio    );

            // Convert to capability change (ON->ON)
            *inOutPowerState = ON_STATE;
            *inOutChangeFlags |= kIOPMSynchronize;

            // Revert device desire from SLEEP to ON
            changePowerStateToPriv(ON_STATE);
        }
        else
        {
            // System is in dark wake, ok to drop power state.
            // Broadcast root powering down to entire tree.
            *inOutChangeFlags |= kIOPMRootChangeDown;
        }
    }
    else if (powerState > currentPowerState)
    {
        if ((_currentCapability & kIOPMSystemCapabilityCPU) == 0)
        {
            // Broadcast power up when waking from sleep, but not for the
            // initial power change at boot by checking for cpu capability.
            *inOutChangeFlags |= kIOPMRootChangeUp;
        }
    }
}

void IOPMrootDomain::handleOurPowerChangeStart(
    IOService *             service,
    IOPMActions *           actions,
    IOPMPowerStateIndex     powerState,
    IOPMPowerChangeFlags *  inOutChangeFlags,
    IOPMRequestTag          requestTag )
{
    uint32_t changeFlags        = *inOutChangeFlags;
    uint32_t currentPowerState  = (uint32_t) getPowerState();
    uint32_t sleepReason        = requestTag ? requestTag : kIOPMSleepReasonIdle;
    bool     publishSleepReason = false;

    _systemTransitionType    = kSystemTransitionNone;
    _systemMessageClientMask = 0;
    capabilityLoss           = false;
    toldPowerdCapWillChange  = false;

    if (lowBatteryCondition)
    {
        // Low battery notification may arrive after the initial sleep request
        // has been queued. Override the sleep reason so powerd and others can
        // treat this as an emergency sleep.
        sleepReason = kIOPMSleepReasonLowPower;
    }

    // 1. Explicit capability change.

    if (changeFlags & kIOPMSynchronize)
    {
        if (powerState == ON_STATE)
        {
            if (changeFlags & kIOPMSyncNoChildNotify)
                _systemTransitionType = kSystemTransitionNewCapClient;
            else
                _systemTransitionType = kSystemTransitionCapability;
        }
    }

    // 2. Going to sleep (cancellation still possible).

    else if (powerState < currentPowerState)
        _systemTransitionType = kSystemTransitionSleep;

    // 3. Woke from (idle or demand) sleep.

    else if (!systemBooting &&
             (changeFlags & kIOPMSelfInitiated) &&
             (powerState > currentPowerState))
    {
        _systemTransitionType = kSystemTransitionWake;
        _desiredCapability = kIOPMSystemCapabilityCPU |
                             kIOPMSystemCapabilityNetwork;

        // Early exit from dark wake to full (e.g. LID open)
        if (kFullWakeReasonNone != fullWakeReason)
        {
            _desiredCapability |= (
                kIOPMSystemCapabilityGraphics |
                kIOPMSystemCapabilityAudio );
        }
#if HIBERNATION
    IOHibernateSetWakeCapabilities(_desiredCapability);
#endif
    }

    // Update pending wake capability at the beginning of every
    // state transition (including synchronize). This will become
    // the current capability at the end of the transition.

    if (kSystemTransitionSleep == _systemTransitionType)
    {
        _pendingCapability = 0;
        capabilityLoss = true;

    }
    else if (kSystemTransitionNewCapClient != _systemTransitionType)
    {
        _pendingCapability = _desiredCapability |
                             kIOPMSystemCapabilityCPU |
                             kIOPMSystemCapabilityNetwork;

        if (_pendingCapability & kIOPMSystemCapabilityGraphics)
            _pendingCapability |= kIOPMSystemCapabilityAudio;

        if ((kSystemTransitionCapability == _systemTransitionType) &&
            (_pendingCapability == _currentCapability))
        {
            // Cancel the PM state change.
            _systemTransitionType = kSystemTransitionNone;
            *inOutChangeFlags |= kIOPMNotDone;
        }
        if (__builtin_popcount(_pendingCapability) <
            __builtin_popcount(_currentCapability))
            capabilityLoss = true;
    }

    // 1. Capability change.

    if (kSystemTransitionCapability == _systemTransitionType)
    {
        // Dark to Full transition.
        if (CAP_GAIN(kIOPMSystemCapabilityGraphics))
        {
            tracePoint( kIOPMTracePointDarkWakeExit );

            willEnterFullWake();
        }

        // Full to Dark transition.
        if (CAP_LOSS(kIOPMSystemCapabilityGraphics))
        {
            // Clear previous stats
            IOLockLock(pmStatsLock);
            if (pmStatsAppResponses)
            {
                pmStatsAppResponses->release();
                pmStatsAppResponses = OSArray::withCapacity(5);
            }
            IOLockUnlock(pmStatsLock);


            tracePoint( kIOPMTracePointDarkWakeEntry );
            *inOutChangeFlags |= kIOPMSyncTellPowerDown;
            _systemMessageClientMask = kSystemMessageClientPowerd |
                                       kSystemMessageClientLegacyApp;


            // rdar://15971327
            // Prevent user active transitions before notifying clients
            // that system will sleep.
            preventTransitionToUserActive(true);

            IOService::setAdvisoryTickleEnable( false );

            // Publish the sleep reason for full to dark wake
            publishSleepReason = true;
            lastSleepReason = fullToDarkReason = sleepReason;

            // Publish a UUID for the Sleep --> Wake cycle
            handlePublishSleepWakeUUID(true);
            if (sleepDelaysReport) {
                clock_get_uptime(&ts_sleepStart);
                DLOG("sleepDelaysReport f->9 start at 0x%llx\n", ts_sleepStart);
            }

            wranglerTickled = false;
        }
    }

    // 2. System sleep.

    else if (kSystemTransitionSleep == _systemTransitionType)
    {
        // Beginning of a system sleep transition.
        // Cancellation is still possible.
        tracePoint( kIOPMTracePointSleepStarted );

        _systemMessageClientMask = kSystemMessageClientAll;
        if ((_currentCapability & kIOPMSystemCapabilityGraphics) == 0)
            _systemMessageClientMask &= ~kSystemMessageClientLegacyApp;
        if ((_highestCapability & kIOPMSystemCapabilityGraphics) == 0)
            _systemMessageClientMask &= ~kSystemMessageClientKernel;
#if HIBERNATION
        gIOHibernateState = 0;
#endif

        // Record the reason for dark wake back to sleep
        // System may not have ever achieved full wake

        publishSleepReason = true;
        lastSleepReason = sleepReason;
        if (sleepDelaysReport) {
            clock_get_uptime(&ts_sleepStart);
                DLOG("sleepDelaysReport 9->0 start at 0x%llx\n", ts_sleepStart);
        }
    }

    // 3. System wake.

    else if (kSystemTransitionWake == _systemTransitionType)
    {
        tracePoint( kIOPMTracePointWakeWillPowerOnClients );
        // Clear stats about sleep 

        if (_pendingCapability & kIOPMSystemCapabilityGraphics)
        {
            willEnterFullWake();
        }
        else
        {
            // Message powerd only
            _systemMessageClientMask = kSystemMessageClientPowerd;
            tellClients(kIOMessageSystemWillPowerOn);
        }
    }

    // The only location where the sleep reason is published. At this point
    // sleep can still be cancelled, but sleep reason should be published
    // early for logging purposes.

    if (publishSleepReason)
    {
        static const char * IOPMSleepReasons[] =
        {
            kIOPMClamshellSleepKey,
            kIOPMPowerButtonSleepKey,
            kIOPMSoftwareSleepKey,
            kIOPMOSSwitchHibernationKey,
            kIOPMIdleSleepKey,
            kIOPMLowPowerSleepKey,
            kIOPMThermalEmergencySleepKey,
            kIOPMMaintenanceSleepKey,
            kIOPMSleepServiceExitKey,
            kIOPMDarkWakeThermalEmergencyKey
        };

        // Record sleep cause in IORegistry
        uint32_t reasonIndex = sleepReason - kIOPMSleepReasonClamshell;
        if (reasonIndex < sizeof(IOPMSleepReasons)/sizeof(IOPMSleepReasons[0])) {
            DLOG("sleep reason %s\n", IOPMSleepReasons[reasonIndex]);
            setProperty(kRootDomainSleepReasonKey, IOPMSleepReasons[reasonIndex]);
        }
    }

    if ((kSystemTransitionNone != _systemTransitionType) &&
        (kSystemTransitionNewCapClient != _systemTransitionType))
    {
        _systemStateGeneration++;
        systemDarkWake = false;

        DLOG("=== START (%u->%u, 0x%x) type %u, gen %u, msg %x, "
             "dcp %x:%x:%x\n",
            currentPowerState, (uint32_t) powerState, *inOutChangeFlags,
            _systemTransitionType, _systemStateGeneration,
            _systemMessageClientMask,
            _desiredCapability, _currentCapability, _pendingCapability);
    }
}

void IOPMrootDomain::handleOurPowerChangeDone(
    IOService *             service,
    IOPMActions *           actions,
    IOPMPowerStateIndex     powerState,
    IOPMPowerChangeFlags    changeFlags,
    IOPMRequestTag          requestTag __unused )
{
    if (kSystemTransitionNewCapClient == _systemTransitionType)
    {
        _systemTransitionType = kSystemTransitionNone;
        return;
    }

    if (_systemTransitionType != kSystemTransitionNone)
    {
        uint32_t currentPowerState = (uint32_t) getPowerState();

        if (changeFlags & kIOPMNotDone)
        {
            // Power down was cancelled or vetoed.
            _pendingCapability = _currentCapability;
            lastSleepReason = 0;

            if (!CAP_CURRENT(kIOPMSystemCapabilityGraphics) &&
                 CAP_CURRENT(kIOPMSystemCapabilityCPU))
            {
                pmPowerStateQueue->submitPowerEvent(
                    kPowerEventPolicyStimulus,
                    (void *) kStimulusDarkWakeReentry,
                    _systemStateGeneration );
            }

            // Revert device desire to max.
            changePowerStateToPriv(ON_STATE);
        }
        else
        {
            // Send message on dark wake to full wake promotion.
            // tellChangeUp() handles the normal SLEEP->ON case.

            if (kSystemTransitionCapability == _systemTransitionType)
            {
                if (CAP_GAIN(kIOPMSystemCapabilityGraphics))
                {
                    lastSleepReason = 0; // stop logging wrangler tickles
                    tellClients(kIOMessageSystemHasPoweredOn);
                }
                if (CAP_LOSS(kIOPMSystemCapabilityGraphics))
                {
                    // Going dark, reset full wake state
                    // userIsActive will be cleared by wrangler powering down
                    fullWakeReason = kFullWakeReasonNone;

                    if (ts_sleepStart) {
                        clock_get_uptime(&wake2DarkwakeDelay);
                        SUB_ABSOLUTETIME(&wake2DarkwakeDelay, &ts_sleepStart);
                        DLOG("sleepDelaysReport f->9 end 0x%llx\n", wake2DarkwakeDelay);
                        ts_sleepStart = 0;
                    }
                }
            }

            // Reset state after exiting from dark wake.

            if (CAP_GAIN(kIOPMSystemCapabilityGraphics) ||
                CAP_LOSS(kIOPMSystemCapabilityCPU))
            {
                darkWakeMaintenance = false;
                darkWakeToSleepASAP = false;
                pciCantSleepValid   = false;
                darkWakeSleepService = false;

                if (CAP_LOSS(kIOPMSystemCapabilityCPU))
                {
                    // Remove the influence of display power assertion
                    // before next system wake.
                    if (wrangler) wrangler->changePowerStateForRootDomain(
                                                kWranglerPowerStateMin );
                    removeProperty(gIOPMUserTriggeredFullWakeKey);
                }
            }

            // Entered dark mode.

            if (((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0) &&
                 (_pendingCapability & kIOPMSystemCapabilityCPU))
            {
                // Queue an evaluation of whether to remain in dark wake,
                // and for how long. This serves the purpose of draining
                // any assertions from the queue.

                pmPowerStateQueue->submitPowerEvent(
                    kPowerEventPolicyStimulus,
                    (void *) kStimulusDarkWakeEntry,
                    _systemStateGeneration );
            }
        }

        DLOG("=== FINISH (%u->%u, 0x%x) type %u, gen %u, msg %x, "
             "dcp %x:%x:%x, dbgtimer %u\n",
            currentPowerState, (uint32_t) powerState, changeFlags,
            _systemTransitionType, _systemStateGeneration,
            _systemMessageClientMask,
            _desiredCapability, _currentCapability, _pendingCapability,
            _lastDebugWakeSeconds);

        if (_pendingCapability & kIOPMSystemCapabilityGraphics)
        {
            displayWakeCnt++;
#if DARK_TO_FULL_EVALUATE_CLAMSHELL
            if (clamshellExists && fullWakeThreadCall &&
                CAP_HIGHEST(kIOPMSystemCapabilityGraphics))
            {
                // Not the initial graphics full power, graphics won't
                // send a power notification to trigger a lid state
                // evaluation.

                AbsoluteTime deadline;
                clock_interval_to_deadline(45, kSecondScale, &deadline);
                thread_call_enter_delayed(fullWakeThreadCall, deadline);
            }
#endif
        }
        else if (CAP_GAIN(kIOPMSystemCapabilityCPU))
            darkWakeCnt++;

        // Update current system capability.
        if (_currentCapability != _pendingCapability)
            _currentCapability = _pendingCapability;

        // Update highest system capability.

        _highestCapability |= _currentCapability;

        if (darkWakePostTickle &&
            (kSystemTransitionWake == _systemTransitionType) &&
            (gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) ==
             kDarkWakeFlagHIDTickleLate)
        {
            darkWakePostTickle = false;
            reportUserInput();
        }
        else if (wranglerTickled) {
            requestFullWake( kFullWakeReasonLocalUser );
        }

        // Reset tracepoint at completion of capability change,
        // completion of wake transition, and aborted sleep transition.

        if ((_systemTransitionType == kSystemTransitionCapability) ||
            (_systemTransitionType == kSystemTransitionWake) ||
            ((_systemTransitionType == kSystemTransitionSleep) &&
             (changeFlags & kIOPMNotDone)))
        {
            setProperty(kIOPMSystemCapabilitiesKey, _currentCapability, 64);
            tracePoint( kIOPMTracePointSystemUp );
        }

        _systemTransitionType = kSystemTransitionNone;
        _systemMessageClientMask = 0;
        toldPowerdCapWillChange  = false;

        logGraphicsClamp = false;

        if (lowBatteryCondition) {
            privateSleepSystem (kIOPMSleepReasonLowPower);
        }
        else if ((fullWakeReason == kFullWakeReasonDisplayOn) && (!displayPowerOnRequested)) {
            // Request for full wake is removed while system is waking up to full wake
            DLOG("DisplayOn fullwake request is removed\n");
            handleDisplayPowerOn();
        }

    }
}

//******************************************************************************
// PM actions for graphics and audio.
//******************************************************************************

void IOPMrootDomain::overridePowerChangeForUIService(
    IOService *             service,
    IOPMActions *           actions,
    IOPMPowerStateIndex *   inOutPowerState,
    IOPMPowerChangeFlags *  inOutChangeFlags )
{
    uint32_t powerState  = (uint32_t) *inOutPowerState;
    uint32_t changeFlags = (uint32_t) *inOutChangeFlags;

    if (kSystemTransitionNone == _systemTransitionType)
    {
        // Not in midst of a system transition.
        // Do not modify power limit enable state.
    }
    else if ((actions->parameter & kPMActionsFlagLimitPower) == 0)
    {
        // Activate power limiter.

        if ((actions->parameter & kPMActionsFlagIsDisplayWrangler) &&
            ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0) &&
            (changeFlags & kIOPMSynchronize))
        {
            actions->parameter |= kPMActionsFlagLimitPower;
        }
        else if ((actions->parameter & kPMActionsFlagIsAudioDevice) &&
                 ((gDarkWakeFlags & kDarkWakeFlagAudioNotSuppressed) == 0) &&
                 ((_pendingCapability & kIOPMSystemCapabilityAudio) == 0) &&
                 (changeFlags & kIOPMSynchronize))
        {
            actions->parameter |= kPMActionsFlagLimitPower;
        }
        else if ((actions->parameter & kPMActionsFlagIsGraphicsDevice) &&
                 (_systemTransitionType == kSystemTransitionSleep))
        {
            // For graphics devices, arm the limiter when entering
            // system sleep. Not when dropping to dark wake.
            actions->parameter |= kPMActionsFlagLimitPower;
        }

        if (actions->parameter & kPMActionsFlagLimitPower)
        {
            DLOG("+ plimit %s %p\n",
                service->getName(), OBFUSCATE(service));
        }
    }
    else
    {
        // Remove power limit.

        if ((actions->parameter & (
            kPMActionsFlagIsDisplayWrangler |
            kPMActionsFlagIsGraphicsDevice )) &&
            (_pendingCapability & kIOPMSystemCapabilityGraphics))
        {
            actions->parameter &= ~kPMActionsFlagLimitPower;
        }
        else if ((actions->parameter & kPMActionsFlagIsAudioDevice) &&
                 (_pendingCapability & kIOPMSystemCapabilityAudio))
        {
            actions->parameter &= ~kPMActionsFlagLimitPower;
        }

        if ((actions->parameter & kPMActionsFlagLimitPower) == 0)
        {
            DLOG("- plimit %s %p\n",
                service->getName(), OBFUSCATE(service));
        }
    }

    if (actions->parameter & kPMActionsFlagLimitPower)
    {
        uint32_t maxPowerState = (uint32_t)(-1);

        if (changeFlags & (kIOPMDomainDidChange | kIOPMDomainWillChange))
        {
            // Enforce limit for system power/cap transitions.

            maxPowerState = 0;
            if ((service->getPowerState() > maxPowerState) &&
                (actions->parameter & kPMActionsFlagIsDisplayWrangler))
            {
                maxPowerState++;

                // Remove lingering effects of any tickle before entering
                // dark wake. It will take a new tickle to return to full
                // wake, so the existing tickle state is useless.

                if (changeFlags & kIOPMDomainDidChange)
                    *inOutChangeFlags |= kIOPMExpireIdleTimer;
            }
            else if (actions->parameter & kPMActionsFlagIsGraphicsDevice)
            {
                maxPowerState++;
            }
        }
        else
        {
            // Deny all self-initiated changes when power is limited.
            // Wrangler tickle should never defeat the limiter.

            maxPowerState = service->getPowerState();
        }

        if (powerState > maxPowerState)
        {
            DLOG("> plimit %s %p (%u->%u, 0x%x)\n",
                service->getName(), OBFUSCATE(service), powerState, maxPowerState,
                changeFlags);
            *inOutPowerState = maxPowerState;

            if (darkWakePostTickle &&
                (actions->parameter & kPMActionsFlagIsDisplayWrangler) &&
                (changeFlags & kIOPMDomainWillChange) &&
                ((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) ==
                 kDarkWakeFlagHIDTickleEarly))
            {
                darkWakePostTickle = false;
                reportUserInput();
            }
        }

        if (!graphicsSuppressed && (changeFlags & kIOPMDomainDidChange))
        {
            if (logGraphicsClamp)
            {
                AbsoluteTime    now;
                uint64_t        nsec;

                clock_get_uptime(&now);
                SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
                absolutetime_to_nanoseconds(now, &nsec);
                if (kIOLogPMRootDomain & gIOKitDebug)
                    MSG("Graphics suppressed %u ms\n",
                        ((int)((nsec) / 1000000ULL)));
            }
            graphicsSuppressed = true;
        }
    }
}

void IOPMrootDomain::handleActivityTickleForDisplayWrangler(
    IOService *     service,
    IOPMActions *   actions )
{
#if !NO_KERNEL_HID
    // Warning: Not running in PM work loop context - don't modify state !!!
    // Trap tickle directed to IODisplayWrangler while running with graphics
    // capability suppressed.

    assert(service == wrangler);

    clock_get_uptime(&userActivityTime);
    bool aborting = ((lastSleepReason == kIOPMSleepReasonIdle)
                  || (lastSleepReason == kIOPMSleepReasonMaintenance)
                  || (lastSleepReason == kIOPMSleepReasonSoftware));
    if (aborting) {
        userActivityCount++;
        DLOG("display wrangler tickled1 %d lastSleepReason %d\n",
            userActivityCount, lastSleepReason);
    }

    if (!wranglerTickled &&
        ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0))
    {
        DLOG("display wrangler tickled\n");
        if (kIOLogPMRootDomain & gIOKitDebug)
            OSReportWithBacktrace("Dark wake display tickle");
        if (pmPowerStateQueue)
        {
            pmPowerStateQueue->submitPowerEvent(
                kPowerEventPolicyStimulus,
                (void *) kStimulusDarkWakeActivityTickle,
                true /* set wake type */ );
        }
    }
#endif
}

void IOPMrootDomain::handleUpdatePowerClientForDisplayWrangler(
    IOService *             service,
    IOPMActions *           actions,
    const OSSymbol *        powerClient,
    IOPMPowerStateIndex     oldPowerState,
    IOPMPowerStateIndex     newPowerState )
{
#if !NO_KERNEL_HID
    assert(service == wrangler);

    // This function implements half of the user active detection
    // by monitoring changes to the display wrangler's device desire.
    //
    // User becomes active when either:
    // 1. Wrangler's DeviceDesire increases to max, but wrangler is already
    //    in max power state. This desire change in absence of a power state
    //    change is detected within. This handles the case when user becomes
    //    active while the display is already lit by setDisplayPowerOn().
    //
    // 2. Power state change to max, and DeviceDesire is also at max.
    //    Handled by displayWranglerNotification().
    //
    // User becomes inactive when DeviceDesire drops to sleep state or below.

    DLOG("wrangler %s (ps %u, %u->%u)\n",
        powerClient->getCStringNoCopy(),
        (uint32_t) service->getPowerState(),
        (uint32_t) oldPowerState, (uint32_t) newPowerState);

    if (powerClient == gIOPMPowerClientDevice)
    {
        if ((newPowerState > oldPowerState) &&
            (newPowerState == kWranglerPowerStateMax) &&
            (service->getPowerState() == kWranglerPowerStateMax))
        {
            evaluatePolicy( kStimulusEnterUserActiveState );
        }
        else
        if ((newPowerState < oldPowerState) &&
            (newPowerState <= kWranglerPowerStateSleep))
        {
            evaluatePolicy( kStimulusLeaveUserActiveState );
        }
    }

    if (newPowerState <= kWranglerPowerStateSleep) {
        evaluatePolicy( kStimulusDisplayWranglerSleep );
    }
    else if (newPowerState == kWranglerPowerStateMax) {
        evaluatePolicy( kStimulusDisplayWranglerWake );
    }
#endif
}

//******************************************************************************
// User active state management
//******************************************************************************

void IOPMrootDomain::preventTransitionToUserActive( bool prevent )
{
#if !NO_KERNEL_HID
    _preventUserActive = prevent;
    if (wrangler && !_preventUserActive)
    {
        // Allowing transition to user active, but the wrangler may have
        // already powered ON in case of sleep cancel/revert. Poll the
        // same conditions checked for in displayWranglerNotification()
        // to bring the user active state up to date.

        if ((wrangler->getPowerState() == kWranglerPowerStateMax) &&
            (wrangler->getPowerStateForClient(gIOPMPowerClientDevice) ==
             kWranglerPowerStateMax))
        {
            evaluatePolicy( kStimulusEnterUserActiveState );
        }
    }
#endif
}

//******************************************************************************
// Approve usage of delayed child notification by PM.
//******************************************************************************

bool IOPMrootDomain::shouldDelayChildNotification(
    IOService * service )
{
    if (((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) != 0) &&
        (kFullWakeReasonNone == fullWakeReason) &&
        (kSystemTransitionWake == _systemTransitionType))
    {
        DLOG("%s: delay child notify\n", service->getName());
        return true;
    }
    return false;
}

//******************************************************************************
// PM actions for PCI device.
//******************************************************************************

void IOPMrootDomain::handlePowerChangeStartForPCIDevice(
    IOService *             service,
    IOPMActions *           actions,
    IOPMPowerStateIndex     powerState,
    IOPMPowerChangeFlags *  inOutChangeFlags )
{
    pmTracer->tracePCIPowerChange(
        PMTraceWorker::kPowerChangeStart,
        service, *inOutChangeFlags,
        (actions->parameter & kPMActionsPCIBitNumberMask));
}

void IOPMrootDomain::handlePowerChangeDoneForPCIDevice(
    IOService *             service,
    IOPMActions *           actions,
    IOPMPowerStateIndex     powerState,
    IOPMPowerChangeFlags    changeFlags )
{
    pmTracer->tracePCIPowerChange(
        PMTraceWorker::kPowerChangeCompleted,
        service, changeFlags,
        (actions->parameter & kPMActionsPCIBitNumberMask));
}

//******************************************************************************
// registerInterest
//
// Override IOService::registerInterest() to intercept special clients.
//******************************************************************************

class IOPMServiceInterestNotifier: public _IOServiceInterestNotifier
{

    friend class IOPMrootDomain;
    OSDeclareDefaultStructors(IOPMServiceInterestNotifier)

protected:
    uint32_t    ackTimeoutCnt;
    uint32_t    msgType;  // Message pending ack

};

OSDefineMetaClassAndStructors(IOPMServiceInterestNotifier, _IOServiceInterestNotifier)

IONotifier * IOPMrootDomain::registerInterest(
                const OSSymbol * typeOfInterest,
                IOServiceInterestHandler handler,
                void * target, void * ref )
{
    IOPMServiceInterestNotifier *notifier = 0;
    bool            isSystemCapabilityClient;
    bool            isKernelCapabilityClient;
    IOReturn        rc = kIOReturnError;;

    isSystemCapabilityClient =
        typeOfInterest &&
        typeOfInterest->isEqualTo(kIOPMSystemCapabilityInterest);

    isKernelCapabilityClient =
        typeOfInterest &&
        typeOfInterest->isEqualTo(gIOPriorityPowerStateInterest);

    if (isSystemCapabilityClient)
        typeOfInterest = gIOAppPowerStateInterest;

    notifier = new IOPMServiceInterestNotifier;
    if (!notifier) return NULL;

    if (notifier->init()) {
        rc  = super::registerInterestForNotifer(notifier, typeOfInterest, handler, target, ref);
    }
    if (rc != kIOReturnSuccess) {
        notifier->release();
        notifier = 0;

        return NULL;
    }
    if (pmPowerStateQueue)
    {
        notifier->ackTimeoutCnt = 0;
        if (isSystemCapabilityClient)
        {
            notifier->retain();
            if (pmPowerStateQueue->submitPowerEvent(
                kPowerEventRegisterSystemCapabilityClient, notifier) == false)
                notifier->release();
        }

        if (isKernelCapabilityClient)
        {
            notifier->retain();
            if (pmPowerStateQueue->submitPowerEvent(
                kPowerEventRegisterKernelCapabilityClient, notifier) == false)
                notifier->release();
        }
    }

    return notifier;
}

//******************************************************************************
// systemMessageFilter
//
//******************************************************************************

bool IOPMrootDomain::systemMessageFilter(
    void * object, void * arg1, void * arg2, void * arg3 )
{
    const IOPMInterestContext * context = (const IOPMInterestContext *) arg1;
    bool  isCapMsg = (context->messageType == kIOMessageSystemCapabilityChange);
    bool  isCapClient = false;
    bool  allow = false;
    IOPMServiceInterestNotifier *notifier;

    notifier = OSDynamicCast(IOPMServiceInterestNotifier, (OSObject *)object);
    do {
        if ((kSystemTransitionNewCapClient == _systemTransitionType) &&
            (!isCapMsg || !_joinedCapabilityClients ||
             !_joinedCapabilityClients->containsObject((OSObject *) object)))
            break;

        // Capability change message for app and kernel clients.

        if (isCapMsg)
        {
            if ((context->notifyType == kNotifyPriority) ||
                (context->notifyType == kNotifyCapabilityChangePriority))
                isCapClient = true;

            if ((context->notifyType == kNotifyCapabilityChangeApps) &&
                (object == (void *) systemCapabilityNotifier))
                isCapClient = true;
        }

        if (isCapClient)
        {
            IOPMSystemCapabilityChangeParameters * capArgs =
                (IOPMSystemCapabilityChangeParameters *) arg2;

            if (kSystemTransitionNewCapClient == _systemTransitionType)
            {
                capArgs->fromCapabilities = 0;
                capArgs->toCapabilities = _currentCapability;
                capArgs->changeFlags = 0;
            }
            else
            {
                capArgs->fromCapabilities = _currentCapability;
                capArgs->toCapabilities = _pendingCapability;

                if (context->isPreChange)
                    capArgs->changeFlags = kIOPMSystemCapabilityWillChange;
                else
                    capArgs->changeFlags = kIOPMSystemCapabilityDidChange;

                if ((object == (void *) systemCapabilityNotifier) &&
                    context->isPreChange)
                {
                    toldPowerdCapWillChange = true;
                }
            }

            // Capability change messages only go to the PM configd plugin.
            // Wait for response post-change if capabilitiy is increasing.
            // Wait for response pre-change if capability is decreasing.

            if ((context->notifyType == kNotifyCapabilityChangeApps) && arg3 &&
                ( (capabilityLoss && context->isPreChange) ||
                  (!capabilityLoss && !context->isPreChange) ) )
            {
                // app has not replied yet, wait for it
                *((OSObject **) arg3) = kOSBooleanFalse;

                if (notifier) {
                    notifier->msgType = context->messageType;
                }
            }

            allow = true;
            break;
        }

        // Capability client will always see kIOMessageCanSystemSleep,
        // even for demand sleep. It will also have a chance to veto
        // sleep one last time after all clients have responded to
        // kIOMessageSystemWillSleep

        if ((kIOMessageCanSystemSleep == context->messageType) ||
            (kIOMessageSystemWillNotSleep == context->messageType))
        {
            if (object == (OSObject *) systemCapabilityNotifier)
            {
                allow = true;
                if (notifier) {
                    notifier->msgType = context->messageType;
                }
                break;
            }

            // Not idle sleep, don't ask apps.
            if (context->changeFlags & kIOPMSkipAskPowerDown)
            {
                break;
            }
        }

        if (kIOPMMessageLastCallBeforeSleep == context->messageType)
        {
            if ((object == (OSObject *) systemCapabilityNotifier) &&
                CAP_HIGHEST(kIOPMSystemCapabilityGraphics) &&
                (fullToDarkReason == kIOPMSleepReasonIdle)) {
                if (notifier) {
                    notifier->msgType = context->messageType;
                }
                allow = true;
            }
            break;
        }

        // Reject capability change messages for legacy clients.
        // Reject legacy system sleep messages for capability client.

        if (isCapMsg || (object == (OSObject *) systemCapabilityNotifier))
        {
            break;
        }

        // Filter system sleep messages.

        if ((context->notifyType == kNotifyApps) &&
            (_systemMessageClientMask & kSystemMessageClientLegacyApp))
        {
            allow = true;

            if (notifier) {
                if (arg3) {
                    if (notifier->ackTimeoutCnt >= 3)
                        *((OSObject **) arg3) = kOSBooleanFalse;
                    else
                        *((OSObject **) arg3) = kOSBooleanTrue;
                }

                notifier->msgType = context->messageType;
            }
        }
        else if ((context->notifyType == kNotifyPriority) &&
                 (_systemMessageClientMask & kSystemMessageClientKernel))
        {
            allow = true;
        }
    }
    while (false);

    if (allow && isCapMsg && _joinedCapabilityClients)
    {
        _joinedCapabilityClients->removeObject((OSObject *) object);
        if (_joinedCapabilityClients->getCount() == 0)
        {
            DLOG("destroyed capability client set %p\n",
                OBFUSCATE(_joinedCapabilityClients));
            _joinedCapabilityClients->release();
            _joinedCapabilityClients = 0;
        }
    }

    return allow;
}

//******************************************************************************
// setMaintenanceWakeCalendar
//
//******************************************************************************

IOReturn IOPMrootDomain::setMaintenanceWakeCalendar(
    const IOPMCalendarStruct * calendar )
{
    OSData * data;
    IOReturn ret = 0;

    if (!calendar)
        return kIOReturnBadArgument;

    data = OSData::withBytesNoCopy((void *) calendar, sizeof(*calendar));
    if (!data)
        return kIOReturnNoMemory;

    if (kPMCalendarTypeMaintenance == calendar->selector) {
        ret = setPMSetting(gIOPMSettingMaintenanceWakeCalendarKey, data);
        if (kIOReturnSuccess == ret)
            OSBitOrAtomic(kIOPMAlarmBitMaintenanceWake, &_scheduledAlarms);
    } else
    if (kPMCalendarTypeSleepService == calendar->selector)
    {
        ret = setPMSetting(gIOPMSettingSleepServiceWakeCalendarKey, data);
        if (kIOReturnSuccess == ret)
            OSBitOrAtomic(kIOPMAlarmBitSleepServiceWake, &_scheduledAlarms);
    }
    DLOG("_scheduledAlarms = 0x%x\n", (uint32_t) _scheduledAlarms);

    data->release();
    return ret;
}

// MARK: -
// MARK: Display Wrangler

//******************************************************************************
// displayWranglerNotification
//
// Handle the notification when the IODisplayWrangler changes power state.
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
    DLOG("wrangler %s ps %d\n",
         getIOMessageString(messageType), displayPowerState);

    switch (messageType) {
       case kIOMessageDeviceWillPowerOff:
            // Display wrangler has dropped power due to display idle
            // or force system sleep.
            //
            // 4 Display ON             kWranglerPowerStateMax
            // 3 Display Dim            kWranglerPowerStateDim
            // 2 Display Sleep          kWranglerPowerStateSleep
            // 1 Not visible to user
            // 0 Not visible to user    kWranglerPowerStateMin

            if (displayPowerState <= kWranglerPowerStateSleep)
                gRootDomain->evaluatePolicy( kStimulusDisplayWranglerSleep );
            break;

        case kIOMessageDeviceHasPoweredOn:
            // Display wrangler has powered on due to user activity
            // or wake from sleep.

            if (kWranglerPowerStateMax == displayPowerState)
            {
                gRootDomain->evaluatePolicy( kStimulusDisplayWranglerWake );

                // See comment in handleUpdatePowerClientForDisplayWrangler
                if (service->getPowerStateForClient(gIOPMPowerClientDevice) ==
                    kWranglerPowerStateMax)
                {
                    gRootDomain->evaluatePolicy( kStimulusEnterUserActiveState );
                }
            }
            break;
    }
#endif
    return kIOReturnUnsupported;
}

//******************************************************************************
// displayWranglerMatchPublished
//
// Receives a notification when the IODisplayWrangler is published.
// When it's published we install a power state change handler.
//******************************************************************************

bool IOPMrootDomain::displayWranglerMatchPublished(
    void * target,
    void * refCon,
    IOService * newService,
    IONotifier * notifier __unused)
{
#if !NO_KERNEL_HID
    // found the display wrangler, now install a handler
    if( !newService->registerInterest( gIOGeneralInterest,
                            &displayWranglerNotification, target, 0) )
    {
        return false;
    }
#endif
    return true;
}

#if defined(__i386__) || defined(__x86_64__)

bool IOPMrootDomain::IONVRAMMatchPublished(
    void * target,
    void * refCon,
    IOService * newService,
    IONotifier * notifier)
{
    unsigned int     len = 0;
    IOPMrootDomain *rd = (IOPMrootDomain *)target;
    OSNumber    *statusCode = NULL;

    if (PEReadNVRAMProperty(kIOSleepWakeDebugKey, NULL, &len))
    {
        statusCode = OSDynamicCast(OSNumber, rd->getProperty(kIOPMSleepWakeFailureCodeKey));
        if (statusCode != NULL) {
            if (statusCode->unsigned64BitValue() != 0) {
                rd->swd_flags |= SWD_BOOT_BY_SW_WDOG;
                MSG("System was rebooted due to Sleep/Wake failure\n");
            }
            else {
                rd->swd_flags |= SWD_BOOT_BY_OSX_WDOG;
                MSG("System was non-responsive and was rebooted by watchdog\n");
            }
        }

        rd->swd_logBufMap = rd->sleepWakeDebugRetrieve();
    }
    if (notifier) notifier->remove();
    return true;
}

#else
bool IOPMrootDomain::IONVRAMMatchPublished(
    void * target,
    void * refCon,
    IOService * newService,
    IONotifier * notifier __unused)
{
    return false;
}

#endif

//******************************************************************************
// reportUserInput
//
//******************************************************************************

void IOPMrootDomain::reportUserInput( void )
{
#if !NO_KERNEL_HID
    OSIterator * iter;
    OSDictionary * matching;

    if(!wrangler)
    {
        matching = serviceMatching("IODisplayWrangler");
        iter = getMatchingServices(matching);
        if (matching) matching->release();
        if(iter)
        {
            wrangler = OSDynamicCast(IOService, iter->getNextObject());
            iter->release();
        }
    }

    if(wrangler)
        wrangler->activityTickle(0,0);
#endif
}

//******************************************************************************
// latchDisplayWranglerTickle
//******************************************************************************

bool IOPMrootDomain::latchDisplayWranglerTickle( bool latch )
{
#if !NO_KERNEL_HID
    if (latch)
    {
        if (!(_currentCapability & kIOPMSystemCapabilityGraphics) &&
            !(_pendingCapability & kIOPMSystemCapabilityGraphics) &&
            !checkSystemCanSustainFullWake())
        {
            // Currently in dark wake, and not transitioning to full wake.
            // Full wake is unsustainable, so latch the tickle to prevent
            // the display from lighting up momentarily.
            wranglerTickleLatched = true;
        }
        else
        {
            wranglerTickleLatched = false;
        }
    }
    else if (wranglerTickleLatched && checkSystemCanSustainFullWake())
    {
        wranglerTickleLatched = false;

        pmPowerStateQueue->submitPowerEvent(
            kPowerEventPolicyStimulus,
            (void *) kStimulusDarkWakeActivityTickle );
    }

    return wranglerTickleLatched;
#else
    return false;
#endif
}

//******************************************************************************
// setDisplayPowerOn
//
// For root domain user client
//******************************************************************************

void IOPMrootDomain::setDisplayPowerOn( uint32_t options )
{
    pmPowerStateQueue->submitPowerEvent( kPowerEventSetDisplayPowerOn,
                                         (void *) 0, options );
}

// MARK: -
// MARK: Battery

//******************************************************************************
// batteryPublished
//
// Notification on battery class IOPowerSource appearance
//******************************************************************************

bool IOPMrootDomain::batteryPublished(
    void * target,
    void * root_domain,
    IOService * resourceService,
    IONotifier * notifier __unused )
{
    // rdar://2936060&4435589
    // All laptops have dimmable LCD displays
    // All laptops have batteries
    // So if this machine has a battery, publish the fact that the backlight
    // supports dimming.
    ((IOPMrootDomain *)root_domain)->publishFeature("DisplayDims");

    return (true);
}

// MARK: -
// MARK: System PM Policy

//******************************************************************************
// checkSystemSleepAllowed
//
//******************************************************************************

bool IOPMrootDomain::checkSystemSleepAllowed( IOOptionBits options,
                                              uint32_t     sleepReason )
{
    int err = 0;

    // Conditions that prevent idle and demand system sleep.

    do {
        if (userDisabledAllSleep)
        {
            err = 1;        // 1. user-space sleep kill switch
            break;
        }

        if (systemBooting || systemShutdown || gWillShutdown)
        {
            err = 2;        // 2. restart or shutdown in progress
            break;
        }

        if (options == 0)
            break;

        // Conditions above pegs the system at full wake.
        // Conditions below prevent system sleep but does not prevent
        // dark wake, and must be called from gated context.

#if !CONFIG_SLEEP
        err = 3;            // 3. config does not support sleep
        break;
#endif

        if (lowBatteryCondition || thermalWarningState)
        {
            break;          // always sleep on low battery or when in thermal warning state
        }

        if (sleepReason == kIOPMSleepReasonDarkWakeThermalEmergency)
        {
            break;          // always sleep on dark wake thermal emergencies
        }

        if (preventSystemSleepList->getCount() != 0)
        {
            err = 4;        // 4. child prevent system sleep clamp
            break;
        }

        if (getPMAssertionLevel( kIOPMDriverAssertionCPUBit ) ==
            kIOPMDriverAssertionLevelOn)
        {
            err = 5;        // 5. CPU assertion
            break;
        }

        if (pciCantSleepValid)
        {
            if (pciCantSleepFlag)
                err = 6;    // 6. PCI card does not support PM (cached)
            break;
        }
        else if (sleepSupportedPEFunction &&
                 CAP_HIGHEST(kIOPMSystemCapabilityGraphics))
        {
            IOReturn ret;
            OSBitAndAtomic(~kPCICantSleep, &platformSleepSupport);
            ret = getPlatform()->callPlatformFunction(
                                    sleepSupportedPEFunction, false,
                                    NULL, NULL, NULL, NULL);
            pciCantSleepValid = true;
            pciCantSleepFlag  = false;
            if ((platformSleepSupport & kPCICantSleep) ||
                ((ret != kIOReturnSuccess) && (ret != kIOReturnUnsupported)))
            {
                err = 6;    // 6. PCI card does not support PM
                pciCantSleepFlag = true;
                break;
            }
        }
    }
    while (false);

    if (err)
    {
        DLOG("System sleep prevented by %d\n", err);
        return false;
    }
    return true;
}

bool IOPMrootDomain::checkSystemSleepEnabled( void )
{
    return checkSystemSleepAllowed(0, 0);
}

bool IOPMrootDomain::checkSystemCanSleep( uint32_t sleepReason )
{
    ASSERT_GATED();
    return checkSystemSleepAllowed(1, sleepReason);
}

//******************************************************************************
// checkSystemCanSustainFullWake
//******************************************************************************

bool IOPMrootDomain::checkSystemCanSustainFullWake( void )
{
#if !NO_KERNEL_HID
    if (lowBatteryCondition || thermalWarningState)
    {
        // Low battery wake, or received a low battery notification
        // while system is awake. This condition will persist until
        // the following wake.
        return false;
    }

    if (clamshellExists && clamshellClosed && !clamshellSleepDisabled)
    {
        // Graphics state is unknown and external display might not be probed.
        // Do not incorporate state that requires graphics to be in max power
        // such as desktopMode or clamshellDisabled.

        if (!acAdaptorConnected)
        {
            DLOG("full wake check: no AC\n");
            return false;
        }
    }
#endif
    return true;
}

//******************************************************************************
// mustHibernate
//******************************************************************************

#if HIBERNATION

bool IOPMrootDomain::mustHibernate( void )
{
    return (lowBatteryCondition || thermalWarningState);
}

#endif /* HIBERNATION */

//******************************************************************************
// adjustPowerState
//
// Conditions that affect our wake/sleep decision has changed.
// If conditions dictate that the system must remain awake, clamp power
// state to max with changePowerStateToPriv(ON). Otherwise if sleepASAP
// is TRUE, then remove the power clamp and allow the power state to drop
// to SLEEP_STATE.
//******************************************************************************

void IOPMrootDomain::adjustPowerState( bool sleepASAP )
{
    DLOG("adjustPowerState ps %u, asap %d, idleSleepEnabled %d\n",
        (uint32_t) getPowerState(), sleepASAP, idleSleepEnabled);

    ASSERT_GATED();

    if ((!idleSleepEnabled) || !checkSystemSleepEnabled())
    {
        changePowerStateToPriv(ON_STATE);
    }
    else if ( sleepASAP )
    {
        changePowerStateToPriv(SLEEP_STATE);
    }
}

void IOPMrootDomain::handleDisplayPowerOn( )
{
    if (!wrangler) return;
    if (displayPowerOnRequested)
    {
        if (!checkSystemCanSustainFullWake()) return;

        // Force wrangler to max power state. If system is in dark wake
        // this alone won't raise the wrangler's power state.

        wrangler->changePowerStateForRootDomain(kWranglerPowerStateMax);

        // System in dark wake, always requesting full wake should
        // not have any bad side-effects, even if the request fails.

        if (!CAP_CURRENT(kIOPMSystemCapabilityGraphics))
        {
            setProperty(kIOPMRootDomainWakeTypeKey, kIOPMRootDomainWakeTypeNotification);
            requestFullWake( kFullWakeReasonDisplayOn );
        }
    }
    else
    {
        // Relenquish desire to power up display.
        // Must first transition to state 1 since wrangler doesn't
        // power off the displays at state 0. At state 0 the root
        // domain is removed from the wrangler's power client list.

        wrangler->changePowerStateForRootDomain(kWranglerPowerStateMin + 1);
        wrangler->changePowerStateForRootDomain(kWranglerPowerStateMin);

    }

}

//******************************************************************************
// dispatchPowerEvent
//
// IOPMPowerStateQueue callback function. Running on PM work loop thread.
//******************************************************************************

void IOPMrootDomain::dispatchPowerEvent(
    uint32_t event, void * arg0, uint64_t arg1 )
{
    DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
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

                if (lowBatteryCondition)
                {
                    privateSleepSystem (kIOPMSleepReasonLowPower);

                    // The rest is unnecessary since the system is expected
                    // to sleep immediately. The following wake will update
                    // everything.
                    break;
                }

                if (swd_flags & SWD_VALID_LOGS) {
                    if (swd_flags & SWD_LOGS_IN_MEM) {
                        sleepWakeDebugDumpFromMem(swd_logBufMap);
                        swd_logBufMap->release();
                        swd_logBufMap = 0;
                    }
                    else if (swd_flags & SWD_LOGS_IN_FILE) 
                        sleepWakeDebugDumpFromFile();
                }
                else if (swd_flags & (SWD_BOOT_BY_SW_WDOG|SWD_BOOT_BY_OSX_WDOG)) {
                    // If logs are invalid, write the failure code
                    sleepWakeDebugDumpFromMem(NULL);
                }
                // If lid is closed, re-send lid closed notification
                // now that booting is complete.
                if ( clamshellClosed )
                {
                    handlePowerNotification(kLocalEvalClamshellCommand);
                }
                evaluatePolicy( kStimulusAllowSystemSleepChanged );

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
                systemShutdown = true;
            } else {
                /*
                 A shutdown was initiated, but then the shutdown
                 was cancelled, clearing systemShutdown to false here.
                */
                systemShutdown = false;
            }
            break;

        case kPowerEventUserDisabledSleep:
            userDisabledAllSleep = (kOSBooleanTrue == (OSBoolean *) arg0);
            break;

        case kPowerEventRegisterSystemCapabilityClient:
            if (systemCapabilityNotifier)
            {
                systemCapabilityNotifier->release();
                systemCapabilityNotifier = 0;
            }
            if (arg0)
            {
                systemCapabilityNotifier = (IONotifier *) arg0;
                systemCapabilityNotifier->retain();
            }
            /* intentional fall-through */
            [[clang::fallthrough]];

        case kPowerEventRegisterKernelCapabilityClient:
            if (!_joinedCapabilityClients)
                _joinedCapabilityClients = OSSet::withCapacity(8);
            if (arg0)
            {
                IONotifier * notify = (IONotifier *) arg0;
                if (_joinedCapabilityClients)
                {
                    _joinedCapabilityClients->setObject(notify);
                    synchronizePowerTree( kIOPMSyncNoChildNotify );
                }
                notify->release();
            }
            break;

        case kPowerEventPolicyStimulus:
            if (arg0)
            {
                int stimulus = (uintptr_t) arg0;
                evaluatePolicy( stimulus, (uint32_t) arg1 );
            }
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

        case kPowerEventQueueSleepWakeUUID:
            handleQueueSleepWakeUUID((OSObject *)arg0);
            break;
        case kPowerEventPublishSleepWakeUUID:
            handlePublishSleepWakeUUID((bool)arg0);
            break;

        case kPowerEventSetDisplayPowerOn:
            if (!wrangler) break;
            if (arg1 != 0)
            {
                displayPowerOnRequested = true;
            }
            else
            {
                displayPowerOnRequested = false;
            }
            handleDisplayPowerOn();
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

void IOPMrootDomain::setThermalState(OSObject *value)
{
   OSNumber * num;

   if (gIOPMWorkLoop->inGate() == false) {
       gIOPMWorkLoop->runAction(
               OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::setThermalState),
               (OSObject *)this,
               (void *)value);

       return;
    }
    if (value && (num = OSDynamicCast(OSNumber, value))) {
        thermalWarningState = ((num->unsigned32BitValue() == kIOPMThermalLevelWarning) || 
                               (num->unsigned32BitValue() == kIOPMThermalLevelTrap)) ? 1 : 0; 
    }
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

    if (shouldUpdate) {
        if (event && 
             event->isEqualTo(kIOPMThermalLevelWarningKey)) {
             setThermalState(value);
        }
        messageClients (kIOPMMessageSystemPowerEventOccurred, (void *)NULL);
    }

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
        kPowerEventReceivedPowerNotification, (void *)(uintptr_t) msg );
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
        MSG("PowerManagement emergency overtemp signal. Going to sleep!");
        privateSleepSystem (kIOPMSleepReasonThermalEmergency);
    }

    /*
     * Forward DW thermal notification to client, if system is not going to sleep
     */
    if ((msg & kIOPMDWOverTemp) && (_systemTransitionType != kSystemTransitionSleep))
    {
        DLOG("DarkWake thermal limits message received!\n");

        messageClients(kIOPMMessageDarkWakeThermalEmergency);
    }

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
        clamshellClosed = false;
        clamshellExists = true;

        // Don't issue a hid tickle when lid is open and polled on wake
        if (msg & kIOPMSetValue)
        {
            setProperty(kIOPMRootDomainWakeTypeKey, "Lid Open");
            reportUserInput();
        }

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
        clamshellClosed = true;
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
        eval_clamshell = true;
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
        eval_clamshell = true;

        // Lack of AC may have latched a display wrangler tickle.
        // This mirrors the hardware's USB wake event latch, where a latched
        // USB wake event followed by an AC attach will trigger a full wake.
        latchDisplayWranglerTickle( false );

#if HIBERNATION
        // AC presence will reset the standy timer delay adjustment.
        _standbyTimerResetSeconds = 0;
#endif
        if (!userIsActive) {
            // Reset userActivityTime when power supply is changed(rdr 13789330)
            clock_get_uptime(&userActivityTime);
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
        if (true == clamshellDisabled)
        {
            eval_clamshell = true;
        }

        clamshellDisabled = false;
        sendClientClamshellNotification();
    }

    /*
     * Disable Clamshell (external display appeared)
     * We don't bother re-evaluating clamshell state. If the system is awake,
     * the lid is probably open.
     */
    if (msg & kIOPMDisableClamshell)
    {
        clamshellDisabled = true;
        sendClientClamshellNotification();
    }

    /*
     * Evaluate clamshell and SLEEP if appropiate
     */
    if (eval_clamshell && clamshellClosed)
    {
        if (shouldSleepOnClamshellClosed())
            privateSleepSystem (kIOPMSleepReasonClamshell);
        else
            evaluatePolicy( kStimulusDarkWakeEvaluate );
    }

    /*
     * Power Button
     */
    if (msg & kIOPMPowerButton)
    {
        if (!wranglerAsleep)
        {
            OSString *pbs = OSString::withCString("DisablePowerButtonSleep");
            // Check that power button sleep is enabled
            if( pbs ) {
                if( kOSBooleanTrue != getProperty(pbs))
                    privateSleepSystem (kIOPMSleepReasonPowerButton);
            }
        }
        else
            reportUserInput();
    }
}

//******************************************************************************
// evaluatePolicy
//
// Evaluate root-domain policy in response to external changes.
//******************************************************************************

void IOPMrootDomain::evaluatePolicy( int stimulus, uint32_t arg )
{
    union {
        struct {
            int idleSleepEnabled    : 1;
            int idleSleepDisabled   : 1;
            int displaySleep        : 1;
            int sleepDelayChanged   : 1;
            int evaluateDarkWake    : 1;
            int adjustPowerState    : 1;
            int userBecameInactive  : 1;
        } bit;
        uint32_t u32;
    } flags;

    DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);

    ASSERT_GATED();
    flags.u32 = 0;

    switch (stimulus)
    {
        case kStimulusDisplayWranglerSleep:
            if (!wranglerAsleep)
            {
                // first transition to wrangler sleep or lower
                flags.bit.displaySleep = true;
            }
            break;

        case kStimulusDisplayWranglerWake:
            displayIdleForDemandSleep = false;
            wranglerAsleep = false;
            break;

        case kStimulusEnterUserActiveState:
            if (_preventUserActive)
            {
                DLOG("user active dropped\n");
                break;
            }
            if (!userIsActive)
            {
                userIsActive = true;
                userWasActive = true;

                // Stay awake after dropping demand for display power on
                if (kFullWakeReasonDisplayOn == fullWakeReason) {
                    fullWakeReason = fFullWakeReasonDisplayOnAndLocalUser;
                    DLOG("User activity while in notification wake\n");
                    changePowerStateWithOverrideTo( ON_STATE, 0);
                }

                kdebugTrace(kPMLogUserActiveState, 0, 1, 0);
                setProperty(gIOPMUserIsActiveKey, kOSBooleanTrue);
                messageClients(kIOPMMessageUserIsActiveChanged);
            }
            flags.bit.idleSleepDisabled = true;
            break;

        case kStimulusLeaveUserActiveState:
            if (userIsActive)
            {
                userIsActive = false;
                clock_get_uptime(&userBecameInactiveTime);
                flags.bit.userBecameInactive = true;

                kdebugTrace(kPMLogUserActiveState, 0, 0, 0);
                setProperty(gIOPMUserIsActiveKey, kOSBooleanFalse);
                messageClients(kIOPMMessageUserIsActiveChanged);
            }
            break;

        case kStimulusAggressivenessChanged:
        {
            unsigned long   minutesToIdleSleep  = 0;
            unsigned long   minutesToDisplayDim = 0;
            unsigned long   minutesDelta        = 0;

            // Fetch latest display and system sleep slider values.
            getAggressiveness(kPMMinutesToSleep, &minutesToIdleSleep);
            getAggressiveness(kPMMinutesToDim,   &minutesToDisplayDim);
            DLOG("aggressiveness changed: system %u->%u, display %u\n",
                (uint32_t) sleepSlider,
                (uint32_t) minutesToIdleSleep,
                (uint32_t) minutesToDisplayDim);

            DLOG("idle time -> %ld secs (ena %d)\n",
                idleSeconds, (minutesToIdleSleep != 0));


            // How long to wait before sleeping the system once
            // the displays turns off is indicated by 'extraSleepDelay'.

            if ( minutesToIdleSleep > minutesToDisplayDim )
                minutesDelta = minutesToIdleSleep - minutesToDisplayDim;
            else if ( minutesToIdleSleep == minutesToDisplayDim )
                minutesDelta = 1;

            if ((!idleSleepEnabled) && (minutesToIdleSleep != 0))
                idleSleepEnabled = flags.bit.idleSleepEnabled = true;

            if ((idleSleepEnabled) && (minutesToIdleSleep == 0)) {
                flags.bit.idleSleepDisabled = true;
                idleSleepEnabled = false;
            }
            if (0x7fffffff == minutesToIdleSleep)
                minutesToIdleSleep = idleSeconds;

            if (((minutesDelta != extraSleepDelay) ||
                        (userActivityTime != userActivityTime_prev)) &&
                !flags.bit.idleSleepEnabled && !flags.bit.idleSleepDisabled)
                flags.bit.sleepDelayChanged = true;

            if (systemDarkWake && !darkWakeToSleepASAP &&
                (flags.bit.idleSleepEnabled || flags.bit.idleSleepDisabled))
            {
                // Reconsider decision to remain in dark wake
                flags.bit.evaluateDarkWake = true;
            }

            sleepSlider = minutesToIdleSleep;
            extraSleepDelay = minutesDelta;
            userActivityTime_prev = userActivityTime;
        }   break;

        case kStimulusDemandSystemSleep:
            displayIdleForDemandSleep = true;
            if (wrangler && wranglerIdleSettings)
            {
                // Request wrangler idle only when demand sleep is triggered
                // from full wake.
                if(CAP_CURRENT(kIOPMSystemCapabilityGraphics))
                {
                    wrangler->setProperties(wranglerIdleSettings);
                    DLOG("Requested wrangler idle\n");
                }
            }
            // arg = sleepReason
            changePowerStateWithOverrideTo( SLEEP_STATE, arg );
            break;

        case kStimulusAllowSystemSleepChanged:
            flags.bit.adjustPowerState = true;
            break;

        case kStimulusDarkWakeActivityTickle:
            // arg == true implies real and not self generated wrangler tickle.
            // Update wake type on PM work loop instead of the tickle thread to
            // eliminate the possibility of an early tickle clobbering the wake
            // type set by the platform driver.
            if (arg == true)
                setProperty(kIOPMRootDomainWakeTypeKey, kIOPMRootDomainWakeTypeHIDActivity);
            
            if (false == wranglerTickled)
            {
                if (latchDisplayWranglerTickle(true))
                {
                    DLOG("latched tickle\n");
                    break;
                }

                wranglerTickled = true;
                DLOG("Requesting full wake after dark wake activity tickle\n");
                requestFullWake( kFullWakeReasonLocalUser );
            }
            break;

        case kStimulusDarkWakeEntry:
        case kStimulusDarkWakeReentry:
            // Any system transitions since the last dark wake transition
            // will invalid the stimulus.

            if (arg == _systemStateGeneration)
            {
                DLOG("dark wake entry\n");
                systemDarkWake = true;

                // Keep wranglerAsleep an invariant when wrangler is absent
                if (wrangler)
                    wranglerAsleep = true;

                if (kStimulusDarkWakeEntry == stimulus)
                {
                    clock_get_uptime(&userBecameInactiveTime);
                    flags.bit.evaluateDarkWake = true;
                }

                // Always accelerate disk spindown while in dark wake,
                // even if system does not support/allow sleep.

                cancelIdleSleepTimer();
                setQuickSpinDownTimeout();
            }
            break;

        case kStimulusDarkWakeEvaluate:
            if (systemDarkWake)
            {
                flags.bit.evaluateDarkWake = true;
            }
            break;

        case kStimulusNoIdleSleepPreventers:
            flags.bit.adjustPowerState = true;
            break;

    } /* switch(stimulus) */

    if (flags.bit.evaluateDarkWake && (kFullWakeReasonNone == fullWakeReason))
    {
        if (darkWakeToSleepASAP ||
            (clamshellClosed && !(desktopMode && acAdaptorConnected)))
        {
            uint32_t newSleepReason;

            if (CAP_HIGHEST(kIOPMSystemCapabilityGraphics))
            {
                // System was previously in full wake. Sleep reason from
                // full to dark already recorded in fullToDarkReason.

                if (lowBatteryCondition)
                    newSleepReason = kIOPMSleepReasonLowPower;
                else
                    newSleepReason = fullToDarkReason;
            }
            else
            {
                // In dark wake from system sleep.

                if (darkWakeSleepService)
                    newSleepReason = kIOPMSleepReasonSleepServiceExit;
                else
                    newSleepReason = kIOPMSleepReasonMaintenance;
            }

            if (checkSystemCanSleep(newSleepReason))
            {
                privateSleepSystem(newSleepReason);
            }
        }
        else // non-maintenance (network) dark wake
        {
            if (checkSystemCanSleep(kIOPMSleepReasonIdle))
            {
                // Release power clamp, and wait for children idle.
                adjustPowerState(true);
            }
            else
            {
                changePowerStateToPriv(ON_STATE);
            }
        }
    }

    if (systemDarkWake)
    {
        // The rest are irrelevant while system is in dark wake.
        flags.u32 = 0;
    }

    if ((flags.bit.displaySleep) &&
        (kFullWakeReasonDisplayOn == fullWakeReason))
    {
        // kIOPMSleepReasonMaintenance?
        DLOG("Display sleep while in notification wake\n");
        changePowerStateWithOverrideTo( SLEEP_STATE, kIOPMSleepReasonMaintenance );
    }

    if (flags.bit.userBecameInactive || flags.bit.sleepDelayChanged)
    {
        bool cancelQuickSpindown = false;

        if (flags.bit.sleepDelayChanged)
        {
            // Cancel existing idle sleep timer and quick disk spindown.
            // New settings will be applied by the idleSleepEnabled flag
            // handler below if idle sleep is enabled.

            DLOG("extra sleep timer changed\n");
            cancelIdleSleepTimer();
            cancelQuickSpindown = true;
        }
        else
        {
            DLOG("user inactive\n");
        }

        if (!userIsActive && idleSleepEnabled)
        {
            startIdleSleepTimer(getTimeToIdleSleep());
        }

        if (cancelQuickSpindown)
            restoreUserSpinDownTimeout();
    }

    if (flags.bit.idleSleepEnabled)
    {
        DLOG("idle sleep timer enabled\n");
        if (!wrangler)
        {
            changePowerStateToPriv(ON_STATE);
            startIdleSleepTimer( idleSeconds );
        }
        else
        {
            // Start idle timer if prefs now allow system sleep
            // and user is already inactive. Disk spindown is
            // accelerated upon timer expiration.

            if (!userIsActive)
            {
                startIdleSleepTimer(getTimeToIdleSleep());
            }
        }
    }

    if (flags.bit.idleSleepDisabled)
    {
        DLOG("idle sleep timer disabled\n");
        cancelIdleSleepTimer();
        restoreUserSpinDownTimeout();
        adjustPowerState();
    }

    if (flags.bit.adjustPowerState)
    {
        bool sleepASAP = false;

        if (!systemBooting && (preventIdleSleepList->getCount() == 0))
        {
            if (!wrangler)
            {
                changePowerStateToPriv(ON_STATE);
                if (idleSleepEnabled)
                {
                    // stay awake for at least idleSeconds
                    startIdleSleepTimer(idleSeconds);
                }
            }
            else if (!extraSleepDelay && !idleSleepTimerPending && !systemDarkWake)
            {
                sleepASAP = true;
            }
        }

        adjustPowerState(sleepASAP);
    }
}

//******************************************************************************
// requestFullWake
//
// Request transition from dark wake to full wake
//******************************************************************************

void IOPMrootDomain::requestFullWake( FullWakeReason reason )
{
    uint32_t        options = 0;
    IOService *     pciRoot = 0;
    bool            promotion = false;

    // System must be in dark wake and a valid reason for entering full wake
    if ((kFullWakeReasonNone == reason) ||
        (kFullWakeReasonNone != fullWakeReason) ||
        (CAP_CURRENT(kIOPMSystemCapabilityGraphics)))
    {
        return;
    }

    // Will clear reason upon exit from full wake
    fullWakeReason = reason;

    _desiredCapability |= (kIOPMSystemCapabilityGraphics |
                           kIOPMSystemCapabilityAudio);

    if ((kSystemTransitionWake == _systemTransitionType) &&
        !(_pendingCapability & kIOPMSystemCapabilityGraphics) &&
        !graphicsSuppressed)
    {
        // Promote to full wake while waking up to dark wake due to tickle.
        // PM will hold off notifying the graphics subsystem about system wake
        // as late as possible, so if a HID tickle does arrive, graphics can
        // power up on this same wake cycle. The latency to power up graphics
        // on the next cycle can be huge on some systems. However, once any
        // graphics suppression has taken effect, it is too late. All other
        // graphics devices must be similarly suppressed. But the delay till
        // the following cycle should be short.

        _pendingCapability |= (kIOPMSystemCapabilityGraphics |
                               kIOPMSystemCapabilityAudio);

        // Immediately bring up audio and graphics
        pciRoot = pciHostBridgeDriver;
        willEnterFullWake();
        promotion = true;
    }

    // Unsafe to cancel once graphics was powered.
    // If system woke from dark wake, the return to sleep can
    // be cancelled. "awake -> dark -> sleep" transition
    // can be canceled also, during the "dark --> sleep" phase
    // *prior* to driver power down.
    if (!CAP_HIGHEST(kIOPMSystemCapabilityGraphics) ||
        _pendingCapability == 0) {
        options |= kIOPMSyncCancelPowerDown;
    }

    synchronizePowerTree(options, pciRoot);
    if (kFullWakeReasonLocalUser == fullWakeReason)
    {
        // IOGraphics doesn't light the display even though graphics is
        // enabled in kIOMessageSystemCapabilityChange message(radar 9502104)
        // So, do an explicit activity tickle
        if (wrangler)
            wrangler->activityTickle(0,0);
    }

    // Log a timestamp for the initial full wake request.
    // System may not always honor this full wake request.
    if (!CAP_HIGHEST(kIOPMSystemCapabilityGraphics))
    {
        AbsoluteTime    now;
        uint64_t        nsec;

        clock_get_uptime(&now);
        SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
        absolutetime_to_nanoseconds(now, &nsec);
        MSG("full wake %s (reason %u) %u ms\n",
            promotion ? "promotion" : "request",
            fullWakeReason, ((int)((nsec) / 1000000ULL)));
    }
}

//******************************************************************************
// willEnterFullWake
//
// System will enter full wake from sleep, from dark wake, or from dark
// wake promotion. This function aggregate things that are in common to
// all three full wake transitions.
//
// Assumptions: fullWakeReason was updated
//******************************************************************************

void IOPMrootDomain::willEnterFullWake( void )
{
    hibernateRetry = false;
    sleepToStandby = false;
    standbyNixed   = false;
    resetTimers    = false;
    sleepTimerMaintenance = false;

    _systemMessageClientMask = kSystemMessageClientPowerd |
                               kSystemMessageClientLegacyApp;

    if ((_highestCapability & kIOPMSystemCapabilityGraphics) == 0)
    {
        // Initial graphics full power
        _systemMessageClientMask |= kSystemMessageClientKernel;

        // Set kIOPMUserTriggeredFullWakeKey before full wake for IOGraphics
        setProperty(gIOPMUserTriggeredFullWakeKey,
            (kFullWakeReasonLocalUser == fullWakeReason) ?
                kOSBooleanTrue : kOSBooleanFalse);
    }
#if HIBERNATION
    IOHibernateSetWakeCapabilities(_pendingCapability);
#endif

    IOService::setAdvisoryTickleEnable( true );
    tellClients(kIOMessageSystemWillPowerOn);
    preventTransitionToUserActive(false);
}

//******************************************************************************
// fullWakeDelayedWork
//
// System has already entered full wake. Invoked by a delayed thread call.
//******************************************************************************

void IOPMrootDomain::fullWakeDelayedWork( void )
{
#if DARK_TO_FULL_EVALUATE_CLAMSHELL
    // Not gated, don't modify state
    if ((kSystemTransitionNone == _systemTransitionType) &&
        CAP_CURRENT(kIOPMSystemCapabilityGraphics))
    {
        receivePowerNotification( kLocalEvalClamshellCommand );
    }
#endif
}

//******************************************************************************
// evaluateAssertions
//
//******************************************************************************
void IOPMrootDomain::evaluateAssertions(IOPMDriverAssertionType newAssertions, IOPMDriverAssertionType oldAssertions)
{
    IOPMDriverAssertionType changedBits = newAssertions ^ oldAssertions;

    messageClients(kIOPMMessageDriverAssertionsChanged);

    if (changedBits & kIOPMDriverAssertionPreventDisplaySleepBit) {

        if (wrangler) {
            bool value = (newAssertions & kIOPMDriverAssertionPreventDisplaySleepBit) ? true : false;

            DLOG("wrangler->setIgnoreIdleTimer\(%d)\n", value);
            wrangler->setIgnoreIdleTimer( value );
        }
    }

    if (changedBits & kIOPMDriverAssertionCPUBit) {
        evaluatePolicy(kStimulusDarkWakeEvaluate);
        if (!assertOnWakeSecs && gIOLastWakeAbsTime) {
                AbsoluteTime    now;
                clock_usec_t    microsecs;
                clock_get_uptime(&now);
                SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
                absolutetime_to_microtime(now, &assertOnWakeSecs, &microsecs);
                if (assertOnWakeReport)  {
                    HISTREPORT_TALLYVALUE(assertOnWakeReport, (int64_t)assertOnWakeSecs);
                    DLOG("Updated assertOnWake %lu\n", (unsigned long)assertOnWakeSecs);
                }
        }
    }

    if (changedBits & kIOPMDriverAssertionReservedBit7) {
        bool value = (newAssertions & kIOPMDriverAssertionReservedBit7) ? true : false;
        if (value) {
            DLOG("Driver assertion ReservedBit7 raised. Legacy IO preventing sleep\n");
            updatePreventIdleSleepList(this, true);
        }
        else {
            DLOG("Driver assertion ReservedBit7 dropped\n");
            updatePreventIdleSleepList(this, false);
        }
    }
}

// MARK: -
// MARK: Statistics

//******************************************************************************
// pmStats
//
//******************************************************************************

void IOPMrootDomain::pmStatsRecordEvent(
    int                 eventIndex,
    AbsoluteTime        timestamp)
{
    bool        starting = eventIndex & kIOPMStatsEventStartFlag ? true:false;
    bool        stopping = eventIndex & kIOPMStatsEventStopFlag ? true:false;
    uint64_t    delta;
    uint64_t    nsec;
    OSData *publishPMStats = NULL;

    eventIndex &= ~(kIOPMStatsEventStartFlag | kIOPMStatsEventStopFlag);

    absolutetime_to_nanoseconds(timestamp, &nsec);

    switch (eventIndex) {
        case kIOPMStatsHibernateImageWrite:
            if (starting)
                gPMStats.hibWrite.start = nsec;
            else if (stopping)
                gPMStats.hibWrite.stop = nsec;

            if (stopping) {
                delta = gPMStats.hibWrite.stop - gPMStats.hibWrite.start;
                IOLog("PMStats: Hibernate write took %qd ms\n", delta/1000000ULL);
            }
            break;
        case kIOPMStatsHibernateImageRead:
            if (starting)
                gPMStats.hibRead.start = nsec;
            else if (stopping)
                gPMStats.hibRead.stop = nsec;

            if (stopping) {
                delta = gPMStats.hibRead.stop - gPMStats.hibRead.start;
                IOLog("PMStats: Hibernate read took %qd ms\n", delta/1000000ULL);

                publishPMStats = OSData::withBytes(&gPMStats, sizeof(gPMStats));
                setProperty(kIOPMSleepStatisticsKey, publishPMStats);
                publishPMStats->release();
                bzero(&gPMStats, sizeof(gPMStats));
            }
            break;
    }
}

/*
 * Appends a record of the application response to
 * IOPMrootDomain::pmStatsAppResponses
 */
void IOPMrootDomain::pmStatsRecordApplicationResponse(
    const OSSymbol      *response,
    const char          *name,
    int                 messageType,
    uint32_t            delay_ms,
    uint64_t            id,
    OSObject            *object,
    IOPMPowerStateIndex powerState)
{
    OSDictionary    *responseDescription    = NULL;
    OSNumber        *delayNum               = NULL;
    OSNumber        *powerCaps              = NULL;
    OSNumber        *pidNum                 = NULL;
    OSNumber        *msgNum                 = NULL;
    const OSSymbol  *appname;
    const OSSymbol  *sleep = NULL, *wake = NULL;
    IOPMServiceInterestNotifier *notify = 0;

    if (object && (notify = OSDynamicCast(IOPMServiceInterestNotifier, object)))
    {
        if (response->isEqualTo(gIOPMStatsApplicationResponseTimedOut)) 
            notify->ackTimeoutCnt++;
        else
            notify->ackTimeoutCnt = 0;

    }

    if (response->isEqualTo(gIOPMStatsApplicationResponsePrompt) || 
         (_systemTransitionType == kSystemTransitionNone) || (_systemTransitionType == kSystemTransitionNewCapClient))
        return;


    if (response->isEqualTo(gIOPMStatsDriverPSChangeSlow)) {
        kdebugTrace(kPMLogDrvResponseDelay, id, messageType, delay_ms);
    }
    else if (notify) {
        kdebugTrace(kPMLogAppResponseDelay, id,  notify->msgType, delay_ms);
        notify->msgType = 0;
    }

    responseDescription = OSDictionary::withCapacity(5);
    if (responseDescription)
    {
        if (response) {
            responseDescription->setObject(_statsResponseTypeKey, response);
        }

        msgNum = OSNumber::withNumber(messageType, 32);
        if (msgNum) {
            responseDescription->setObject(_statsMessageTypeKey, msgNum);
            msgNum->release();
        }

        if (name && (strlen(name) > 0))
        {
            appname = OSSymbol::withCString(name);
            if (appname) {
                responseDescription->setObject(_statsNameKey, appname);
                appname->release();
            }
        }

        if (id != 0) {
            pidNum = OSNumber::withNumber(id, 32);
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

        if (response->isEqualTo(gIOPMStatsDriverPSChangeSlow)) {
            powerCaps = OSNumber::withNumber(powerState, 32);

#if !defined(__i386__) && !defined(__x86_64__) && (DEVELOPMENT || DEBUG)
            IOLog("%s::powerStateChange type(%d) to(%lu) async took %d ms\n",
                  name, messageType,
                  powerState, delay_ms);
#endif

        }
        else {
            powerCaps = OSNumber::withNumber(_pendingCapability, 32);
        }
        if (powerCaps) {
            responseDescription->setObject(_statsPowerCapsKey, powerCaps);
            powerCaps->release();
        }

        sleep = OSSymbol::withCString("Sleep");
        wake = OSSymbol::withCString("Wake");
        if (_systemTransitionType == kSystemTransitionSleep)  {
            responseDescription->setObject(kIOPMStatsSystemTransitionKey, sleep);
        }
        else if (_systemTransitionType == kSystemTransitionWake) {
            responseDescription->setObject(kIOPMStatsSystemTransitionKey, wake);
        }
        else if (_systemTransitionType == kSystemTransitionCapability) {
            if (CAP_LOSS(kIOPMSystemCapabilityGraphics))
                responseDescription->setObject(kIOPMStatsSystemTransitionKey, sleep);
            else if (CAP_GAIN(kIOPMSystemCapabilityGraphics))
                responseDescription->setObject(kIOPMStatsSystemTransitionKey, wake);
        }
        if (sleep) sleep->release();
        if (wake) wake->release();



        IOLockLock(pmStatsLock);
        if (pmStatsAppResponses && pmStatsAppResponses->getCount() < 50) {
            pmStatsAppResponses->setObject(responseDescription);
        }
        IOLockUnlock(pmStatsLock);

        responseDescription->release();
    }

    return;
}

// MARK: -
// MARK: PMTraceWorker

//******************************************************************************
// TracePoint support
//
//******************************************************************************

#define kIOPMRegisterNVRAMTracePointHandlerKey  \
        "IOPMRegisterNVRAMTracePointHandler"

IOReturn IOPMrootDomain::callPlatformFunction(
    const OSSymbol * functionName,
    bool waitForFunction,
    void * param1, void * param2,
    void * param3, void * param4 )
{
    uint32_t bootFailureCode = 0xffffffff;
    unsigned int len = sizeof(bootFailureCode);
    if (pmTracer && functionName &&
        functionName->isEqualTo(kIOPMRegisterNVRAMTracePointHandlerKey) &&
        !pmTracer->tracePointHandler && !pmTracer->tracePointTarget)
    {
        uint32_t    tracePointPhases, tracePointPCI;
        uint64_t    statusCode;

        pmTracer->tracePointHandler = (IOPMTracePointHandler) param1;
        pmTracer->tracePointTarget  = (void *) param2;
        tracePointPCI               = (uint32_t)(uintptr_t) param3;
        tracePointPhases            = (uint32_t)(uintptr_t) param4;
        if ((tracePointPhases & 0xff) == kIOPMTracePointSystemSleep) {
           if (!PEReadNVRAMProperty(kIOEFIBootRomFailureKey, &bootFailureCode, &len)) {
              MSG("Failed to read failure code from NVRam\n");
           }
           // Failure code from EFI/BootRom is a four byte structure
           tracePointPCI = OSSwapBigToHostInt32(bootFailureCode);
        }
        statusCode = (((uint64_t)tracePointPCI) << 32) | tracePointPhases;
        if ((tracePointPhases & 0xff) != kIOPMTracePointSystemUp) {
            MSG("Sleep failure code 0x%08x 0x%08x\n",
                tracePointPCI, tracePointPhases);
        }
        setProperty(kIOPMSleepWakeFailureCodeKey, statusCode, 64);
        pmTracer->tracePointHandler( pmTracer->tracePointTarget, 0, 0 );

        return kIOReturnSuccess;
    }
#if HIBERNATION
    else if (functionName &&
             functionName->isEqualTo(kIOPMInstallSystemSleepPolicyHandlerKey))
    {
        if (gSleepPolicyHandler)
            return kIOReturnExclusiveAccess;
        if (!param1)
            return kIOReturnBadArgument;
        gSleepPolicyHandler = (IOPMSystemSleepPolicyHandler) param1;
        gSleepPolicyTarget  = (void *) param2;
        setProperty("IOPMSystemSleepPolicyHandler", kOSBooleanTrue);
        return kIOReturnSuccess;
    }
#endif

    return super::callPlatformFunction(
        functionName, waitForFunction, param1, param2, param3, param4);
}

void IOPMrootDomain::kdebugTrace(uint32_t event, uint64_t id,
                                 uintptr_t param1, uintptr_t param2, uintptr_t param3)
{
    uint32_t code   = IODBG_POWER(event);
    uint64_t regId  = id;
    if (regId == 0) {
        regId  = getRegistryEntryID();
    }
    IOTimeStampConstant(code, (uintptr_t) regId, param1, param2, param3);
}


void IOPMrootDomain::tracePoint( uint8_t point )
{
    if (systemBooting) return;

    if (kIOPMTracePointWakeCapabilityClients == point)
        acceptSystemWakeEvents(false);

    kdebugTrace(kPMLogSleepWakeTracePoint, 0, point, 0);
    pmTracer->tracePoint(point);
}

void IOPMrootDomain::traceDetail(uint32_t msgType, uint32_t msgIndex, uintptr_t handler)
{
    if (!systemBooting) {
        uint32_t detail = ((msgIndex & 0xff) << 24) |
                          ((msgType & 0xfff) << 12) |
                          (handler & 0xfff);
        pmTracer->traceDetail( detail );
        kdebugTrace(kPMLogSleepWakeTracePoint, 0, pmTracer->getTracePhase(), msgType, handler & 0xfff);
    }
}


void IOPMrootDomain::configureReportGated(uint64_t channel_id, uint64_t action, void *result)
{
    size_t      reportSize;
    void        **report = NULL;
    uint32_t    bktCnt;
    uint32_t    bktSize;
    uint32_t    *clientCnt;

    ASSERT_GATED();

    report = NULL;
    if (channel_id == kAssertDelayChID) {
        report = &assertOnWakeReport;
        bktCnt = kAssertDelayBcktCnt;
        bktSize = kAssertDelayBcktSize;
        clientCnt = &assertOnWakeClientCnt;
    }
    else if (channel_id == kSleepDelaysChID) {
        report = &sleepDelaysReport;
        bktCnt = kSleepDelaysBcktCnt;
        bktSize = kSleepDelaysBcktSize;
        clientCnt = &sleepDelaysClientCnt;
    }

    switch (action)
    {
        case kIOReportEnable:

            if (*report) {
                (*clientCnt)++;
                break;
            }

            reportSize = HISTREPORT_BUFSIZE(bktCnt);
            *report = IOMalloc(reportSize);
            if (*report == NULL) {
                break;
            }
            bzero(*report, reportSize);
            HISTREPORT_INIT(bktCnt, bktSize, *report, reportSize,
                                 getRegistryEntryID(), channel_id,  kIOReportCategoryPower);

            if (channel_id == kAssertDelayChID)
                assertOnWakeSecs = 0;

            break;

        case kIOReportDisable:
            if (*clientCnt == 0) {
                break;
            }
            if (*clientCnt == 1)
            {
                IOFree(*report, HISTREPORT_BUFSIZE(bktCnt));
                *report = NULL;
            }
            (*clientCnt)--;

            if (channel_id == kAssertDelayChID)
                assertOnWakeSecs = -1;  // Invalid value to prevent updates

            break;

        case kIOReportGetDimensions:
            if (*report) {
                HISTREPORT_UPDATERES(*report, kIOReportGetDimensions, result);
            }
            break;
    }

    return;
}

IOReturn IOPMrootDomain::configureReport(IOReportChannelList    *channelList,
                                    IOReportConfigureAction action,
                                    void                   *result,
                                    void                   *destination)
{
    unsigned cnt;
    uint64_t configAction = (uint64_t)action;

    for (cnt = 0; cnt < channelList->nchannels; cnt++) {
        if ( (channelList->channels[cnt].channel_id == kSleepCntChID) ||
               (channelList->channels[cnt].channel_id == kDarkWkCntChID) ||
               (channelList->channels[cnt].channel_id == kUserWkCntChID) ) {
            if (action != kIOReportGetDimensions) continue;
            SIMPLEREPORT_UPDATERES(kIOReportGetDimensions, result);
        }
        else if ((channelList->channels[cnt].channel_id == kAssertDelayChID) ||
                 (channelList->channels[cnt].channel_id == kSleepDelaysChID)) {
            gIOPMWorkLoop->runAction(
                     OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::configureReportGated),
                     (OSObject *)this, (void *)channelList->channels[cnt].channel_id,
                     (void *)configAction, (void *)result);
        }
    }

    return super::configureReport(channelList, action, result, destination);
}

IOReturn IOPMrootDomain::updateReportGated(uint64_t ch_id, void *result, IOBufferMemoryDescriptor *dest)
{

    uint32_t    size2cpy;
    void        *data2cpy;
    void        **report;

    ASSERT_GATED();

    report = NULL;
    if (ch_id == kAssertDelayChID) {
        report = &assertOnWakeReport;
    }
    else if (ch_id == kSleepDelaysChID) {
        report = &sleepDelaysReport;
    }

    if (*report == NULL) {
        return kIOReturnNotOpen;
    }

    HISTREPORT_UPDATEPREP(*report, data2cpy, size2cpy);
    if (size2cpy > (dest->getCapacity() - dest->getLength()) ) {
        return kIOReturnOverrun;
    }

    HISTREPORT_UPDATERES(*report, kIOReportCopyChannelData, result);
    dest->appendBytes(data2cpy, size2cpy);

    return kIOReturnSuccess;
}

IOReturn IOPMrootDomain::updateReport(IOReportChannelList      *channelList,
                                 IOReportUpdateAction      action,
                                 void                     *result,
                                 void                     *destination)
{
    uint32_t size2cpy;
    void *data2cpy;
    uint8_t buf[SIMPLEREPORT_BUFSIZE];
    IOBufferMemoryDescriptor *dest = OSDynamicCast(IOBufferMemoryDescriptor, (OSObject *)destination);
    unsigned cnt;
    uint64_t ch_id;

    if (action != kIOReportCopyChannelData) goto exit;

    for (cnt = 0; cnt < channelList->nchannels; cnt++) {
        ch_id = channelList->channels[cnt].channel_id ;

        if ((ch_id == kAssertDelayChID) || (ch_id == kSleepDelaysChID)) {
            gIOPMWorkLoop->runAction(
                     OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::updateReportGated),
                     (OSObject *)this, (void *)ch_id,
                     (void *)result, (void *)dest);
            continue;

        }
        else if ((ch_id == kSleepCntChID) ||
                (ch_id == kDarkWkCntChID) || (ch_id == kUserWkCntChID)) {
            SIMPLEREPORT_INIT(buf, sizeof(buf), getRegistryEntryID(), ch_id, kIOReportCategoryPower);
        }
        else continue;

        if (ch_id == kSleepCntChID)
            SIMPLEREPORT_SETVALUE(buf, sleepCnt);
        else if (ch_id == kDarkWkCntChID)
            SIMPLEREPORT_SETVALUE(buf, darkWakeCnt);
        else if (ch_id == kUserWkCntChID)
            SIMPLEREPORT_SETVALUE(buf, displayWakeCnt);

        SIMPLEREPORT_UPDATEPREP(buf, data2cpy, size2cpy);
        SIMPLEREPORT_UPDATERES(kIOReportCopyChannelData, result);
        dest->appendBytes(data2cpy, size2cpy);
    }

exit:
    return super::updateReport(channelList, action, result, destination);
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

    DLOG("PMTraceWorker %p\n", OBFUSCATE(me));

    // Note that we cannot instantiate the PCI device -> bit mappings here, since
    // the IODeviceTree has not yet been created by IOPlatformExpert. We create
    // this dictionary lazily.
    me->owner = owner;
    me->pciDeviceBitMappings = NULL;
    me->pmTraceWorkerLock = IOLockAlloc();
    me->tracePhase = kIOPMTracePointSystemUp;
    me->traceData32 = 0;
    me->loginWindowData = 0;
    me->coreDisplayData = 0;
    me->coreGraphicsData = 0;
    return me;
}

void PMTraceWorker::RTC_TRACE(void)
{
    if (tracePointHandler && tracePointTarget)
    {
        uint32_t    wordA;

        IOLockLock(pmTraceWorkerLock);
        wordA = (loginWindowData << 24) | (coreDisplayData << 16) |
                (coreGraphicsData << 8) | tracePhase;
        IOLockUnlock(pmTraceWorkerLock);

        tracePointHandler( tracePointTarget, traceData32, wordA );
        _LOG("RTC_TRACE wrote 0x%08x 0x%08x\n", traceData32, wordA);
    }
}

int PMTraceWorker::recordTopLevelPCIDevice(IOService * pciDevice)
{
    const OSSymbol *    deviceName;
    int                 index = -1;

    IOLockLock(pmTraceWorkerLock);

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
        _LOG("PMTrace PCI array: set object %s => %d\n",
            deviceName->getCStringNoCopy(), index);
    }
    if (deviceName)
        deviceName->release();
    if (!addedToRegistry && (index >= 0))
        addedToRegistry = owner->setProperty("PCITopLevel", this);

exit:
    IOLockUnlock(pmTraceWorkerLock);
    return index;
}

bool PMTraceWorker::serialize(OSSerialize *s) const
{
    bool ok = false;
    if (pciDeviceBitMappings)
    {
        IOLockLock(pmTraceWorkerLock);
        ok = pciDeviceBitMappings->serialize(s);
        IOLockUnlock(pmTraceWorkerLock);
    }
    return ok;
}

void PMTraceWorker::tracePoint(uint8_t phase)
{
    // clear trace detail when phase begins
    if (tracePhase != phase)
        traceData32 = 0;

    tracePhase = phase;

    DLOG("trace point 0x%02x\n", tracePhase);
    RTC_TRACE();
}

void PMTraceWorker::traceDetail(uint32_t detail)
{

    traceData32 = detail;
    DLOG("trace point 0x%02x detail 0x%08x\n", tracePhase, traceData32);

    RTC_TRACE();
}

void PMTraceWorker::traceComponentWakeProgress(uint32_t component, uint32_t data)
{
    switch (component) {
        case kIOPMLoginWindowProgress:
            loginWindowData = data & kIOPMLoginWindowProgressMask;
            break;
        case kIOPMCoreDisplayProgress:
            coreDisplayData = data & kIOPMCoreDisplayProgressMask;
            break;
        case kIOPMCoreGraphicsProgress:
            coreGraphicsData = data & kIOPMCoreGraphicsProgressMask;
            break;
        default:
            return;
    }
    
    DLOG("component trace point 0x%02x data 0x%08x\n", component, data);
    RTC_TRACE();
}

void PMTraceWorker::tracePCIPowerChange(
    change_t type, IOService *service, uint32_t changeFlags, uint32_t bitNum)
{
    uint32_t    bitMask;
    uint32_t    expectedFlag;

    // Ignore PCI changes outside of system sleep/wake.
    if ((kIOPMTracePointSleepPowerPlaneDrivers != tracePhase) &&
        (kIOPMTracePointWakePowerPlaneDrivers  != tracePhase))
        return;

    // Only record the WillChange transition when going to sleep,
    // and the DidChange on the way up.
    changeFlags &= (kIOPMDomainWillChange | kIOPMDomainDidChange);
    expectedFlag = (kIOPMTracePointSleepPowerPlaneDrivers == tracePhase) ?
                    kIOPMDomainWillChange : kIOPMDomainDidChange;
    if (changeFlags != expectedFlag)
        return;

    // Mark this device off in our bitfield
    if (bitNum < kPMMaxRTCBitfieldSize)
    {
        bitMask = (1 << bitNum);

        if (kPowerChangeStart == type)
        {
            traceData32 |= bitMask;
            _LOG("PMTrace: Device %s started  - bit %2d mask 0x%08x => 0x%08x\n",
                service->getName(), bitNum, bitMask, traceData32);
            owner->kdebugTrace(kPMLogPCIDevChangeStart, service->getRegistryEntryID(), traceData32, 0);
        }
        else
        {
            traceData32 &= ~bitMask;
            _LOG("PMTrace: Device %s finished - bit %2d mask 0x%08x => 0x%08x\n",
                service->getName(), bitNum, bitMask, traceData32);
            owner->kdebugTrace(kPMLogPCIDevChangeDone, service->getRegistryEntryID(), traceData32, 0);
        }

        DLOG("trace point 0x%02x detail 0x%08x\n", tracePhase, traceData32);
        RTC_TRACE();
    }
}

uint64_t  PMTraceWorker::getPMStatusCode( )
{
    return (((uint64_t)traceData32 << 32) | ((uint64_t)tracePhase));

}

uint8_t PMTraceWorker::getTracePhase()
{
    return tracePhase;
}

uint32_t PMTraceWorker::getTraceData()
{
    return traceData32;
}

// MARK: -
// MARK: PMHaltWorker

//******************************************************************************
// PMHaltWorker Class
//
//******************************************************************************

PMHaltWorker * PMHaltWorker::worker( void )
{
    PMHaltWorker *  me;
    IOThread        thread;

    do {
        me = OSTypeAlloc( PMHaltWorker );
        if (!me || !me->init())
            break;

        me->lock = IOLockAlloc();
        if (!me->lock)
            break;

        DLOG("PMHaltWorker %p\n", OBFUSCATE(me));
        me->retain();   // thread holds extra retain
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
    DLOG("PMHaltWorker free %p\n", OBFUSCATE(this));
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
    DLOG("All done for worker: %p (visits = %u)\n", OBFUSCATE(me), me->visits);
    thread_wakeup( &gPMHaltDepth );
    me->release();
}

void PMHaltWorker::work( PMHaltWorker * me )
{
    IOService *     service;
    OSSet *         inner;
    AbsoluteTime    startTime;
    UInt32          deltaTime;
    bool            timeout;

    while (true)
    {
        service = 0;
        timeout = false;

        // Claim an unit of work from the shared pool
        IOLockLock( gPMHaltLock );
        inner = (OSSet *)gPMHaltArray->getObject(me->depth);
        if (inner)
        {
            service = OSDynamicCast(IOService, inner->getAnyObject());
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

            service->systemWillShutdown( gPMHaltMessageType );

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
            (gIOKitDebug & kIOLogPMRootDomain))
        {
            LOG("%s driver %s (0x%llx) took %u ms\n",
                (gPMHaltMessageType == kIOMessageSystemWillPowerOff) ?
                    "PowerOff" : "Restart",
                service->getName(), service->getRegistryEntryID(),
                (uint32_t) deltaTime );
        }

        service->release();
        me->visits++;
    }
}

void PMHaltWorker::checkTimeout( PMHaltWorker * me, AbsoluteTime * now )
{
    UInt64          nano;
    AbsoluteTime    startTime;
    AbsoluteTime    endTime;

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
            MSG("%s still waiting on %s\n",
                (gPMHaltMessageType == kIOMessageSystemWillPowerOff) ?
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
    PMHaltWorker *  worker;
    OSObject *      prop;

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
notifySystemShutdown( IOService * root, uint32_t messageType )
{
#define PLACEHOLDER ((OSSet *)gPMHaltArray)
    IORegistryIterator *    iter;
    IORegistryEntry *       entry;
    IOService *             node;
    OSSet *                 inner;
    PMHaltWorker *          workers[kPMHaltMaxWorkers];
    AbsoluteTime            deadline;
    unsigned int            totalNodes = 0;
    unsigned int            depth;
    unsigned int            rootDepth;
    unsigned int            numWorkers;
    unsigned int            count;
    int                     waitResult;
    void *                  baseFunc;
    bool                    ok;

    DLOG("%s msgType = 0x%x\n", __FUNCTION__, messageType);

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

    gPMHaltMessageType = messageType;

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

    DLOG("PM nodes %u, maxDepth %u, workers %u\n",
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

// MARK: -
// MARK: Kernel Assertion

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

OSObject * IOPMrootDomain::copyProperty( const char * aKey) const
{
    OSObject *obj = NULL;
    obj = IOService::copyProperty(aKey);

    if (obj)  return obj;

    if (!strncmp(aKey, kIOPMSleepWakeWdogRebootKey,
                        sizeof(kIOPMSleepWakeWdogRebootKey))) {
        if (swd_flags & SWD_BOOT_BY_SW_WDOG)
            return kOSBooleanTrue;
        else
            return kOSBooleanFalse;

    }

    if (!strncmp(aKey, kIOPMSleepWakeWdogLogsValidKey,
                        sizeof(kIOPMSleepWakeWdogLogsValidKey))) {
        if (swd_flags & SWD_VALID_LOGS)
            return kOSBooleanTrue;
        else
            return kOSBooleanFalse;

    }

    /*
     * XXX: We should get rid of "DesktopMode" property  when 'kAppleClamshellCausesSleepKey'
     * is set properly in darwake from sleep. For that, kIOPMEnableClamshell msg has to be
     * issued by DisplayWrangler on darkwake.
     */
    if (!strcmp(aKey, "DesktopMode")) {
        if (desktopMode)
            return kOSBooleanTrue;
        else
            return kOSBooleanFalse;
    }
    if (!strcmp(aKey, "DisplayIdleForDemandSleep")) {
        if (displayIdleForDemandSleep) {
            return kOSBooleanTrue;
        }
        else  {
            return kOSBooleanFalse;
        }
    }

    if (!strcmp(aKey, kIOPMDriverWakeEventsKey))
    {
        OSArray * array = 0;
        WAKEEVENT_LOCK();
        if (_systemWakeEventsArray && _systemWakeEventsArray->getCount()) {
            OSCollection *collection = _systemWakeEventsArray->copyCollection();
            if (collection && !(array = OSDynamicCast(OSArray, collection))) {
                collection->release();
            }
        }
        WAKEEVENT_UNLOCK();
        return array;
    }

    if (!strcmp(aKey, kIOPMSleepStatisticsAppsKey))
    {
        OSArray * array = 0;
        IOLockLock(pmStatsLock);
        if (pmStatsAppResponses && pmStatsAppResponses->getCount()) {
            OSCollection *collection = pmStatsAppResponses->copyCollection();
            if (collection && !(array = OSDynamicCast(OSArray, collection))) {
                collection->release();
            }
            pmStatsAppResponses->flushCollection();
        }
        IOLockUnlock(pmStatsLock);
        return array;
    }

    if (!strcmp(aKey, kIOPMIdleSleepPreventersKey))
    {
        OSArray *idleSleepList = NULL;
        gRootDomain->copySleepPreventersList(&idleSleepList, NULL);
        return idleSleepList;
    }

    if (!strcmp(aKey, kIOPMSystemSleepPreventersKey))
    {
        OSArray *systemSleepList = NULL;
        gRootDomain->copySleepPreventersList(NULL, &systemSleepList);
        return systemSleepList;
    }

    return NULL;
}

// MARK: -
// MARK: Wake Event Reporting

void IOPMrootDomain::copyWakeReasonString( char * outBuf, size_t bufSize )
{
    WAKEEVENT_LOCK();
    strlcpy(outBuf, gWakeReasonString, bufSize);
    WAKEEVENT_UNLOCK();
}

//******************************************************************************
// acceptSystemWakeEvents
//
// Private control for the acceptance of driver wake event claims.
//******************************************************************************

void IOPMrootDomain::acceptSystemWakeEvents( bool accept )
{
    bool logWakeReason = false;

    WAKEEVENT_LOCK();
    if (accept)
    {
        gWakeReasonString[0] = '\0';
        if (!_systemWakeEventsArray)
            _systemWakeEventsArray = OSArray::withCapacity(4);
        if ((_acceptSystemWakeEvents = (_systemWakeEventsArray != 0)))
            _systemWakeEventsArray->flushCollection();
    }
    else
    {
        _acceptSystemWakeEvents = false;
    }
    WAKEEVENT_UNLOCK();

    if (logWakeReason)
        MSG("system wake events:%s\n", gWakeReasonString);
}

//******************************************************************************
// claimSystemWakeEvent
//
// For a driver to claim a device is the source/conduit of a system wake event.
//******************************************************************************

void IOPMrootDomain::claimSystemWakeEvent(
    IOService *     device,
    IOOptionBits    flags,
    const char *    reason,
    OSObject *      details )
{
    const OSSymbol *    deviceName   = 0;
    OSNumber *          deviceRegId  = 0;
    OSNumber *          claimTime    = 0;
    OSData *            flagsData    = 0;
    OSString *          reasonString = 0;
    OSDictionary *      d = 0;
    uint64_t            timestamp;
    bool                ok = false;

    pmEventTimeStamp(&timestamp);

    if (!device || !reason) return;

    deviceName   = device->copyName(gIOServicePlane);
    deviceRegId  = OSNumber::withNumber(device->getRegistryEntryID(), 64);
    claimTime    = OSNumber::withNumber(timestamp, 64);
    flagsData    = OSData::withBytes(&flags, sizeof(flags));
    reasonString = OSString::withCString(reason);
    d = OSDictionary::withCapacity(5 + (details ? 1 : 0));
    if (!deviceName || !deviceRegId || !claimTime || !flagsData || !reasonString)
        goto done;

    d->setObject(gIONameKey, deviceName);
    d->setObject(gIORegistryEntryIDKey, deviceRegId);
    d->setObject(kIOPMWakeEventTimeKey, claimTime);
    d->setObject(kIOPMWakeEventFlagsKey, flagsData);
    d->setObject(kIOPMWakeEventReasonKey, reasonString);
    if (details)
        d->setObject(kIOPMWakeEventDetailsKey, details);

    WAKEEVENT_LOCK();
    if (!gWakeReasonSysctlRegistered)
    {
        // Lazy registration until the platform driver stops registering
        // the same name.
        gWakeReasonSysctlRegistered = true;
    }
    if (_acceptSystemWakeEvents)
    {
        ok = _systemWakeEventsArray->setObject(d);
        if (gWakeReasonString[0] != '\0')
            strlcat(gWakeReasonString, " ", sizeof(gWakeReasonString));
        strlcat(gWakeReasonString, reason, sizeof(gWakeReasonString));
    }
    WAKEEVENT_UNLOCK();

done:
    if (deviceName)   deviceName->release();
    if (deviceRegId)  deviceRegId->release();
    if (claimTime)    claimTime->release();
    if (flagsData)    flagsData->release();
    if (reasonString) reasonString->release();
    if (d) d->release();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// MARK: -
// MARK: PMSettingHandle

OSDefineMetaClassAndStructors( PMSettingHandle, OSObject )

void PMSettingHandle::free( void )
{
    if (pmso)
    {
        pmso->clientHandleFreed();
        pmso->release();
        pmso = 0;
    }

    OSObject::free();
}

// MARK: -
// MARK: PMSettingObject

#undef super
#define super OSObject
OSDefineMetaClassAndFinalStructors( PMSettingObject, OSObject )

/*
 * Static constructor/initializer for PMSettingObject
 */
PMSettingObject *PMSettingObject::pmSettingObject(
    IOPMrootDomain                      *parent_arg,
    IOPMSettingControllerCallback       handler_arg,
    OSObject                            *target_arg,
    uintptr_t                           refcon_arg,
    uint32_t                            supportedPowerSources,
    const OSSymbol *                    settings[],
    OSObject                            **handle_obj)
{
    uint32_t                            settingCount = 0;
    PMSettingObject                     *pmso = 0;
    PMSettingHandle                     *pmsh = 0;

    if ( !parent_arg || !handler_arg || !settings || !handle_obj )
        return NULL;

    // count OSSymbol entries in NULL terminated settings array
    while (settings[settingCount]) {
        settingCount++;
    }
    if (0 == settingCount)
        return NULL;

    pmso = new PMSettingObject;
    if (!pmso || !pmso->init())
        goto fail;

    pmsh = new PMSettingHandle;
    if (!pmsh || !pmsh->init())
        goto fail;

    queue_init(&pmso->calloutQueue);
    pmso->parent       = parent_arg;
    pmso->func         = handler_arg;
    pmso->target       = target_arg;
    pmso->refcon       = refcon_arg;
    pmso->settingCount = settingCount;

    pmso->retain();     // handle holds a retain on pmso
    pmsh->pmso = pmso;
    pmso->pmsh = pmsh;

    pmso->publishedFeatureID = (uint32_t *)IOMalloc(sizeof(uint32_t)*settingCount);
    if (pmso->publishedFeatureID) {
        for (unsigned int i=0; i<settingCount; i++) {
            // Since there is now at least one listener to this setting, publish
            // PM root domain support for it.
            parent_arg->publishPMSetting( settings[i],
                    supportedPowerSources, &pmso->publishedFeatureID[i] );
        }
    }

    *handle_obj = pmsh;
    return pmso;

fail:
    if (pmso) pmso->release();
    if (pmsh) pmsh->release();
    return NULL;
}

void PMSettingObject::free( void )
{
    if (publishedFeatureID) {
        for (uint32_t i=0; i<settingCount; i++) {
            if (publishedFeatureID[i]) {
                parent->removePublishedFeature( publishedFeatureID[i] );
            }
        }

        IOFree(publishedFeatureID, sizeof(uint32_t) * settingCount);
    }

    super::free();
}

void PMSettingObject::dispatchPMSetting( const OSSymbol * type, OSObject * object )
{
    (*func)(target, type, object, refcon);
}

void PMSettingObject::clientHandleFreed( void )
{
    parent->deregisterPMSettingObject(this);
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
        owner->evaluateAssertions(assertionsCombined, oldCombined);
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
    track.id = OSIncrementAtomic64((SInt64*) &issuingUniqueID);
    track.level = level;
    track.assertionBits = which;
    track.ownerString = whoItIs ? OSSymbol::withCString(whoItIs):0;
    track.ownerService = serviceID;
    track.registryEntryID = serviceID ? serviceID->getRegistryEntryID():0;
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
                (void *)(uintptr_t)_level, _id);
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
            _n = OSNumber::withNumber((uintptr_t)_a->registryEntryID, 64);
            if (_n) {
                details->setObject(kIOPMDriverAssertionRegistryEntryIDKey, _n);
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

// MARK: -
// MARK: IORootParent

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndFinalStructors(IORootParent, IOService)

// The reason that root domain needs a root parent is to facilitate demand
// sleep, since a power change from the root parent cannot be vetoed.
//
// The above statement is no longer true since root domain now performs
// demand sleep using overrides. But root parent remains to avoid changing
// the power tree stacking. Root parent is parked at the max power state.


static IOPMPowerState patriarchPowerStates[2] =
{
    {1,0,ON_POWER,0,0,0,0,0,0,0,0,0},
    {1,0,ON_POWER,0,0,0,0,0,0,0,0,0},
};

void IORootParent::initialize( void )
{
}

bool IORootParent::start( IOService * nub )
{
    IOService::start(nub);
    attachToParent( getRegistryRoot(), gIOPowerPlane );
    PMinit();
    registerPowerDriver(this, patriarchPowerStates, 2);
    makeUsable();
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
}

void IORootParent::dozeSystem( void )
{
}

void IORootParent::sleepToDoze( void )
{
}

void IORootParent::wakeSystem( void )
{
}

OSObject * IORootParent::copyProperty( const char * aKey) const
{
    return (IOService::copyProperty(aKey));
}


#if defined(__i386__) || defined(__x86_64__)
IOReturn IOPMrootDomain::restartWithStackshot()
{
    if ((swd_flags & SWD_WDOG_ENABLED) == 0)
        return kIOReturnError;

    takeStackshot(true, true, false);

    return kIOReturnSuccess;
}

void IOPMrootDomain::sleepWakeDebugTrig(bool wdogTrigger)
{
    takeStackshot(wdogTrigger, false, false);
}

void IOPMrootDomain::takeStackshot(bool wdogTrigger, bool isOSXWatchdog, bool isSpinDump)
{
   swd_hdr *         hdr = NULL;
   addr64_t          data[3];
   int               wdog_panic = -1;
   int               cnt = 0;
   pid_t             pid = 0;
   kern_return_t     kr = KERN_SUCCESS;
   uint32_t          flags;

   char *            dstAddr;
   uint32_t          size;
   uint32_t          bytesRemaining;
   unsigned          bytesWritten = 0;
   unsigned          totalBytes = 0;
   unsigned int      len;
   OSString *        UUIDstring = NULL;
   uint64_t          code;
   IOMemoryMap *     logBufMap = NULL;


   uint32_t          bufSize;
   uint32_t          initialStackSize;

   if (isSpinDump) {
       if (_systemTransitionType != kSystemTransitionSleep &&
           _systemTransitionType != kSystemTransitionWake)
           return;
   } else {
       if ( kIOSleepWakeWdogOff & gIOKitDebug )
           return;
   }

   if (wdogTrigger) {
       PE_parse_boot_argn("swd_panic", &wdog_panic, sizeof(wdog_panic));
       if (wdog_panic == 1) {
           // If boot-arg specifies to panic then panic.
           panic("Sleep/Wake hang detected\n");
           return;
       }
       else if (swd_flags & SWD_BOOT_BY_SW_WDOG) {
           // If current boot is due to this watch dog trigger restart in previous boot,
           // then don't trigger again until at least 1 successful sleep & wake.
           if (!(sleepCnt && (displayWakeCnt || darkWakeCnt))) {
               IOLog("Shutting down due to repeated Sleep/Wake failures\n");
               PEHaltRestart(kPEHaltCPU);
               return;
           }
       }

   }

   if (isSpinDump) {
      if (gSpinDumpBufferFull)
         return;
      if (swd_spindump_buffer == NULL) {
         sleepWakeDebugSpinDumpMemAlloc();
         if (swd_spindump_buffer == NULL) return;
      }

      bufSize = SWD_SPINDUMP_SIZE;
      initialStackSize = SWD_INITIAL_SPINDUMP_SIZE;
   } else {
      if (sleepWakeDebugIsWdogEnabled() == false)
         return;

      if (swd_buffer == NULL) {
         sleepWakeDebugMemAlloc();
         if (swd_buffer == NULL) return;
      }

      bufSize = SWD_BUF_SIZE;
      initialStackSize = SWD_INITIAL_STACK_SIZE;
   }

   if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock))
       return;

   if (isSpinDump) {
      hdr = (swd_hdr *)swd_spindump_buffer;
   }
   else {
      hdr = (swd_hdr *)swd_buffer;
   }

   memset(hdr->UUID, 0x20, sizeof(hdr->UUID));
   if ((UUIDstring = OSDynamicCast(OSString, getProperty(kIOPMSleepWakeUUIDKey))) != NULL ) {

      if (wdogTrigger || (!UUIDstring->isEqualTo(hdr->UUID))) {
         const char *str = UUIDstring->getCStringNoCopy();
         snprintf(hdr->UUID, sizeof(hdr->UUID), "UUID: %s", str);
      }
      else {
         DLOG("Data for current UUID already exists\n");
         goto exit;
      }
   }

   dstAddr = (char*)hdr + hdr->spindump_offset;
   bytesRemaining = bufSize - hdr->spindump_offset;

   /* if AppleOSXWatchdog triggered the stackshot, set the flag in the heaer */
   hdr->is_osx_watchdog = isOSXWatchdog;

   DLOG("Taking snapshot. bytesRemaining: %d\n", bytesRemaining);

   flags = STACKSHOT_KCDATA_FORMAT|STACKSHOT_NO_IO_STATS|STACKSHOT_SAVE_KEXT_LOADINFO;
   while (kr == KERN_SUCCESS) {

       if (cnt == 0) {
           /*
            * Take stackshot of all process on first sample. Size is restricted
            * to SWD_INITIAL_STACK_SIZE
            */
           pid = -1;
           size = (bytesRemaining > initialStackSize) ? initialStackSize : bytesRemaining;
           flags |= STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY;
       }
       else {
           /* Take sample of kernel threads only */
           pid = 0;
           size = bytesRemaining;
       }

       kr = stack_snapshot_from_kernel(pid, dstAddr, size, flags, 0, &bytesWritten);
       DLOG("stack_snapshot_from_kernel returned 0x%x. pid: %d bufsize:0x%x flags:0x%x bytesWritten: %d\n",
               kr, pid, size, flags, bytesWritten);
       if (kr == KERN_INSUFFICIENT_BUFFER_SIZE) {
           if (pid == -1) {
               // Insufficient buffer when trying to take stackshot of user & kernel space threads.
               // Continue to take stackshot of just kernel threads
               ++cnt;
               kr = KERN_SUCCESS;
               continue;
           }
           else if (totalBytes == 0) {
               MSG("Failed to get stackshot(0x%x) bufsize:0x%x flags:0x%x\n", kr, size, flags);
           }
       }

       dstAddr += bytesWritten;
       totalBytes += bytesWritten;
       bytesRemaining -= bytesWritten;

       if (++cnt == 10) {
           break;
       }
       IOSleep(10); // 10 ms
   }

   hdr->spindump_size = (bufSize - bytesRemaining - hdr->spindump_offset);


   memset(hdr->spindump_status, 0x20, sizeof(hdr->spindump_status));
   code = pmTracer->getPMStatusCode();
   memset(hdr->PMStatusCode, 0x20, sizeof(hdr->PMStatusCode));
   snprintf(hdr->PMStatusCode, sizeof(hdr->PMStatusCode), "\nCode: %08x %08x",
           (uint32_t)((code >> 32) & 0xffffffff), (uint32_t)(code & 0xffffffff));
   memset(hdr->reason, 0x20, sizeof(hdr->reason));
   if (isSpinDump) {
      snprintf(hdr->reason, sizeof(hdr->reason), "\nStackshot reason: PSC Delay\n\n");
      gRootDomain->swd_lock = 0;
      gSpinDumpBufferFull = true;
      return;
   }
   snprintf(hdr->reason, sizeof(hdr->reason), "\nStackshot reason: Watchdog\n\n");


   data[0] = round_page(sizeof(swd_hdr) + hdr->spindump_size);
   /* Header & rootdomain log is constantly changing and  is not covered by CRC */
   data[1] = hdr->crc = crc32(0, ((char*)swd_buffer+hdr->spindump_offset), hdr->spindump_size);
   data[2] = kvtophys((vm_offset_t)swd_buffer);
   len = sizeof(addr64_t)*3;
   DLOG("bytes: 0x%llx crc:0x%llx paddr:0x%llx\n",
         data[0], data[1], data[2]);

   if (PEWriteNVRAMProperty(kIOSleepWakeDebugKey, data, len) == false)
   {
      DLOG("Failed to update nvram boot-args\n");
      goto exit;
   }

exit:

   gRootDomain->swd_lock = 0;

   if (wdogTrigger) {
      IOLog("Restarting to collect Sleep wake debug logs\n");
      PEHaltRestart(kPERestartCPU);
   }
   else {
     logBufMap = sleepWakeDebugRetrieve();
      if (logBufMap) {
          sleepWakeDebugDumpFromMem(logBufMap);
          logBufMap->release();
          logBufMap = 0;
      }
   }
}

void IOPMrootDomain::sleepWakeDebugMemAlloc( )
{
    vm_size_t    size = SWD_BUF_SIZE;

    swd_hdr      *hdr = NULL;

    IOBufferMemoryDescriptor  *memDesc = NULL;


    if ( kIOSleepWakeWdogOff & gIOKitDebug )
      return;

    if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock))
       return;

    // Try allocating above 4GB. If that fails, try at 2GB
    memDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
                            kernel_task, kIOMemoryPhysicallyContiguous|kIOMemoryMapperNone,
                            size, 0xFFFFFFFF00000000ULL);
    if (!memDesc) {
       memDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
                            kernel_task, kIOMemoryPhysicallyContiguous|kIOMemoryMapperNone,
                            size, 0xFFFFFFFF10000000ULL);
    }

    if (memDesc == NULL)
    {
      DLOG("Failed to allocate Memory descriptor for sleepWake debug\n");
      goto exit;
    }


    hdr = (swd_hdr *)memDesc->getBytesNoCopy();
    memset(hdr, 0, sizeof(swd_hdr));

    hdr->signature = SWD_HDR_SIGNATURE;
    hdr->alloc_size = size;

    hdr->spindump_offset = sizeof(swd_hdr);
    swd_buffer = (void *)hdr;
    swd_memDesc = memDesc;
    DLOG("SleepWake debug buffer size:0x%x spindump offset:0x%x\n", hdr->alloc_size, hdr->spindump_offset);

exit:
    gRootDomain->swd_lock = 0;
}

void IOPMrootDomain::sleepWakeDebugSpinDumpMemAlloc( )
{
    vm_size_t    size = SWD_SPINDUMP_SIZE;

    swd_hdr      *hdr = NULL;

    IOBufferMemoryDescriptor  *memDesc = NULL;

    if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock))
        return;

    memDesc = IOBufferMemoryDescriptor::inTaskWithOptions(
                            kernel_task, kIODirectionIn|kIOMemoryMapperNone,
                            SWD_SPINDUMP_SIZE);

    if (memDesc == NULL)
    {
        DLOG("Failed to allocate Memory descriptor for sleepWake debug spindump\n");
        goto exit;
    }


    hdr = (swd_hdr *)memDesc->getBytesNoCopy();
    memset(hdr, 0, sizeof(swd_hdr));

    hdr->signature = SWD_HDR_SIGNATURE;
    hdr->alloc_size = size;

    hdr->spindump_offset = sizeof(swd_hdr);
    swd_spindump_buffer = (void *)hdr;

exit:
    gRootDomain->swd_lock = 0;
}

void IOPMrootDomain::sleepWakeDebugEnableWdog()
{
    swd_flags |= SWD_WDOG_ENABLED;
    if (!swd_buffer)
        sleepWakeDebugMemAlloc();
}

bool IOPMrootDomain::sleepWakeDebugIsWdogEnabled()
{
    return ((swd_flags & SWD_WDOG_ENABLED) &&
            !systemBooting && !systemShutdown && !gWillShutdown);
}

void IOPMrootDomain::sleepWakeDebugSaveSpinDumpFile()
{
    swd_hdr *hdr = NULL;
    errno_t error = EIO;

    if (swd_spindump_buffer && gSpinDumpBufferFull) {
        hdr = (swd_hdr *)swd_spindump_buffer;

        error = sleepWakeDebugSaveFile("/var/tmp/SleepWakeDelayStacks.dump",
                        (char*)hdr+hdr->spindump_offset, hdr->spindump_size);

        if (error) return;

        sleepWakeDebugSaveFile("/var/tmp/SleepWakeDelayLog.dump",
                         (char*)hdr+offsetof(swd_hdr, UUID),
                         sizeof(swd_hdr)-offsetof(swd_hdr, UUID));

        gSpinDumpBufferFull = false;
    }
}

errno_t IOPMrootDomain::sleepWakeDebugSaveFile(const char *name, char *buf, int len)
{
   struct vnode         *vp = NULL;
   vfs_context_t        ctx = vfs_context_create(vfs_context_current());
   kauth_cred_t         cred = vfs_context_ucred(ctx);
   struct vnode_attr    va;
   errno_t      error = EIO;

   if (vnode_open(name, (O_CREAT | FWRITE | O_NOFOLLOW),
                        S_IRUSR|S_IRGRP|S_IROTH, VNODE_LOOKUP_NOFOLLOW, &vp, ctx) != 0)
   {
      IOLog("Failed to open the file %s\n", name);
      swd_flags |= SWD_FILEOP_ERROR;
      goto exit;
   }
   VATTR_INIT(&va);
   VATTR_WANTED(&va, va_nlink);
   /* Don't dump to non-regular files or files with links. */
   if (vp->v_type != VREG ||
        vnode_getattr(vp, &va, ctx) || va.va_nlink != 1) {
        IOLog("Bailing as this is not a regular file\n");
        swd_flags |= SWD_FILEOP_ERROR;
        goto exit;
    }
    VATTR_INIT(&va);
    VATTR_SET(&va, va_data_size, 0);
    vnode_setattr(vp, &va, ctx);


    if (buf != NULL) {
        error = vn_rdwr(UIO_WRITE, vp, buf, len, 0,
                UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *) 0,  vfs_context_proc(ctx));
        if (error != 0) {
            IOLog("Failed to save sleep wake log. err 0x%x\n", error);
            swd_flags |= SWD_FILEOP_ERROR;
        }
        else {
            DLOG("Saved %d bytes to file %s\n",len, name);
        }
    }

exit:
    if (vp) vnode_close(vp, FWRITE, ctx);
    if (ctx) vfs_context_rele(ctx);

    return error;

}

errno_t IOPMrootDomain::sleepWakeDebugCopyFile(
                               struct vnode *srcVp, 
                               vfs_context_t srcCtx,
                               char *tmpBuf, uint64_t tmpBufSize,
                               uint64_t srcOffset, 
                               const char *dstFname, 
                               uint64_t numBytes,
                               uint32_t crc)
{
   struct vnode         *vp = NULL;
   vfs_context_t        ctx = vfs_context_create(vfs_context_current());
   struct vnode_attr    va;
   errno_t      error = EIO;
   uint64_t bytesToRead, bytesToWrite;
   uint64_t readFileOffset, writeFileOffset, srcDataOffset; 
   uint32_t newcrc = 0;

   if (vnode_open(dstFname, (O_CREAT | FWRITE | O_NOFOLLOW), 
                        S_IRUSR|S_IRGRP|S_IROTH, VNODE_LOOKUP_NOFOLLOW, &vp, ctx) != 0) 
   {
      IOLog("Failed to open the file %s\n", dstFname);
      swd_flags |= SWD_FILEOP_ERROR;
      goto exit;
   }
   VATTR_INIT(&va);
   VATTR_WANTED(&va, va_nlink);
   /* Don't dump to non-regular files or files with links. */
   if (vp->v_type != VREG ||
        vnode_getattr(vp, &va, ctx) || va.va_nlink != 1) {
        IOLog("Bailing as this is not a regular file\n");
        swd_flags |= SWD_FILEOP_ERROR;
        goto exit;
	}
    VATTR_INIT(&va);	
    VATTR_SET(&va, va_data_size, 0);
    vnode_setattr(vp, &va, ctx);
   
    writeFileOffset = 0;
    while(numBytes) {
        bytesToRead = (round_page(numBytes) > tmpBufSize) ? tmpBufSize : round_page(numBytes);
        readFileOffset = trunc_page(srcOffset);

       DLOG("Read file (numBytes:0x%llx offset:0x%llx)\n", bytesToRead, readFileOffset);
       error = vn_rdwr(UIO_READ, srcVp, tmpBuf, bytesToRead, readFileOffset,
               UIO_SYSSPACE, IO_SKIP_ENCRYPTION|IO_SYNC|IO_NODELOCKED|IO_UNIT|IO_NOCACHE, 
               vfs_context_ucred(srcCtx), (int *) 0,
               vfs_context_proc(srcCtx));
       if (error) {
           IOLog("Failed to read file(numBytes:0x%llx)\n", bytesToRead);
           swd_flags |= SWD_FILEOP_ERROR;
           break;
       }

       srcDataOffset = (uint64_t)tmpBuf + (srcOffset - readFileOffset);
       bytesToWrite = bytesToRead - (srcOffset - readFileOffset);
       if (bytesToWrite > numBytes) bytesToWrite = numBytes;

       if (crc) {
           newcrc = crc32(newcrc, (void *)srcDataOffset, bytesToWrite);
       }
       DLOG("Write file (numBytes:0x%llx offset:0x%llx)\n", bytesToWrite, writeFileOffset);
       error = vn_rdwr(UIO_WRITE, vp, (char *)srcDataOffset, bytesToWrite, writeFileOffset,
               UIO_SYSSPACE, IO_SYNC|IO_NODELOCKED|IO_UNIT, 
               vfs_context_ucred(ctx), (int *) 0,
               vfs_context_proc(ctx));
       if (error) {
           IOLog("Failed to write file(numBytes:0x%llx)\n", bytesToWrite);
           swd_flags |= SWD_FILEOP_ERROR;
           break;
       }

       writeFileOffset += bytesToWrite;
       numBytes -= bytesToWrite;
       srcOffset += bytesToWrite;

    }
    if (crc != newcrc) {
        /* Set stackshot size to 0 if crc doesn't match */
        VATTR_INIT(&va);
        VATTR_SET(&va, va_data_size, 0);
        vnode_setattr(vp, &va, ctx);

        IOLog("CRC check failed. expected:0x%x actual:0x%x\n", crc, newcrc);
        swd_flags |= SWD_DATA_CRC_ERROR;
        error = EFAULT;
    }
exit:
    if (vp) { 
        error = vnode_close(vp, FWRITE, ctx);
        DLOG("vnode_close on file %s returned 0x%x\n",dstFname, error);
    }
    if (ctx) vfs_context_rele(ctx);

    return error;



}
uint32_t IOPMrootDomain::checkForValidDebugData(const char *fname, vfs_context_t *ctx, 
                                            void *tmpBuf, struct vnode **vp)
{
    int             rc;
    uint64_t        hdrOffset;
    uint32_t        error = 0;

    struct vnode_attr           va;
    IOHibernateImageHeader      *imageHdr;

    *vp = NULL;
    if (vnode_open(fname, (FREAD | O_NOFOLLOW), 0,
                   VNODE_LOOKUP_NOFOLLOW, vp, *ctx) != 0) 
    {
        DMSG("sleepWakeDebugDumpFromFile: Failed to open the file %s\n", fname);
        goto err;
    }
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_nlink);
    VATTR_WANTED(&va, va_data_alloc);
    if ((*vp)->v_type != VREG ||
        vnode_getattr((*vp), &va, *ctx) || va.va_nlink != 1) {
        IOLog("sleepWakeDebugDumpFromFile: Bailing as %s is not a regular file\n", fname);
        error = SWD_FILEOP_ERROR;
        goto err;
    }

    /* Read the sleepimage file header */
    rc = vn_rdwr(UIO_READ, *vp, (char *)tmpBuf, round_page(sizeof(IOHibernateImageHeader)), 0,
                UIO_SYSSPACE, IO_SKIP_ENCRYPTION|IO_SYNC|IO_NODELOCKED|IO_UNIT|IO_NOCACHE, 
                vfs_context_ucred(*ctx), (int *) 0,
                vfs_context_proc(*ctx));
    if (rc != 0) {
        IOLog("sleepWakeDebugDumpFromFile: Failed to read header size %lu(rc=%d) from %s\n", 
             round_page(sizeof(IOHibernateImageHeader)), rc, fname);
        error = SWD_FILEOP_ERROR;
        goto err;
    }

    imageHdr = ((IOHibernateImageHeader *)tmpBuf);
    if (imageHdr->signature != kIOHibernateHeaderDebugDataSignature) {
        IOLog("sleepWakeDebugDumpFromFile: File %s header has unexpected value 0x%x\n", 
             fname, imageHdr->signature);
        error = SWD_HDR_SIGNATURE_ERROR;
        goto err;
    }

    /* Sleep/Wake debug header(swd_hdr) is at the beggining of the second block */
    hdrOffset = imageHdr->deviceBlockSize;
    if (hdrOffset + sizeof(swd_hdr) >= va.va_data_alloc) {
        IOLog("sleepWakeDebugDumpFromFile: header is crossing file size(0x%llx) in file %s\n",  
             va.va_data_alloc, fname);
        error = SWD_HDR_SIZE_ERROR;
        goto err;
    }

    return 0; 

err:
    if (*vp) vnode_close(*vp, FREAD, *ctx);
    *vp = NULL;

    return error;
}

void IOPMrootDomain::sleepWakeDebugDumpFromFile( )
{
#if HIBERNATION
    int             rc;
    char			hibernateFilename[MAXPATHLEN+1];
    void            *tmpBuf;
    swd_hdr         *hdr = NULL;
    uint32_t        stacksSize, logSize;
    uint64_t        tmpBufSize;
    uint64_t        hdrOffset, stacksOffset, logOffset;
    errno_t         error = EIO;
    OSObject        *obj = NULL;
    OSString        *str = NULL;
    OSNumber        *failStat = NULL;
    struct vnode    *vp = NULL;
    vfs_context_t   ctx = NULL;
    const char      *stacksFname, *logFname;

    IOBufferMemoryDescriptor    *tmpBufDesc = NULL;

    DLOG("sleepWakeDebugDumpFromFile\n");
    if ((swd_flags & SWD_LOGS_IN_FILE) == 0)
        return;

   if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock))
       return;


    /* Allocate a temp buffer to copy data between files */
    tmpBufSize = 2*4096;
    tmpBufDesc = IOBufferMemoryDescriptor::
        inTaskWithOptions(kernel_task, kIODirectionOutIn | kIOMemoryMapperNone, 
                          tmpBufSize, PAGE_SIZE);

    if (!tmpBufDesc) {
        DMSG("sleepWakeDebugDumpFromFile: Fail to allocate temp buf\n");
        goto exit;
    }

    tmpBuf = tmpBufDesc->getBytesNoCopy();

   ctx = vfs_context_create(vfs_context_current());

    /* First check if 'kSleepWakeStackBinFilename' has valid data */
    swd_flags |= checkForValidDebugData(kSleepWakeStackBinFilename, &ctx, tmpBuf, &vp);
    if (vp == NULL) {
        /* Check if the debug data is saved to hibernation file */
        hibernateFilename[0] = 0;
        if ((obj = copyProperty(kIOHibernateFileKey)))
        {
            if ((str = OSDynamicCast(OSString, obj)))
                strlcpy(hibernateFilename, str->getCStringNoCopy(),
                        sizeof(hibernateFilename));
            obj->release();
        }
        if (!hibernateFilename[0]) {
            DMSG("sleepWakeDebugDumpFromFile: Failed to get hibernation file name\n");
            goto exit;
        }

        swd_flags |= checkForValidDebugData(hibernateFilename, &ctx, tmpBuf, &vp);
        if (vp == NULL) {
            DMSG("sleepWakeDebugDumpFromFile: No valid debug data is found\n");
            goto exit;
        }
        DLOG("Getting SW Stacks image from file %s\n", hibernateFilename);
    }
    else {
        DLOG("Getting SW Stacks image from file %s\n", kSleepWakeStackBinFilename);
    }

    hdrOffset = ((IOHibernateImageHeader *)tmpBuf)->deviceBlockSize;

    DLOG("Reading swd_hdr len 0x%lx offset 0x%lx\n", round_page(sizeof(swd_hdr)), trunc_page(hdrOffset));
    /* Read the sleep/wake debug header(swd_hdr) */
    rc = vn_rdwr(UIO_READ, vp, (char *)tmpBuf, round_page(sizeof(swd_hdr)), trunc_page(hdrOffset),
                UIO_SYSSPACE, IO_SKIP_ENCRYPTION|IO_SYNC|IO_NODELOCKED|IO_UNIT|IO_NOCACHE, 
                vfs_context_ucred(ctx), (int *) 0,
                vfs_context_proc(ctx));
    if (rc != 0) {
        DMSG("sleepWakeDebugDumpFromFile: Failed to debug read header size %lu. rc=%d\n",
             round_page(sizeof(swd_hdr)), rc);
          swd_flags |= SWD_FILEOP_ERROR;
        goto exit;
    }

    hdr = (swd_hdr *)((char *)tmpBuf + (hdrOffset - trunc_page(hdrOffset)));
    if ((hdr->signature != SWD_HDR_SIGNATURE) || (hdr->alloc_size > SWD_BUF_SIZE) ||
        (hdr->spindump_offset > SWD_BUF_SIZE) || (hdr->spindump_size > SWD_BUF_SIZE)) {
        DMSG("sleepWakeDebugDumpFromFile: Invalid data in debug header. sign:0x%x size:0x%x spindump_offset:0x%x spindump_size:0x%x\n",
             hdr->signature, hdr->alloc_size, hdr->spindump_offset, hdr->spindump_size);
          swd_flags |= SWD_BUF_SIZE_ERROR;
        goto exit;
    }
    stacksSize = hdr->spindump_size;

    /* Get stacks & log offsets in the image file */
    stacksOffset = hdrOffset + hdr->spindump_offset;
    logOffset = hdrOffset + offsetof(swd_hdr, UUID);
    logSize = sizeof(swd_hdr)-offsetof(swd_hdr, UUID); 
    stacksFname = getDumpStackFilename(hdr);
    logFname = getDumpLogFilename(hdr);

    error = sleepWakeDebugCopyFile(vp, ctx, (char *)tmpBuf, tmpBufSize, stacksOffset,
                                   stacksFname, stacksSize, hdr->crc);
    if (error == EFAULT) {
        DMSG("sleepWakeDebugDumpFromFile: Stackshot CRC doesn't match\n");
        goto exit;
    }
    error = sleepWakeDebugCopyFile(vp, ctx, (char *)tmpBuf, tmpBufSize, logOffset, 
                                   logFname, logSize, 0);
    if (error) {
        DMSG("sleepWakeDebugDumpFromFile: Failed to write the log file(0x%x)\n", error);
        goto exit;
    }
exit:
    if (error) {
      // Write just the SleepWakeLog.dump with failure code
      uint64_t fcode = 0;
      const char *fname;
      swd_hdr hdrCopy;
      char *offset = NULL;
      int  size;

      hdr = &hdrCopy;
      if (swd_flags & SWD_BOOT_BY_SW_WDOG) {
          failStat = OSDynamicCast(OSNumber, getProperty(kIOPMSleepWakeFailureCodeKey));
          fcode = failStat->unsigned64BitValue();
          fname = kSleepWakeLogFilename;
      }
      else {
          fname = kAppleOSXWatchdogLogFilename;
      }

      offset = (char*)hdr+offsetof(swd_hdr, UUID);
      size = sizeof(swd_hdr)-offsetof(swd_hdr, UUID);
      memset(offset, 0x20, size); // Fill with spaces


      snprintf(hdr->spindump_status, sizeof(hdr->spindump_status), "\nstatus: 0x%x", swd_flags);
      snprintf(hdr->PMStatusCode, sizeof(hdr->PMStatusCode), "\nCode: 0x%llx", fcode);
      snprintf(hdr->reason, sizeof(hdr->reason), "\nStackshot reason: Watchdog\n\n");
      sleepWakeDebugSaveFile(fname, offset, size);

    }
    gRootDomain->swd_lock = 0;

    if (vp) vnode_close(vp, FREAD, ctx);
    if (ctx) vfs_context_rele(ctx);
    if (tmpBufDesc) tmpBufDesc->release();
#endif /* HIBERNATION */
}

void IOPMrootDomain::sleepWakeDebugDumpFromMem(IOMemoryMap *logBufMap)
{
   IOVirtualAddress     srcBuf = NULL;
   char                 *stackBuf = NULL, *logOffset = NULL;
   int                  logSize = 0;

   errno_t      error = EIO;
   uint64_t     bufSize = 0;
   swd_hdr      *hdr = NULL;
   OSNumber  *failStat = NULL;

   if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock))
       return;

   if ((logBufMap == 0) || ( (srcBuf = logBufMap->getVirtualAddress()) == 0) )
   {
      DLOG("Nothing saved to dump to file\n");
      goto exit;
   }

   hdr = (swd_hdr *)srcBuf;
   bufSize = logBufMap->getLength();
   if (bufSize <= sizeof(swd_hdr))
   {
      IOLog("SleepWake log buffer size is invalid\n");
      swd_flags |= SWD_BUF_SIZE_ERROR;
      goto exit;
   }

   stackBuf = (char*)hdr+hdr->spindump_offset;

   error = sleepWakeDebugSaveFile(getDumpStackFilename(hdr), stackBuf, hdr->spindump_size);
   if (error) goto exit;

   logOffset = (char*)hdr+offsetof(swd_hdr, UUID);
   logSize = sizeof(swd_hdr)-offsetof(swd_hdr, UUID);

   error = sleepWakeDebugSaveFile(getDumpLogFilename(hdr), logOffset, logSize);
   if (error) goto exit;

    hdr->spindump_size = 0;
    error = 0;

exit:
    if (error) {
      // Write just the SleepWakeLog.dump with failure code
      uint64_t fcode = 0;
      const char *sname, *lname;
      swd_hdr hdrCopy;

      /* Try writing an empty stacks file */
      hdr = &hdrCopy;
      if (swd_flags & SWD_BOOT_BY_SW_WDOG) {
          failStat = OSDynamicCast(OSNumber, getProperty(kIOPMSleepWakeFailureCodeKey));
          fcode = failStat->unsigned64BitValue();
          lname = kSleepWakeLogFilename;
          sname = kSleepWakeStackFilename;
      }
      else {
          lname = kAppleOSXWatchdogLogFilename;
          sname= kAppleOSXWatchdogStackFilename;
      }

      sleepWakeDebugSaveFile(sname, NULL, 0);

      logOffset = (char*)hdr+offsetof(swd_hdr, UUID);
      logSize = sizeof(swd_hdr)-offsetof(swd_hdr, UUID);
      memset(logOffset, 0x20, logSize); // Fill with spaces


      snprintf(hdr->spindump_status, sizeof(hdr->spindump_status), "\nstatus: 0x%x", swd_flags);
      snprintf(hdr->PMStatusCode, sizeof(hdr->PMStatusCode), "\nCode: 0x%llx", fcode);
      snprintf(hdr->reason, sizeof(hdr->reason), "\nStackshot reason: Watchdog\n\n");
      sleepWakeDebugSaveFile(lname, logOffset, logSize);
    }

    gRootDomain->swd_lock = 0;
}

IOMemoryMap *IOPMrootDomain::sleepWakeDebugRetrieve( )
{
   IOVirtualAddress     vaddr = NULL;
   IOMemoryDescriptor * desc = NULL;
   IOMemoryMap *        logBufMap = NULL;

   uint32_t          len = INT_MAX;
   addr64_t          data[3];
   uint64_t          bufSize = 0;
   uint64_t          crc = 0;
   uint64_t          newcrc = 0;
   uint64_t          paddr = 0;
   swd_hdr           *hdr = NULL;
   bool              ret = false;
   char              str[20];


   if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock))
       return NULL;

   if (!PEReadNVRAMProperty(kIOSleepWakeDebugKey, 0, &len)) {
      DLOG("No sleepWakeDebug note to read\n");
      goto exit;
   }

   if (len == strlen("sleepimage")) {
       str[0] = 0;
       PEReadNVRAMProperty(kIOSleepWakeDebugKey, str, &len);

       if (!strncmp((char*)str, "sleepimage", strlen("sleepimage"))) {
           DLOG("sleepWakeDebugRetrieve: in file logs\n");
           swd_flags |= SWD_LOGS_IN_FILE|SWD_VALID_LOGS;
           goto exit;
       }
   }
   else if (len == sizeof(addr64_t)*3) {
       PEReadNVRAMProperty(kIOSleepWakeDebugKey, data, &len);
   }
   else {
      DLOG("Invalid sleepWakeDebug note length(%d)\n", len);
      goto exit;
   }



   DLOG("sleepWakeDebugRetrieve: data[0]:0x%llx data[1]:0x%llx data[2]:0x%llx\n",
        data[0], data[1], data[2]);
   DLOG("sleepWakeDebugRetrieve: in mem logs\n");
   bufSize = data[0];
   crc = data[1];
   paddr = data[2];
   if ( (bufSize <= sizeof(swd_hdr)) ||(bufSize > SWD_BUF_SIZE) || (crc == 0) )
   {
      IOLog("SleepWake log buffer size is invalid\n");
      swd_flags |= SWD_BUF_SIZE_ERROR;
      return NULL;
   }

   DLOG("size:0x%llx crc:0x%llx paddr:0x%llx\n",
         bufSize, crc, paddr);


   desc = IOMemoryDescriptor::withAddressRange( paddr, bufSize,
                          kIODirectionOutIn | kIOMemoryMapperNone, NULL);
   if (desc == NULL)
   {
      IOLog("Fail to map SleepWake log buffer\n");
      swd_flags |= SWD_INTERNAL_FAILURE;
      goto exit;
   }

   logBufMap = desc->map();

   vaddr = logBufMap->getVirtualAddress();


   if ( (logBufMap->getLength() <= sizeof(swd_hdr)) || (vaddr == NULL) ) {
      IOLog("Fail to map SleepWake log buffer\n");
      swd_flags |= SWD_INTERNAL_FAILURE;
      goto exit;
   }

   hdr = (swd_hdr *)vaddr;
   if (hdr->spindump_offset+hdr->spindump_size > bufSize)
   {
      IOLog("SleepWake log header size is invalid\n");
      swd_flags |= SWD_HDR_SIZE_ERROR;
      goto exit;
   }

   hdr->crc = crc;
   newcrc = crc32(0, (void *)((char*)vaddr+hdr->spindump_offset),
            hdr->spindump_size);
   if (newcrc != crc) {
      IOLog("SleepWake log buffer contents are invalid\n");
      swd_flags |= SWD_DATA_CRC_ERROR;
      goto exit;
   }

   ret = true;
   swd_flags |= SWD_LOGS_IN_MEM | SWD_VALID_LOGS;


exit:
   PERemoveNVRAMProperty(kIOSleepWakeDebugKey);
   if (!ret) {
      if (logBufMap) logBufMap->release();
      logBufMap = 0;
   }
   if (desc) desc->release();
    gRootDomain->swd_lock = 0;

   return logBufMap;
}

#else

void IOPMrootDomain::sleepWakeDebugTrig(bool restart)
{
    uint32_t wdog_panic = 1;

    if (restart) {
        if (PE_parse_boot_argn("swd_panic", &wdog_panic, sizeof(wdog_panic)) &&
            (wdog_panic == 0)) {
            return;
        }
        panic("Sleep/Wake hang detected\n");
        return;
    }
}

void IOPMrootDomain::takeStackshot(bool restart, bool isOSXWatchdog, bool isSpinDump)
{
#pragma unused(restart)
#pragma unused(isOSXWatchdog)
}

void IOPMrootDomain::sleepWakeDebugMemAlloc( )
{
}
void IOPMrootDomain::sleepWakeDebugDumpFromMem(IOMemoryMap *map)
{
}
errno_t IOPMrootDomain::sleepWakeDebugCopyFile(
                               struct vnode *srcVp, 
                               vfs_context_t srcCtx,
                               char *tmpBuf, uint64_t tmpBufSize,
                               uint64_t srcOffset, 
                               const char *dstFname, 
                               uint64_t numBytes,
                               uint32_t crc)
{
    return EIO;
}

void IOPMrootDomain::sleepWakeDebugDumpFromFile()
{
}

IOMemoryMap *IOPMrootDomain::sleepWakeDebugRetrieve( )
{
   return NULL;
}

void IOPMrootDomain::sleepWakeDebugEnableWdog()
{
}

bool IOPMrootDomain::sleepWakeDebugIsWdogEnabled()
{
    return false;
}

errno_t IOPMrootDomain::sleepWakeDebugSaveFile(const char *name, char *buf, int len)
{
    return 0;
}

#endif

