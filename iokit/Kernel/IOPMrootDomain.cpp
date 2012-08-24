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
#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <console/video_console.h>
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
#define LOG_PREFIX              "PMRD: "

#define MSG(x...) \
    do { kprintf(LOG_PREFIX x); IOLog(x); } while (false)

#define LOG(x...)    \
    do { kprintf(LOG_PREFIX x); } while (false)

#define DLOG(x...)  do { \
	if (kIOLogPMRootDomain & gIOKitDebug) \
        kprintf(LOG_PREFIX x); } while (false)

#define _LOG(x...)

#define DARK_WAKE_DEBUG                     1
#define SUSPEND_PM_NOTIFICATIONS_DEBUG      1

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

#define DARK_TO_FULL_EVALUATE_CLAMSHELL     0

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
    kPowerEventSuspendClient                    // 14
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
    kStimulusNoIdleSleepPreventers      // 9
};

extern "C" {
IOReturn OSKextSystemSleepOrWake( UInt32 );
}

static void idleSleepTimerExpired( thread_call_param_t, thread_call_param_t );
static void notifySystemShutdown( IOService * root, unsigned long event );
static void handleAggressivesFunction( thread_call_param_t, thread_call_param_t );
static void pmEventTimeStamp(uint64_t *recordTS);

// "IOPMSetSleepSupported"  callPlatformFunction name
static const OSSymbol *sleepSupportedPEFunction = NULL;
static const OSSymbol *sleepMessagePEFunction   = NULL;

#define kIOSleepSupportedKey        "IOSleepSupported"
#define kIOPMSystemCapabilitiesKey  "System Capabilities"

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
    {1, kIOPMRestartCapability,	kIOPMRestart,	RESTART_POWER, 0,0,0,0,0,0,0,0},	
    {1, kIOPMSleepCapability,   kIOPMSleep,     SLEEP_POWER,   0,0,0,0,0,0,0,0},
    {1, kIOPMPowerOn,           kIOPMPowerOn,   ON_POWER,      0,0,0,0,0,0,0,0}
};

#define kIOPMRootDomainWakeTypeSleepService "SleepService"
#define kIOPMRootDomainWakeTypeMaintenance  "Maintenance"
#define kIOPMRootDomainWakeTypeSleepTimer   "SleepTimer"
#define kIOPMrootDomainWakeTypeLowBattery   "LowBattery"
#define kIOPMRootDomainWakeTypeUser         "User"
#define kIOPMRootDomainWakeTypeAlarm        "Alarm"
#define kIOPMRootDomainWakeTypeNetwork      "Network"
#define kIOPMRootDomainWakeTypeHIDActivity  "HID Activity"

// Special interest that entitles the interested client from receiving
// all system messages. Only used by powerd.
//
#define kIOPMSystemCapabilityInterest       "IOPMSystemCapabilityInterest"

#define kPMSuspendedNotificationClients      "PMSuspendedNotificationClients"

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
    kDarkWakeFlagIgnoreDiskIOInDark  = 0x04, // ignore disk idle in DW
    kDarkWakeFlagIgnoreDiskIOAlways  = 0x08, // always ignore disk idle
    kDarkWakeFlagIgnoreDiskIOMask    = 0x0C,
    kDarkWakeFlagAlarmIsDark         = 0x0100
};

static IOPMrootDomain * gRootDomain;
static IONotifier *     gSysPowerDownNotifier = 0;
static UInt32           gSleepOrShutdownPending = 0;
static UInt32           gWillShutdown = 0;
static UInt32           gPagingOff = 0;
static UInt32           gSleepWakeUUIDIsSet = false;
static uint32_t         gAggressivesState = 0;
static uint32_t         gDarkWakeFlags = kDarkWakeFlagHIDTickleNone | kDarkWakeFlagIgnoreDiskIOAlways;
static PMStatsStruct    gPMStats;

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
    void free(void);
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

    void free(void);

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

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

/* @class IOPMTimeline
 * @astract Tracks & records PM activity.
 * @discussion Intended for use only as a helper-class to IOPMrootDomain.
 *      Do not subclass or directly invoke iOPMTimeline
 */
class IOPMTimeline : public OSObject 
{
    OSDeclareDefaultStructors( IOPMTimeline );

public:  
    static IOPMTimeline* timeline(IOPMrootDomain *root_domain);
  
    bool            setProperties(OSDictionary *d);
    OSDictionary    *copyInfoDictionary(void);
    
    IOReturn    recordSystemPowerEvent( PMEventDetails *details );
                                
    IOReturn    recordDetailedPowerEvent( PMEventDetails *details );

    IOMemoryDescriptor      *getPMTraceMemoryDescriptor();
    
    uint32_t getNumEventsLoggedThisPeriod();    
    void     setNumEventsLoggedThisPeriod(uint32_t newCount);
    bool     isSleepCycleInProgress();
    void     setSleepCycleInProgressFlag(bool flag);
private:
    bool        init(void);
    void        free(void);

    void        setEventsTrackedCount(uint32_t newTracked);
    void        setEventsRecordingLevel(uint32_t eventsTrackedBits);
    static uint32_t _atomicIndexIncrement(uint32_t *index, uint32_t limit);
    
    enum {
        kPMTimelineRecordTardyDrivers   = 1 << 0,
        kPMTmielineRecordSystemEvents   = 1 << 1,
        kPMTimelineRecordAllDrivers     = 1 << 2,
        kPMTimelineRecordOff            = 0,
        kPMTimelineRecordDefault        = 3,
        kPMTimelineRecordDebug          = 7    
    };

    // eventsRecordingLevel is a bitfield defining which PM driver events will get logged
    // into the PM buffer. 
    uint32_t                    eventsRecordingLevel;
    
    // pmTraceMemoryDescriptor represents the memory block that IOPMTimeLine records PM trace points into.
    IOBufferMemoryDescriptor    *pmTraceMemoryDescriptor;

    // Pointer to starting address in pmTraceMemoryDescriptor
    IOPMSystemEventRecord       *traceBuffer;
    IOPMTraceBufferHeader       *hdr;

    uint16_t                    systemState;
    
    IOLock                      *logLock;
    IOPMrootDomain              *owner;

    uint32_t                    numEventsLoggedThisPeriod;
    bool                        sleepCycleInProgress;
};

OSDefineMetaClassAndStructors( IOPMTimeline, OSObject )

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
    void                        tracePoint(uint8_t phase, uint8_t data8);
    void                        traceDetail(uint32_t detail);
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

    uint8_t                     addedToRegistry;
    uint8_t                     tracePhase;
    uint8_t                     loginWindowPhase;
    uint8_t                     traceData8;
    uint32_t                    traceData32;
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
    virtual void free( void );
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
		if (OSCompareAndSwap(0, 1, &gPagingOff))
		{
#if !CONFIG_EMBEDDED
			gRootDomain->handlePlatformHaltRestart(kPEPagingOff);
#endif
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

static void disk_sync_callout( thread_call_param_t p0, thread_call_param_t p1 )
{
    IOService * rootDomain = (IOService *) p0;
    uint32_t    notifyRef  = (uint32_t)(uintptr_t) p1;
    uint32_t    powerState = rootDomain->getPowerState();

    DLOG("disk_sync_callout ps=%u\n", powerState);

    if (ON_STATE == powerState)
    {
#if	HIBERNATION
        IOHibernateSystemSleep();
#endif
        sync_internal();
    }
#if	HIBERNATION
    else
    {
        IOHibernateSystemPostWake();
    }
#endif

    rootDomain->allowPowerChange(notifyRef);
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
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    &gIOLastSleepTime, 0, sysctl_sleepwaketime, "S,timeval", "");

static SYSCTL_PROC(_kern, OID_AUTO, waketime,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    &gIOLastWakeTime, 0, sysctl_sleepwaketime, "S,timeval", "");


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
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    0, 0, sysctl_progressmeterenable, "I", "");

static SYSCTL_PROC(_kern, OID_AUTO, progressmeter,
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    0, 0, sysctl_progressmeter, "I", "");

#endif

static SYSCTL_INT(_debug, OID_AUTO, darkwake, CTLFLAG_RW, &gDarkWakeFlags, 0, "");

static const OSSymbol * gIOPMSettingAutoWakeSecondsKey;
static const OSSymbol * gIOPMSettingDebugWakeRelativeKey;
static const OSSymbol * gIOPMSettingMaintenanceWakeCalendarKey;
static const OSSymbol * gIOPMSettingSleepServiceWakeCalendarKey;
static const OSSymbol * gIOPMSettingSilentRunningKey;

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

    super::start(nub);

    gRootDomain = this;
    gIOPMSettingAutoWakeSecondsKey = OSSymbol::withCString(kIOPMSettingAutoWakeSecondsKey);
    gIOPMSettingDebugWakeRelativeKey = OSSymbol::withCString(kIOPMSettingDebugWakeRelativeKey);
    gIOPMSettingMaintenanceWakeCalendarKey = OSSymbol::withCString(kIOPMSettingMaintenanceWakeCalendarKey);
    gIOPMSettingSleepServiceWakeCalendarKey = OSSymbol::withCString(kIOPMSettingSleepServiceWakeCalendarKey);
    gIOPMSettingSilentRunningKey = OSSymbol::withCStringNoCopy(kIOPMSettingSilentRunningKey);

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
    
    queue_init(&aggressivesQueue);
    aggressivesThreadCall = thread_call_allocate(handleAggressivesFunction, this);
    aggressivesData = OSData::withCapacity(
                        sizeof(AggressivesRecord) * (kPMLastAggressivenessType + 4));

    featuresDictLock = IOLockAlloc();
    settingsCtrlLock = IOLockAlloc();
    setPMRootDomain(this);
    
    extraSleepTimer = thread_call_allocate(
                        idleSleepTimerExpired,
                        (thread_call_param_t) this);

    diskSyncCalloutEntry = thread_call_allocate(
                        &disk_sync_callout,
                        (thread_call_param_t) this);
    
    setProperty(kIOSleepSupportedKey, true);

    bzero(&gPMStats, sizeof(gPMStats));

    pmTracer = PMTraceWorker::tracer(this);

    pmAssertions = PMAssertionsTracker::pmAssertionsTracker(this);

    userDisabledAllSleep = false;
    systemBooting = true;
    sleepSlider = 0;
    idleSleepTimerPending = false;
    wrangler = NULL;
    clamshellClosed    = false;
    clamshellExists    = false;
    clamshellDisabled  = true;
    acAdaptorConnected = true;

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

    // List of PM settings that should not automatically publish itself
    // as a feature when registered by a listener.
    noPublishPMSettings = OSArray::withObjects(
                    (const OSObject **) &gIOPMSettingSilentRunningKey, 1, 0);

    fPMSettingsDict = OSDictionary::withCapacity(5);
    preventIdleSleepList = OSSet::withCapacity(8);
    preventSystemSleepList = OSSet::withCapacity(2);

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
    changePowerStateToPriv(ON_STATE);

    if (gIOKitDebug & (kIOLogDriverPower1 | kIOLogDriverPower2))
    {
        // Setup our PM logging & recording code
        timeline = IOPMTimeline::timeline(this);    
        if (timeline) {
            OSDictionary *tlInfo = timeline->copyInfoDictionary();
            
            if (tlInfo) 
            {
                setProperty(kIOPMTimelineDictionaryKey, tlInfo);
                tlInfo->release();
            }
        }
    }

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
    
    
    pmSuspendedCapacity = pmSuspendedSize = 0;
    pmSuspendedPIDS = NULL;
    

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




void IOPMrootDomain::handleSuspendPMNotificationClient(uint32_t pid, bool doSuspend)
{
    ASSERT_GATED();
    
    int index = -1;
    unsigned int i;
    
    if (!pmSuspendedPIDS) {
        pmSuspendedCapacity = 8;
        pmSuspendedSize = pmSuspendedCapacity * sizeof(PMNotifySuspendedStruct);
        pmSuspendedPIDS = (PMNotifySuspendedStruct *)IOMalloc(pmSuspendedSize);
        bzero(pmSuspendedPIDS, pmSuspendedSize);
    }
    
    /* Find the existing pid in the existing array */

    for (i=0; i < pmSuspendedCapacity; i++) {
        if (pmSuspendedPIDS[i].pid == pid) {
            index = i;
            break;
        }
    }
    
    if (-1 == index)
    {
        /* Find an unused slot in the suspended pids table. */

        for (i=0; i < pmSuspendedCapacity; i++) {
            if (pmSuspendedPIDS[i].refcount == 0) {
                break;
            }
        }
    
        if (pmSuspendedCapacity == i) 
        {
            /* GROW if necessary */

            PMNotifySuspendedStruct *newSuspended = NULL;
            pmSuspendedCapacity     *= 2;
            pmSuspendedSize         = pmSuspendedCapacity * sizeof(PMNotifySuspendedStruct);
            newSuspended            = (PMNotifySuspendedStruct *)IOMalloc(pmSuspendedSize);

            bzero(newSuspended, pmSuspendedSize);
            bcopy(pmSuspendedPIDS,  newSuspended, pmSuspendedSize/2);
            IOFree(pmSuspendedPIDS, pmSuspendedSize/2);
        
            pmSuspendedPIDS = newSuspended;
        }

        index = i;
        pmSuspendedPIDS[index].pid = pid;
    }

    if (doSuspend) {
        pmSuspendedPIDS[index].refcount++;
    } else {
        pmSuspendedPIDS[index].refcount--;
    }
        
    /*
     * Publish array of suspended pids in IOPMrootDomain
     */
    OSArray     *publish = OSArray::withCapacity(pmSuspendedCapacity);

    for (i=0; i<pmSuspendedCapacity; i++)
    {
        if (pmSuspendedPIDS[i].refcount > 0) {
            OSDictionary    *suspended = OSDictionary::withCapacity(2);
            OSNumber        *n = NULL;
            
            n = OSNumber::withNumber(pmSuspendedPIDS[i].pid, 32);
            suspended->setObject("pid", n);
            n->release();
            
            n = OSNumber::withNumber(pmSuspendedPIDS[i].refcount, 32);
            suspended->setObject("refcount", n);
            n->release();
            
            publish->setObject(suspended);
            suspended->release();
            
        }
    }
    
    if (0 != publish->getCount()) {
        setProperty(kPMSuspendedNotificationClients, publish);
    } else {
        removeProperty(kPMSuspendedNotificationClients);
    }
    
    publish->release();
    
    return;
}

bool IOPMrootDomain::pmNotificationIsSuspended(uint32_t pid)
{
    unsigned int index;
    
    for (index=0; index < pmSuspendedCapacity; index++) {
        if (pmSuspendedPIDS[index].pid == pid) {
            return pmSuspendedPIDS[index].refcount > 0;
        }
    }
    
    return false;
}


void IOPMrootDomain::suspendPMNotificationsForPID(uint32_t pid, bool doSuspend)
{
    if(pmPowerStateQueue) {
        pmPowerStateQueue->submitPowerEvent(kPowerEventSuspendClient, (void *)pid, (uint64_t)doSuspend );
    }
    return;
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
    OSDictionary    *d;
    OSSymbol        *type;
    OSObject        *obj;
    unsigned int    i;

    const OSSymbol *publish_simulated_battery_string    = OSSymbol::withCString("SoftwareSimulatedBatteries");
    const OSSymbol *boot_complete_string                = OSSymbol::withCString("System Boot Complete");
    const OSSymbol *sys_shutdown_string                 = OSSymbol::withCString("System Shutdown");
    const OSSymbol *stall_halt_string                   = OSSymbol::withCString("StallSystemAtHalt");
    const OSSymbol *battery_warning_disabled_string     = OSSymbol::withCString("BatteryWarningsDisabled");
    const OSSymbol *idle_seconds_string                 = OSSymbol::withCString("System Idle Seconds");
    const OSSymbol *sleepdisabled_string                = OSSymbol::withCString("SleepDisabled");
    const OSSymbol *ondeck_sleepwake_uuid_string        = OSSymbol::withCString(kIOPMSleepWakeUUIDKey);
    const OSSymbol *loginwindow_tracepoint_string       = OSSymbol::withCString(kIOPMLoginWindowSecurityDebugKey);
    const OSSymbol *pmTimelineLogging_string            = OSSymbol::withCString(kIOPMTimelineDictionaryKey);
#if	HIBERNATION
    const OSSymbol *hibernatemode_string                = OSSymbol::withCString(kIOHibernateModeKey);
    const OSSymbol *hibernatefile_string                = OSSymbol::withCString(kIOHibernateFileKey);
    const OSSymbol *hibernatefreeratio_string           = OSSymbol::withCString(kIOHibernateFreeRatioKey);
    const OSSymbol *hibernatefreetime_string            = OSSymbol::withCString(kIOHibernateFreeTimeKey);
#endif
#if SUSPEND_PM_NOTIFICATIONS_DEBUG
    const OSSymbol *suspendPMClient_string              = OSSymbol::withCString(kPMSuspendedNotificationClients);
#endif
    
    if (!dict) 
    {
        return_value = kIOReturnBadArgument;
        goto exit;
    }
    
    if ((b = OSDynamicCast(OSBoolean, dict->getObject(publish_simulated_battery_string))))
    {
        publishResource(publish_simulated_battery_string, kOSBooleanTrue);
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
    
    if( battery_warning_disabled_string && dict->getObject(battery_warning_disabled_string))
    {
        setProperty( battery_warning_disabled_string, dict->getObject(battery_warning_disabled_string));
    }
    
    if (pmTimelineLogging_string && (d = OSDynamicCast(OSDictionary, dict->getObject(pmTimelineLogging_string))))
    {
        if (timeline && timeline->setProperties(d)) 
        {
            OSDictionary *tlInfo = timeline->copyInfoDictionary();            
            if (tlInfo) {
                setProperty(kIOPMTimelineDictionaryKey, tlInfo);
                tlInfo->release();
            }
        }
    }

    if( sys_shutdown_string && (b = OSDynamicCast(OSBoolean, dict->getObject(sys_shutdown_string)))) 
    {
        pmPowerStateQueue->submitPowerEvent(kPowerEventSystemShutdown, (void *) b);
    }
    
    if( stall_halt_string && (b = OSDynamicCast(OSBoolean, dict->getObject(stall_halt_string))) ) 
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
    OSString *str;
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
        if(pmPowerStateQueue) {
            obj->retain();
            pmPowerStateQueue->submitPowerEvent(kPowerEventQueueSleepWakeUUID, (void *)obj);
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

#if SUSPEND_PM_NOTIFICATIONS_DEBUG
    if ((n = OSDynamicCast(OSNumber, dict->getObject(suspendPMClient_string))))
    {
        // Toggle the suspended status for pid n.
        uint32_t pid_int = n->unsigned32BitValue();        
        suspendPMNotificationsForPID(pid_int, !pmNotificationIsSuspended(pid_int));
    }
#endif
    
    if ((b = OSDynamicCast(OSBoolean, dict->getObject(kIOPMDestroyFVKeyOnStandbyKey))))
    {
        setProperty(kIOPMDestroyFVKeyOnStandbyKey, b);
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
        if (gIOPMSettingDebugWakeRelativeKey == type)
        {
            if ((n = OSDynamicCast(OSNumber, obj)))
                _debugWakeSeconds = n->unsigned32BitValue();
            else
                _debugWakeSeconds = 0;
        }
        
        return_value = setPMSetting(type, obj);
        
        if(kIOReturnSuccess != return_value) goto exit;
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
    if(loginwindow_tracepoint_string) loginwindow_tracepoint_string->release();
    if(pmTimelineLogging_string) pmTimelineLogging_string->release();
#if	HIBERNATION
    if(hibernatemode_string) hibernatemode_string->release();
    if(hibernatefile_string) hibernatefile_string->release();
    if(hibernatefreeratio_string) hibernatefreeratio_string->release();
    if(hibernatefreetime_string) hibernatefreetime_string->release();
#endif
#if SUSPEND_PM_NOTIFICATIONS_DEBUG
    if(suspendPMClient_string) suspendPMClient_string->release();
#endif
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

    DLOG("joinAggressiveness %s %p\n", service->getName(), service);

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

                if ((service = (IOService *) connect->copyChildEntry(gIOPowerPlane)))
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

    setQuickSpinDownTimeout();
    adjustPowerState(true);
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
    } else {
        return privateSleepSystem( kIOPMSleepReasonSoftware);
    }
}

/* private */
IOReturn IOPMrootDomain::privateSleepSystem( uint32_t sleepReason )
{
    static const char * IOPMSleepReasons[] = {
        "",
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

    PMEventDetails *details;

    if (!checkSystemCanSleep())
    {
        // Record why the system couldn't sleep	
        details = PMEventDetails::eventDetails(kIOPMEventTypeSleep, NULL,
                                        sleepReason, kIOReturnNotPermitted);
		
		recordAndReleasePMEvent( details );
        return kIOReturnNotPermitted;
    }

    if (kIOPMSleepReasonDarkWakeThermalEmergency == sleepReason)
        messageClients(kIOPMMessageDarkWakeThermalEmergency);

    if (timeline)
        timeline->setSleepCycleInProgressFlag(true);
  
    // Time to publish a UUID for the Sleep --> Wake cycle  
    if(pmPowerStateQueue) {
        pmPowerStateQueue->submitPowerEvent(kPowerEventPublishSleepWakeUUID, (void *)true);
    }
  
    // Log the beginning of system sleep.
	details = PMEventDetails::eventDetails(kIOPMEventTypeSleep, NULL,
                                            sleepReason, kIOReturnSuccess);
	
	recordAndReleasePMEvent( details );
	
    // Record sleep cause in IORegistry
    lastSleepReason = sleepReason;
    sleepReason -= (kIOPMSleepReasonClamshell - 1);
    if (sleepReason && (sleepReason < sizeof(IOPMSleepReasons)/sizeof(IOPMSleepReasons[0]))) {
        setProperty(kRootDomainSleepReasonKey, IOPMSleepReasons[sleepReason]);
    }

    if (pmPowerStateQueue)
        pmPowerStateQueue->submitPowerEvent(
                            kPowerEventPolicyStimulus,
                            (void *) kStimulusDemandSystemSleep );

    return kIOReturnSuccess;
}

IOReturn IOPMrootDomain::recordPMEventGated(PMEventDetails *record)
{  
  // If we don't have a place to log to, we can't actually
  // log anything. Chances are, the person who is asking us to do    
  // the PM logging has forgotten to set the right bootflags
  if(!timeline)
    return kIOReturnSuccess;

  if(gIOPMWorkLoop->inGate() == false) {
    
    IOReturn ret = gIOPMWorkLoop->runAction(
                     OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::recordPMEventGated),
                     (OSObject *)this,
                     (void *)record);
    
    return ret;
  }
  else {
    // Now that we're guaranteed to be running in gate ...

    // Check the validity of the argument we are given
    if(!record) 
      return kIOReturnBadArgument;
    
	  // Record a driver event, or a system event
	  if(record->eventClassifier == kIOPMEventClassDriverEvent
	     || record->eventClassifier == kIOPMEventClassSystemEvent)
		  return this->recordPMEvent(record);
	
	  else
		  return kIOReturnBadArgument;
  }
}

IOReturn IOPMrootDomain::recordAndReleasePMEventGated(PMEventDetails *record)
{
    IOReturn ret = kIOReturnBadArgument;

    if (record)
    {
        ret = recordPMEventGated(record);
        record->release();
    }
    
    return ret;
}

//******************************************************************************
// powerChangeDone
//
// This overrides powerChangeDone in IOService.
//******************************************************************************

void IOPMrootDomain::powerChangeDone( unsigned long previousPowerState )
{
    PMEventDetails *details;

    ASSERT_GATED();
    DLOG("PowerChangeDone: %u->%u\n",
        (uint32_t) previousPowerState, (uint32_t) getPowerState());
	
    switch ( getPowerState() )
    {
        case SLEEP_STATE: {
            if (previousPowerState != ON_STATE)
                break;
			
            details = PMEventDetails::eventDetails(
                            kIOPMEventTypeSleepDone,
                            NULL, 
                            NULL, 
                            kIOReturnSuccess);
			
            recordAndReleasePMEvent( details );

            // re-enable this timer for next sleep
            cancelIdleSleepTimer();

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

            IOHibernateSystemHasSlept();

            evaluateSystemSleepPolicyFinal();
#else
            LOG("System Sleep\n");
#endif

            getPlatform()->sleepKernel();

            // The CPU(s) are off at this point,
            // Code will resume execution here upon wake.

            clock_get_uptime(&systemWakeTime);

#if	HIBERNATION
            IOHibernateSystemWake();
#endif

            // sleep transition complete
            gSleepOrShutdownPending = 0;

            // trip the reset of the calendar clock
            clock_wakeup_calendar();

#if	HIBERNATION
            LOG("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
#endif

            // log system wake
            getPlatform()->PMLog(kIOPMrootDomainClass, kPMLogSystemWake, 0, 0);
            lowBatteryCondition = false;
            lastSleepReason = 0;
            
            _lastDebugWakeSeconds = _debugWakeSeconds;
            _debugWakeSeconds = 0;

            // And start logging the wake event here
            // TODO: Publish the wakeReason string as an integer
            details = PMEventDetails::eventDetails(
                            kIOPMEventTypeWake,
                            NULL, 
                            0, 
                            kIOReturnSuccess);
			
            recordAndReleasePMEvent( details );
			
#ifndef __LP64__
            systemWake();
#endif

#if defined(__i386__) || defined(__x86_64__)
            wranglerTickled    = false;
            graphicsSuppressed = false;
            darkWakePostTickle = false;
            logGraphicsClamp   = true;
            logWranglerTickle  = true;
            sleepTimerMaintenance = false;
            wranglerTickleLatched = false;
            darkWakeThermalAlarm  = false;
            darkWakeThermalEmergency = false;

            OSString * wakeType = OSDynamicCast(
                OSString, getProperty(kIOPMRootDomainWakeTypeKey));
            OSString * wakeReason = OSDynamicCast(
                OSString, getProperty(kIOPMRootDomainWakeReasonKey));

            if (wakeType && wakeType->isEqualTo(kIOPMrootDomainWakeTypeLowBattery))
            {
                lowBatteryCondition = true;
                darkWakeMaintenance = true;
                darkWakeToSleepASAP = true;
            }
            else if ((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) != 0)
            {
                OSNumber * hibOptions = OSDynamicCast(
                    OSNumber, getProperty(kIOHibernateOptionsKey));

                if (hibernateAborted || ((hibOptions &&
                    !(hibOptions->unsigned32BitValue() & kIOHibernateOptionDarkWake))))
                {
                    // Hibernate aborted, or EFI brought up graphics
                    wranglerTickled = true;
                }
                else
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
                    darkWakeToSleepASAP = true;
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
                    darkWakeToSleepASAP = true;
                }
                else
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepService))
                {
                    darkWakeToSleepASAP = true;
//                    darkWakeMaintenance = true; // ????
                    darkWakeSleepService = true;
                }
                else
                {
                    // Unidentified wake source, resume to full wake if debug
                    // alarm is pending.

                    if (_lastDebugWakeSeconds &&
                        (!wakeReason || wakeReason->isEqualTo("")))
                        wranglerTickled = true;
                    else
                        darkWakeToSleepASAP = true;
                }
            }
            else
            {
                if (wakeType &&
                    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepTimer))
                {
                    darkWakeMaintenance = true;
                    darkWakeToSleepASAP = true;
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
                    darkWakeToSleepASAP = true;
                }
            }

            if (wranglerTickled)
                reportUserInput();
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
            // stay awake for at least 30 seconds
            wranglerTickled = true;
            startIdleSleepTimer(30);
#endif

            changePowerStateToPriv(ON_STATE);
        }   break;

        case ON_STATE: {
            if (previousPowerState != ON_STATE)
            {
                details = PMEventDetails::eventDetails(
                                kIOPMEventTypeWakeDone,
                                NULL, 
                                0, 
                                kIOReturnSuccess);
                
                recordAndReleasePMEvent( details );
            }
        }   break;
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
//******************************************************************************

void IOPMrootDomain::updatePreventIdleSleepList(
        IOService * service, bool addNotRemove )
{
    unsigned int oldCount, newCount;

    ASSERT_GATED();

    // Disregard disk I/O (anything besides the display wrangler)
    // as a factor preventing idle sleep,except in the case of legacy disk I/O

    if ((gDarkWakeFlags & kDarkWakeFlagIgnoreDiskIOAlways) &&
        addNotRemove && (service != wrangler) && (service != this))
    {
        return;
    }

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
}

//******************************************************************************
// preventSystemSleepListUpdate
//
// Called by IOService on PM work loop.
//******************************************************************************

void IOPMrootDomain::updatePreventSystemSleepList(
        IOService * service, bool addNotRemove )
{
    unsigned int oldCount;

    ASSERT_GATED();
    if (this == service)
        return;

    oldCount = preventSystemSleepList->getCount();
    if (addNotRemove)
    {
        preventSystemSleepList->setObject(service);
        DLOG("prevent system sleep list: %s+ (%u)\n",
            service->getName(), preventSystemSleepList->getCount());
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

        // Notify platform that sleep has begun
        getPlatform()->callPlatformFunction(
                        sleepMessagePEFunction, false,
                        (void *)(uintptr_t) kIOMessageSystemWillSleep,
                        NULL, NULL, NULL);

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
// Called by PM after all apps have responded to kIOMessageCanSystemSleep.
// pmconfigd may create a deny sleep assertion before ack'ing.
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
        // Full->Dark transition is never cancelled.

        if (!checkSystemCanSleep(true))
        {
            // Cancel dark wake to sleep transition.
            // Must re-scan assertions upon entering dark wake.

            *cancel = true;
            DLOG("cancel dark->sleep\n");
        }
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

    if (idleSeconds && !wrangler)
    {
        // stay awake for at least idleSeconds
        startIdleSleepTimer(idleSeconds);
    }
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
            if (idleSeconds && !wrangler)
            {
                // stay awake for at least idleSeconds
                startIdleSleepTimer(idleSeconds);
            }
            tellClients( kIOMessageSystemWillPowerOn );
        }

        tracePoint( kIOPMTracePointWakeApplications );

        if (pmStatsAppResponses) 
        {
            setProperty(kIOPMSleepStatisticsAppsKey, pmStatsAppResponses);
            pmStatsAppResponses->release();
            pmStatsAppResponses = OSArray::withCapacity(5);
        }

        tellClients( kIOMessageSystemHasPoweredOn );
    }
}

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
    IOReturn    ret;

    DLOG("sysPowerDownHandler message %s\n", getIOMessageString(messageType));

    if (!gRootDomain)
        return kIOReturnUnsupported;

    if (messageType == kIOMessageSystemCapabilityChange)
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

        if ((params->changeFlags & kIOPMSystemCapabilityWillChange) &&
            (params->fromCapabilities & kIOPMSystemCapabilityCPU) &&
            (params->toCapabilities & kIOPMSystemCapabilityCPU) == 0)
        {
            // We will ack within 20 seconds
            params->maxWaitForReply = 20 * 1000 * 1000;
#if	HIBERNATION
            gRootDomain->evaluateSystemSleepPolicyEarly();

            // add in time we could spend freeing pages
            if (gRootDomain->hibernateMode && !gRootDomain->hibernateDisabled)
            {
                params->maxWaitForReply = kCapabilityClientMaxWait;
            }
            DLOG("sysPowerDownHandler timeout %d s\n", (int) (params->maxWaitForReply / 1000 / 1000));
#endif

            if ( !OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending ) )
            {
                // Purposely delay the ack and hope that shutdown occurs quickly.
                // Another option is not to schedule the thread and wait for
                // ack timeout...
                AbsoluteTime deadline;
                clock_interval_to_deadline( 30, kSecondScale, &deadline );
                thread_call_enter1_delayed(
                    gRootDomain->diskSyncCalloutEntry, 
                    (thread_call_param_t) params->notifyRef,
                    deadline );
            }
            else
                thread_call_enter1(
                    gRootDomain->diskSyncCalloutEntry,
                    (thread_call_param_t) params->notifyRef);
        }
#if	HIBERNATION
        else
        if ((params->changeFlags & kIOPMSystemCapabilityDidChange) &&
            (params->toCapabilities & kIOPMSystemCapabilityCPU) &&
            (params->fromCapabilities & kIOPMSystemCapabilityCPU) == 0)
        {
            // We will ack within 110 seconds
            params->maxWaitForReply = 110 * 1000 * 1000;

            thread_call_enter1(
                gRootDomain->diskSyncCalloutEntry,
                (thread_call_param_t) params->notifyRef);
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

        OSString *UUIDstring = NULL;
        
        if (timeline && 
            (UUIDstring = OSDynamicCast(OSString, getProperty(kIOPMSleepWakeUUIDKey)))) 
        {
            PMEventDetails *details = PMEventDetails::eventDetails(kIOPMEventTypeUUIDClear, 
                            UUIDstring->getCStringNoCopy(), NULL, 0);
            if (details) {
                timeline->recordSystemPowerEvent( details );
                details->release();
            }
            timeline->setNumEventsLoggedThisPeriod(0); 
        }

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

        if (timeline) {
            PMEventDetails  *details;
            details = PMEventDetails::eventDetails(kIOPMEventTypeUUIDSet,
                              publishThisUUID->getCStringNoCopy(), NULL, 0);
            if (details) {
                timeline->recordSystemPowerEvent( details );
                details->release();
            }
        }
        
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
// sleepOnClamshellClosed
//
// contains the logic to determine if the system should sleep when the clamshell
// is closed.
//******************************************************************************

bool IOPMrootDomain::shouldSleepOnClamshellClosed( void )
{
    if (!clamshellExists)
        return false;

    DLOG("clamshell closed %d, disabled %d, desktopMode %d, ac %d\n",
        clamshellClosed, clamshellDisabled, desktopMode, acAdaptorConnected);

    return ( !clamshellDisabled && !(desktopMode && acAdaptorConnected) );
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
        (void *) ( (clamshellClosed ? kClamshellStateBit : 0)
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
    array = (const OSArray *) settingsCallbacks->getObject(type);
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
        list = (OSArray *) settingsCallbacks->getObject(settings[i]);
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
            array = (OSArray *) settingsCallbacks->getObject(sym);
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

// MARK: -
// MARK: Deep Sleep Policy

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
    kIOPMSleepFactorDriverAssertBit5        = 0x00000400,   /* Reserved for ThunderBolt */
    kIOPMSleepFactorDriverAssertBit6        = 0x00000800,
    kIOPMSleepFactorDriverAssertBit7        = 0x00001000    /* Reserved for legacy I/O */
};

enum {
    kSleepPhaseEarly, kSleepPhaseFinal
};

bool IOPMrootDomain::evaluateSystemSleepPolicy( IOPMSystemSleepParameters * p, int sleepPhase )
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
    if (getPMAssertionLevel(kIOPMDriverAssertionReservedBit5) !=    /* AssertionBit5 = Thunderbolt */
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorDriverAssertBit5;
    if (getPMAssertionLevel(kIOPMDriverAssertionReservedBit7) !=
        kIOPMDriverAssertionLevelOff)
        currentFactors |= kIOPMSleepFactorDriverAssertBit7;
    if (0 == deepSleepDelay)
        currentFactors |= kIOPMSleepFactorDeepSleepNoDelay;
    if (!clamshellClosed)
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
                if (kSleepPhaseFinal == sleepPhase)
                {
                    clock_sec_t now_secs = gIOLastSleepTime.tv_sec;

                    if (!_standbyTimerResetSeconds ||
                        (now_secs <= _standbyTimerResetSeconds))
                    {
                        // Reset standby timer adjustment
                        _standbyTimerResetSeconds = now_secs;
                        DLOG("standby delay %u, reset %u\n",
                            deepSleepDelay, (uint32_t) _standbyTimerResetSeconds);
                    }
                    else if (deepSleepDelay)
                    {
                        // Shorten the standby delay timer
                        clock_sec_t elapsed = now_secs - _standbyTimerResetSeconds;
                        if (deepSleepDelay > elapsed)
                            deepSleepDelay -= elapsed;
                        else
                            deepSleepDelay = 1; // must be > 0

                        DLOG("standby delay %u, elapsed %u\n",
                            deepSleepDelay, (uint32_t) elapsed);
                    }
                }
                p->sleepTimer = deepSleepDelay;
            }
            else if (kSleepPhaseFinal == sleepPhase)
            {
                // A sleep that does not enable the sleep timer will reset
                // the standby delay adjustment.
                _standbyTimerResetSeconds = 0;
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

    // Full wake resets the standby timer delay adjustment
    if (_highestCapability & kIOPMSystemCapabilityGraphics)
        _standbyTimerResetSeconds = 0;

    hibernateDisabled = false;
    hibernateMode = 0;
    getSleepOption(kIOHibernateModeKey, &hibernateMode);

    if (!hibernateNoDefeat &&
        evaluateSystemSleepPolicy(&params, kSleepPhaseEarly) &&
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

    if (evaluateSystemSleepPolicy(&params, kSleepPhaseFinal))
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

// MARK: -
// MARK: Shutdown and Restart

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
				(ctx->MessageType == kIOMessageSystemWillPowerOff) ? "PowerOff" :
					 (ctx->MessageType == kIOMessageSystemPagingOff) ? "PagingOff" : "Restart",
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

		case kPEPagingOff:
			ctx.PowerState  = ON_STATE;
			ctx.MessageType = kIOMessageSystemPagingOff;
			IOService::updateConsoleUsers(NULL, kIOMessageSystemPagingOff);
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

	deltaTime = computeDeltaTimeMS(&startTime);
	LOG("%s all drivers took %u ms\n",
		(ctx.MessageType == kIOMessageSystemWillPowerOff) ? "PowerOff" :
			 (ctx.MessageType == kIOMessageSystemPagingOff) ? "PagingOff" : "Restart",
		(uint32_t) deltaTime );
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
    IOService *     service,
    IOPMActions *   actions,
    unsigned long * inOutPowerState,
    uint32_t *      inOutChangeFlags )
{
    uint32_t    powerState  = (uint32_t) *inOutPowerState;
    uint32_t    changeFlags = *inOutChangeFlags;
    uint32_t    currentPowerState = (uint32_t) getPowerState();

    if ((currentPowerState == powerState) ||
        (changeFlags & kIOPMParentInitiated))
    {
        // FIXME: cancel any parent change (unexpected)
        // Root parent is permanently pegged at max power,
        // kIOPMParentInitiated is unexpected.
        return;
    }

    if (powerState < currentPowerState)
    {
        if ((changeFlags & kIOPMSkipAskPowerDown) == 0)
        {
            /* Convenient place to run any code at idle sleep time
             * IOPMrootDomain initiates an idle sleep here
             *
             * Set last sleep cause accordingly.
             */
            pmPowerStateQueue->submitPowerEvent(kPowerEventPublishSleepWakeUUID, (void *)true);

            lastSleepReason = kIOPMSleepReasonIdle;
            setProperty(kRootDomainSleepReasonKey, kIOPMIdleSleepKey);
        }
        if (CAP_CURRENT(kIOPMSystemCapabilityGraphics))
        {
            // Root domain is dropping power state ON->SLEEP.
            // If system is in full wake, first drop to dark wake.

            darkWakeToSleepASAP = true;

            // Drop graphics capability.
            // No transition if system is already in dark wake.

            _desiredCapability &= ~(
                kIOPMSystemCapabilityGraphics |
                kIOPMSystemCapabilityAudio    );

            *inOutPowerState = ON_STATE;
            *inOutChangeFlags |= kIOPMSynchronize;

            // Revert device desire from SLEEP->ON.
            changePowerStateToPriv(ON_STATE);
        }
    }
}

void IOPMrootDomain::handleOurPowerChangeStart(
    IOService *     service,
    IOPMActions *   actions,
    uint32_t        powerState,
    uint32_t *      inOutChangeFlags )
{
    uint32_t changeFlags = *inOutChangeFlags;
    uint32_t currentPowerState = (uint32_t) getPowerState();

    _systemTransitionType    = kSystemTransitionNone;
    _systemMessageClientMask = 0;
    capabilityLoss           = false;

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

        // Check for early HID events (e.g. LID open)
        if (wranglerTickled)
        {
            _desiredCapability |= (
                kIOPMSystemCapabilityGraphics |
                kIOPMSystemCapabilityAudio );
        }
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
        if (CAP_LOSS(kIOPMSystemCapabilityGraphics))
            rejectWranglerTickle = true;
    }

    // 1. Capability change.

    if (kSystemTransitionCapability == _systemTransitionType)
    {
        // Dark to Full transition.
        if (CAP_GAIN(kIOPMSystemCapabilityGraphics))
        {
            tracePoint( kIOPMTracePointDarkWakeExit );
            wranglerSleepIgnored = false;
            sleepTimerMaintenance = false;
            hibernateNoDefeat = false;
            _systemMessageClientMask = kSystemMessageClientUser;
            if ((_highestCapability & kIOPMSystemCapabilityGraphics) == 0)
                _systemMessageClientMask |= kSystemMessageClientKernel;

            tellClients(kIOMessageSystemWillPowerOn);
        }

        // Full to Dark transition.
        if (CAP_LOSS(kIOPMSystemCapabilityGraphics))
        {
            tracePoint( kIOPMTracePointDarkWakeEntry );
            *inOutChangeFlags |= kIOPMSyncTellPowerDown;
            _systemMessageClientMask = kSystemMessageClientUser;
        }
    }

    // 2. System sleep.

    else if (kSystemTransitionSleep == _systemTransitionType)
    {
        // Beginning of a system sleep transition.
        // Cancellation is still possible.
        tracePoint( kIOPMTracePointSleepStarted, lastSleepReason );

        _systemMessageClientMask = kSystemMessageClientAll;
        if ((_currentCapability & kIOPMSystemCapabilityGraphics) == 0)
            _systemMessageClientMask &= ~kSystemMessageClientApp;
        if ((_highestCapability & kIOPMSystemCapabilityGraphics) == 0)
            _systemMessageClientMask &= ~kSystemMessageClientKernel;

        // Optimization to ignore wrangler power down thus skipping
        // the disk spindown and arming the idle timer for demand sleep.

        if (changeFlags & kIOPMIgnoreChildren)
        {
            wranglerSleepIgnored = true;
        }

        logWranglerTickle = false;
    }

    // 3. System wake.

    else if (kSystemTransitionWake == _systemTransitionType)
    {
        wranglerSleepIgnored = false;

        if (_pendingCapability & kIOPMSystemCapabilityGraphics)
        {
            _systemMessageClientMask = kSystemMessageClientAll;
        }
        else
        {
            _systemMessageClientMask = kSystemMessageClientConfigd;
        }

        tracePoint( kIOPMTracePointWakeWillPowerOnClients );
        tellClients(kIOMessageSystemWillPowerOn);
    }

    if ((kSystemTransitionNone != _systemTransitionType) &&
        (kSystemTransitionNewCapClient != _systemTransitionType))
    {
        _systemStateGeneration++;
        systemDarkWake = false;

        DLOG("=== START (%u->%u, 0x%x) type %u, gen %u, msg %x, "
             "dcp %x:%x:%x\n",
            currentPowerState, powerState, *inOutChangeFlags,
            _systemTransitionType, _systemStateGeneration,
            _systemMessageClientMask,
            _desiredCapability, _currentCapability, _pendingCapability);
    }
}

void IOPMrootDomain::handleOurPowerChangeDone(
    IOService *     service,
    IOPMActions *   actions,
    uint32_t        powerState,
    uint32_t        changeFlags )
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

            if (((_currentCapability & kIOPMSystemCapabilityGraphics) == 0) &&
                (_currentCapability & kIOPMSystemCapabilityCPU))
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
                    tellClients(kIOMessageSystemHasPoweredOn);
#if DARK_TO_FULL_EVALUATE_CLAMSHELL
                    // Re-evaluate clamshell state ourselves when graphics
                    // will not get kIOMessageSystemHasPoweredOn.

                    if (clamshellClosed &&
                        ((_systemMessageClientMask & kSystemMessageClientKernel) == 0))
                    {
                        receivePowerNotification( kLocalEvalClamshellCommand );
                    }
#endif
                }
                if (CAP_LOSS(kIOPMSystemCapabilityGraphics))
                    wranglerTickled = false;
            }

            // Reset state after exiting from dark wake.

            if (CAP_GAIN(kIOPMSystemCapabilityGraphics) ||
                CAP_LOSS(kIOPMSystemCapabilityCPU))
            {
                darkWakeMaintenance = false;
                darkWakeToSleepASAP = false;
                pciCantSleepValid   = false;
                rejectWranglerTickle = false;
                darkWakeSleepService = false;
            }

            // Entered dark mode.

            if (((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0) &&
                 (_pendingCapability & kIOPMSystemCapabilityCPU))
            {
                if (((gDarkWakeFlags & kDarkWakeFlagIgnoreDiskIOInDark) == 0) &&
                    (kSystemTransitionWake == _systemTransitionType) &&
                    (_lastDebugWakeSeconds == 0))
                {
                    OSObject * prop = copyProperty(kIOPMRootDomainWakeTypeKey);
                    if (prop)
                    {
                        OSString * wakeType = OSDynamicCast(OSString, prop);
                        if (wakeType &&
                            wakeType->isEqualTo(kIOPMRootDomainWakeTypeNetwork))
                        {
                            // Woke from network and entered dark wake.                    
                            if (darkWakeToSleepASAP)
                            {
                                DLOG("cleared darkWakeToSleepASAP\n");
                                darkWakeToSleepASAP = false;
                            }
                        }
                        prop->release();
                    }
                }

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
            currentPowerState, powerState, changeFlags,
            _systemTransitionType, _systemStateGeneration,
            _systemMessageClientMask,
            _desiredCapability, _currentCapability, _pendingCapability,
            _lastDebugWakeSeconds);

        // Update current system capability.

        if (_currentCapability != _pendingCapability)
            _currentCapability = _pendingCapability;

        // Update highest system capability.

        if (!CAP_CURRENT(kIOPMSystemCapabilityCPU))
            _highestCapability = 0;     // reset at sleep state
        else
            _highestCapability |= _currentCapability;

        if (darkWakePostTickle &&
            (kSystemTransitionWake == _systemTransitionType) &&
            (gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) ==
             kDarkWakeFlagHIDTickleLate)
        {
            darkWakePostTickle = false;
            reportUserInput();
        }

        // Reset tracepoint at completion of capability change,
        // completion of wake transition, and aborted sleep transition.

        if ((_systemTransitionType == kSystemTransitionCapability) ||
            (_systemTransitionType == kSystemTransitionWake) ||
            ((_systemTransitionType == kSystemTransitionSleep) &&
             (changeFlags & kIOPMNotDone)))
        {
            setProperty(kIOPMSystemCapabilitiesKey, _currentCapability, 64);
            tracePoint( kIOPMTracePointSystemUp, 0 );

            // kIOPMDWOverTemp notification handling was postponed
            if (darkWakeThermalAlarm)
            {
                if (!wranglerTickled && !darkWakeThermalEmergency &&
                    CAP_CURRENT(kIOPMSystemCapabilityCPU) &&
                    !CAP_CURRENT(kIOPMSystemCapabilityGraphics))
                {
                    darkWakeThermalEmergency = true;
                    privateSleepSystem(kIOPMSleepReasonDarkWakeThermalEmergency);
                    MSG("DarkWake thermal limits breached. Going to sleep!\n");
                }
                darkWakeThermalAlarm = false;
            }
        }

        _systemTransitionType = kSystemTransitionNone;
        _systemMessageClientMask = 0;

        logGraphicsClamp = false;
    }
}

//******************************************************************************
// PM actions for graphics and audio.
//******************************************************************************

void IOPMrootDomain::overridePowerChangeForUIService(
    IOService *     service,
    IOPMActions *   actions,
    unsigned long * inOutPowerState,
    uint32_t *      inOutChangeFlags )
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
                service->getName(), service);
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
                service->getName(), service);
        }
    }

    if (actions->parameter & kPMActionsFlagLimitPower)
    {
        uint32_t maxPowerState = (uint32_t)(-1);

        if (changeFlags & (kIOPMDomainDidChange | kIOPMDomainWillChange))
        {
            // Enforce limit for system power/cap transitions.

            maxPowerState = 0;
            if ((actions->parameter & kPMActionsFlagIsDisplayWrangler) &&
                (service->getPowerState() > 0))
            {
                // Forces a 3->1 transition sequence
                if (changeFlags & kIOPMDomainWillChange)
                    maxPowerState = 3;
                else
                    maxPowerState = 1;
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
                service->getName(), service, powerState, maxPowerState,
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
                SUB_ABSOLUTETIME(&now, &systemWakeTime);
                absolutetime_to_nanoseconds(now, &nsec);
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
    // Warning: Not running in PM work loop context - don't modify state !!!
    // Trap tickle directed to IODisplayWrangler while running with graphics
    // capability suppressed.

    assert(service == wrangler);

    if (service == wrangler)
    {
        bool aborting = ((lastSleepReason == kIOPMSleepReasonIdle) 
                       || (lastSleepReason == kIOPMSleepReasonMaintenance));
        if (aborting) {
            userActivityCount++;
            DLOG("display wrangler tickled1 %d lastSleepReason %d\n", userActivityCount, lastSleepReason);
        }
    }

    if (!wranglerTickled &&
        ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0))
    {
        setProperty(kIOPMRootDomainWakeTypeKey, kIOPMRootDomainWakeTypeHIDActivity);
        DLOG("display wrangler tickled\n");
        if (kIOLogPMRootDomain & gIOKitDebug)
            OSReportWithBacktrace("Dark wake display tickle");
        if (pmPowerStateQueue)
        {
            pmPowerStateQueue->submitPowerEvent(
                kPowerEventPolicyStimulus,
                (void *) kStimulusDarkWakeActivityTickle );
        }
    }
}

//******************************************************************************
// Approve usage of delayed child notification by PM.
//******************************************************************************

bool IOPMrootDomain::shouldDelayChildNotification(
    IOService * service )
{
    if (((gDarkWakeFlags & kDarkWakeFlagHIDTickleMask) != 0) &&
        !wranglerTickled &&
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
    IOService *     service,
    IOPMActions *   actions, 
    uint32_t        powerState,
    uint32_t *      inOutChangeFlags )
{
    pmTracer->tracePCIPowerChange(
        PMTraceWorker::kPowerChangeStart,
        service, *inOutChangeFlags,
        (actions->parameter & kPMActionsPCIBitNumberMask));
}

void IOPMrootDomain::handlePowerChangeDoneForPCIDevice(
    IOService *     service,
    IOPMActions *   actions, 
    uint32_t        powerState,
    uint32_t        changeFlags )
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

IONotifier * IOPMrootDomain::registerInterest(
                const OSSymbol * typeOfInterest,
                IOServiceInterestHandler handler,
                void * target, void * ref )
{
    IONotifier *    notifier;
    bool            isSystemCapabilityClient;
    bool            isKernelCapabilityClient;

    isSystemCapabilityClient =
        typeOfInterest &&
        typeOfInterest->isEqualTo(kIOPMSystemCapabilityInterest);

    isKernelCapabilityClient =
        typeOfInterest &&
        typeOfInterest->isEqualTo(gIOPriorityPowerStateInterest);

    if (isSystemCapabilityClient)
        typeOfInterest = gIOAppPowerStateInterest;

    notifier = super::registerInterest(typeOfInterest, handler, target, ref);
    if (notifier && pmPowerStateQueue)
    {
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
            }

            allow = true;
            break;
        }

        // Capability client will always see kIOMessageCanSystemSleep,
        // even for demand sleep.

        if ((kIOMessageCanSystemSleep == context->messageType) ||
            (kIOMessageSystemWillNotSleep == context->messageType))
        {
            if (object == (OSObject *) systemCapabilityNotifier)
            {
                allow = true;
                break;
            }
            
            // Not idle sleep, don't ask apps.
            if (context->changeFlags & kIOPMSkipAskPowerDown)
            {
                break;
            }
        }

        // Reject capability change messages for legacy clients.
        // Reject legacy system sleep messages for capability client.

        if (isCapMsg || (object == (OSObject *) systemCapabilityNotifier))
        {
            break;
        }

        // Filter system sleep messages.

        if ((context->notifyType == kNotifyApps) &&
            (_systemMessageClientMask & kSystemMessageClientApp))
        {
            allow = true;
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
                _joinedCapabilityClients);
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
    IOReturn ret;

    if (!calendar)
        return kIOReturnBadArgument;
    
    data = OSData::withBytesNoCopy((void *) calendar, sizeof(*calendar));
    if (!data)
        return kIOReturnNoMemory;

    if (kPMCalendarTypeMaintenance == calendar->selector) {
        ret = setPMSetting(gIOPMSettingMaintenanceWakeCalendarKey, data);
    } else 
    if (kPMCalendarTypeSleepService == calendar->selector)
    {
        ret = setPMSetting(gIOPMSettingSleepServiceWakeCalendarKey, data);
    }
    

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
    DLOG("DisplayWrangler message 0x%x, power state %d\n",
              (uint32_t) messageType, displayPowerState);

    switch (messageType) {
       case kIOMessageDeviceWillPowerOff:

            // Display wrangler has dropped power due to display idle
            // or force system sleep.
            //
            // 4 Display ON
            // 3 Display Dim
            // 2 Display Sleep
            // 1 Not visible to user
            // 0 Not visible to user

            if (displayPowerState > 2)
                break;

            gRootDomain->evaluatePolicy( kStimulusDisplayWranglerSleep );
            break;

        case kIOMessageDeviceHasPoweredOn:

            // Display wrangler has powered on due to user activity 
            // or wake from sleep.

            if ( 4 != displayPowerState )
                break;

            gRootDomain->evaluatePolicy( kStimulusDisplayWranglerWake );
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
// blockDisplayWranglerTickle
//******************************************************************************

bool IOPMrootDomain::latchDisplayWranglerTickle( bool latch )
{
#if !NO_KERNEL_HID
    if (latch)
    {
        // Not too late to prevent the display from lighting up
        if (!(_currentCapability & kIOPMSystemCapabilityGraphics) &&
            !(_pendingCapability & kIOPMSystemCapabilityGraphics) &&
            !checkSystemCanSustainFullWake())
        {
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
// checkSystemCanSleep
//
//******************************************************************************

bool IOPMrootDomain::checkSystemCanSleep( IOOptionBits options )
{
    int err = 0;

    // Conditions that prevent idle and demand system sleep.

    do {
        if (userDisabledAllSleep)
        {
            err = 1;        // 1. user-space sleep kill switch
            break;
        }

        if (systemBooting || systemShutdown)
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

        if (lowBatteryCondition)
        {
            break;          // always sleep on low battery
        }

        if(darkWakeThermalEmergency)
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

//******************************************************************************
// checkSystemCanSustainFullWake
//******************************************************************************

bool IOPMrootDomain::checkSystemCanSustainFullWake( void )
{
#if !NO_KERNEL_HID
    if (lowBatteryCondition)
    {
        // Low battery wake, or received a low battery notification
        // while system is awake.
        return false;
    }

    if (clamshellExists && clamshellClosed && !acAdaptorConnected)
    {
        // Lid closed on battery power
        return false;
    }
#endif
    return true;
}

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
    DLOG("adjustPowerState ps %u, asap %d, slider %ld\n",
        (uint32_t) getPowerState(), sleepASAP, sleepSlider);

    ASSERT_GATED();

    if ((sleepSlider == 0) || !checkSystemCanSleep())
    {
        changePowerStateToPriv(ON_STATE);
    }
    else if ( sleepASAP )
    {
        changePowerStateToPriv(SLEEP_STATE);
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
        case kPowerEventSuspendClient:
            handleSuspendPMNotificationClient((uintptr_t)arg0, (bool)arg1);
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
        MSG("PowerManagement emergency overtemp signal. Going to sleep!");
        privateSleepSystem (kIOPMSleepReasonThermalEmergency);
    }

    if (msg & kIOPMDWOverTemp)
    {
        if (!CAP_CURRENT(kIOPMSystemCapabilityCPU) ||
            (_systemTransitionType == kSystemTransitionSleep) ||
            (_systemTransitionType == kSystemTransitionWake)  ||
            (_systemTransitionType == kSystemTransitionCapability))
        {
            // During early wake or when system capability is changing,
            // set flag and take action at end of transition.
            darkWakeThermalAlarm = true;
        }
        else if (!wranglerTickled && !darkWakeThermalEmergency &&
                 !CAP_CURRENT(kIOPMSystemCapabilityGraphics))
        {
            // System in steady state and in dark wake
            darkWakeThermalEmergency = true;
            privateSleepSystem(kIOPMSleepReasonDarkWakeThermalEmergency);
            MSG("DarkWake thermal limits breached. Going to sleep!\n");
        }
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
        if( clamshellClosed )
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
        if( clamshellClosed )
        {
            eval_clamshell = true;
        }

        // Lack of AC may have latched a display wrangler tickle.
        // This mirrors the hardware's USB wake event latch, where a latched
        // USB wake event followed by an AC attach will trigger a full wake.
        latchDisplayWranglerTickle( false );

#if HIBERNATION
        // AC presence will reset the standy timer delay adjustment.
        _standbyTimerResetSeconds = 0;
#endif
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
        if( clamshellClosed && (true == clamshellDisabled) )        
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
    if ( eval_clamshell && shouldSleepOnClamshellClosed() ) 
    {


        privateSleepSystem (kIOPMSleepReasonClamshell);
    }
    else if ( eval_clamshell )
    {
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
                wranglerAsleep = true;
                clock_get_uptime(&wranglerSleepTime);
                flags.bit.displaySleep = true;
            }
            break;

        case kStimulusDisplayWranglerWake:
            wranglerAsleep = false;
            flags.bit.idleSleepDisabled = true;
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

            if (0x7fffffff == minutesToIdleSleep)
                minutesToIdleSleep = idleSeconds;

            // How long to wait before sleeping the system once
            // the displays turns off is indicated by 'extraSleepDelay'.

            if ( minutesToIdleSleep > minutesToDisplayDim )
                minutesDelta = minutesToIdleSleep - minutesToDisplayDim;
            else if( minutesToIdleSleep == minutesToDisplayDim )
                minutesDelta = 1;

            if ((sleepSlider == 0) && (minutesToIdleSleep != 0))
                flags.bit.idleSleepEnabled = true;

            if ((sleepSlider != 0) && (minutesToIdleSleep == 0))
                flags.bit.idleSleepDisabled = true;

            if ((minutesDelta != extraSleepDelay) &&
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
        }   break;

        case kStimulusDemandSystemSleep:
            changePowerStateWithOverrideTo( SLEEP_STATE );
            break;

        case kStimulusAllowSystemSleepChanged:
            flags.bit.adjustPowerState = true;
            break;

        case kStimulusDarkWakeActivityTickle:
            if (false == wranglerTickled)
            {
                uint32_t    options = 0;
                IOService * pciRoot = 0;

                if (rejectWranglerTickle)
                {
                    DLOG("rejected tickle, type %u capability %x:%x\n",
                        _systemTransitionType,
                        _currentCapability, _pendingCapability);
                    break;
                }

                if (latchDisplayWranglerTickle(true))
                {
                    DLOG("latched tickle\n");
                    break;
                }

                _desiredCapability |=
                    (kIOPMSystemCapabilityGraphics |
                     kIOPMSystemCapabilityAudio);
                
                if ((kSystemTransitionWake == _systemTransitionType) &&
                    !(_pendingCapability & kIOPMSystemCapabilityGraphics) &&
                    !graphicsSuppressed)
                {
                    DLOG("Promoting to full wake\n");

                    // Elevate to full wake while waking up to dark wake.
                    // PM will hold off notifying the graphics subsystem about
                    // system wake as late as possible, so if a HID event does
                    // arrive, we can turn on graphics on this wake cycle, and
                    // not have to wait till the following cycle. That latency
                    // can be huge on some systems. However, once any graphics
                    // suppression has taken effect, it is too late. All other
                    // graphics devices must be similarly suppressed. But the
                    // delay till the following cycle should be very short.

                    _pendingCapability |=
                        (kIOPMSystemCapabilityGraphics |
                         kIOPMSystemCapabilityAudio);

                    // Immediately bring up audio and graphics.
                    pciRoot = pciHostBridgeDriver;

                    // Notify clients about full wake.
                    _systemMessageClientMask = kSystemMessageClientAll;
                    tellClients(kIOMessageSystemWillPowerOn);
                }

                // Unsafe to cancel once graphics was powered.
                // If system woke from dark wake, the return to sleep can
                // be cancelled. But "awake -> dark -> sleep" transition
                // cannot be cancelled.
                
                if (!CAP_HIGHEST(kIOPMSystemCapabilityGraphics)) {
                    options |= kIOPMSyncCancelPowerDown;                    
                }

                synchronizePowerTree( options, pciRoot );
                wranglerTickled = true;
                // IOGraphics doesn't lit the display even though graphics
                // is enanbled in kIOMessageSystemCapabilityChange message(radar 9502104)
                // So, do an explicit activity tickle
                if(wrangler)
                    wrangler->activityTickle(0,0);

                if (logWranglerTickle)
                {
                    AbsoluteTime    now;
                    uint64_t        nsec;

                    clock_get_uptime(&now);
                    SUB_ABSOLUTETIME(&now, &systemWakeTime);
                    absolutetime_to_nanoseconds(now, &nsec);
                    MSG("HID tickle %u ms\n",
                        ((int)((nsec) / 1000000ULL)));
                    logWranglerTickle = false;
                }
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
                wranglerAsleep = true;
                clock_get_uptime(&wranglerSleepTime);

                // Always accelerate disk spindown while in dark wake,
                // even if system does not support/allow sleep.

                cancelIdleSleepTimer();
                setQuickSpinDownTimeout();
                flags.bit.evaluateDarkWake = true;
            }
            break;

        case kStimulusDarkWakeEvaluate:
            if (systemDarkWake)
            {
                flags.bit.evaluateDarkWake = true;
            }
#if !DARK_TO_FULL_EVALUATE_CLAMSHELL
            else
            {
                // Not through kLocalEvalClamshellCommand to avoid loop.
                if (clamshellClosed && shouldSleepOnClamshellClosed() &&
                    checkSystemCanSleep(true))
                {
                    privateSleepSystem( kIOPMSleepReasonClamshell );
                }
            }
#endif
            break;

        case kStimulusNoIdleSleepPreventers:
            flags.bit.adjustPowerState = true;
            break;

    } /* switch(stimulus) */

    if (flags.bit.evaluateDarkWake && !wranglerTickled)
    {
        if (darkWakeToSleepASAP ||
            (clamshellClosed && !(desktopMode && acAdaptorConnected)))
        {
            // System currently in dark wake, and no children and
            // assertion prevent system sleep.

            if (checkSystemCanSleep(true))
            {
                if (lowBatteryCondition)
                {
                    lastSleepReason = kIOPMSleepReasonLowPower;
                    setProperty(kRootDomainSleepReasonKey, kIOPMLowPowerSleepKey);
                }
                else  if (darkWakeMaintenance)
                {
                    lastSleepReason = kIOPMSleepReasonMaintenance;
                    setProperty(kRootDomainSleepReasonKey, kIOPMMaintenanceSleepKey);
                } 
                else if (darkWakeSleepService)
                {
                    lastSleepReason = kIOPMSleepReasonSleepServiceExit;
                    setProperty(kRootDomainSleepReasonKey, kIOPMSleepServiceExitKey);
                }
                changePowerStateWithOverrideTo( SLEEP_STATE );
            }
            else
            {
                // Parked in dark wake, a tickle will return to full wake
                rejectWranglerTickle = false;
            }
        }
        else // non-maintenance (network) dark wake
        {
            if (checkSystemCanSleep(true))
            {
                // Release power clamp, and wait for children idle.
                adjustPowerState(true);
            }
            else
            {
                changePowerStateToPriv(ON_STATE);
            }
            rejectWranglerTickle = false;
        }
    }

    if (systemDarkWake)
    {
        // The rest are irrelevant while system is in dark wake.
        flags.u32 = 0;
    }

    if (flags.bit.displaySleep || flags.bit.sleepDelayChanged)
    {
        bool cancelQuickSpindown = false;

        if (flags.bit.sleepDelayChanged)
        {
            DLOG("extra sleep timer changed\n");
            cancelIdleSleepTimer();
            cancelQuickSpindown = true;
        }
        else
        {
            DLOG("display sleep\n");        
        }

        if (wranglerAsleep && !wranglerSleepIgnored)
        {
            if ( extraSleepDelay )
            {
                // Start a timer here if the System Sleep timer is greater
                // than the Display Sleep timer.

                startIdleSleepTimer(gRootDomain->extraSleepDelay * 60);            
            }
            else if ( sleepSlider )
            {
                // Accelerate disk spindown if system sleep and display sleep
                // sliders are set to the same value (e.g. both set to 5 min),
                // and display is about to go dark. Check the system sleep is
                // not set to never sleep. Disk sleep setting is ignored.

                setQuickSpinDownTimeout();
                cancelQuickSpindown = false;
            }
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
            if (idleSeconds)
            {
                startIdleSleepTimer( idleSeconds );
            }
        }
        else
        {
            // Start idle sleep timer if wrangler went to sleep
            // while system sleep was disabled. Disk spindown is
            // accelerated upon timer expiration.

            if (wranglerAsleep)
            {
                AbsoluteTime    now;
                uint64_t        nanos;
                uint32_t        minutesSinceDisplaySleep = 0;
                uint32_t        sleepDelay = 0;

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

                startIdleSleepTimer(sleepDelay * 60);
                DLOG("display slept %u min, set idle timer to %u min\n",
                    minutesSinceDisplaySleep, sleepDelay);
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
                if (idleSeconds)
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
        if(sleepASAP)
        {
            lastSleepReason = kIOPMSleepReasonIdle;
            setProperty(kRootDomainSleepReasonKey, kIOPMIdleSleepKey);
        }

        adjustPowerState(sleepASAP);
    }
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

    if (changedBits & kIOPMDriverAssertionCPUBit)
        evaluatePolicy(kStimulusDarkWakeEvaluate);

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

// MARK: -
// MARK: PMTraceWorker

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
            MSG("Sleep failure code 0x%08x 0x%08x\n",
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
    if (systemBooting) return;

    pmTracer->tracePoint(point);

#if	HIBERNATION
    if (kIOPMTracePointSleepPowerPlaneDrivers == point) IOHibernateIOKitSleep();
#endif
}

void IOPMrootDomain::tracePoint( uint8_t point, uint8_t data )
{
    if (!systemBooting)
        pmTracer->tracePoint(point, data);
}

void IOPMrootDomain::traceDetail( uint32_t detail )
{
    if (!systemBooting)
        pmTracer->traceDetail( detail );
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
    me->traceData32 = 0;
    return me;
}

void PMTraceWorker::RTC_TRACE(void)
{
	if (tracePointHandler && tracePointTarget)
	{
		uint32_t    wordA;

        wordA = (tracePhase << 24) | (loginWindowPhase << 16) |
                (traceData8 << 8);

        tracePointHandler( tracePointTarget, traceData32, wordA );
		_LOG("RTC_TRACE wrote 0x%08x 0x%08x\n", traceData32, wordA);
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
        _LOG("PMTrace PCI array: set object %s => %d\n",
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
    // clear trace detail when phase begins
    if (tracePhase != phase)
        traceData32 = 0;

    tracePhase = phase;

    DLOG("trace point 0x%02x\n", tracePhase);
    RTC_TRACE();
}

void PMTraceWorker::tracePoint(uint8_t phase, uint8_t data8)
{
    // clear trace detail when phase begins
    if (tracePhase != phase)
        traceData32 = 0;

    tracePhase = phase;
    traceData8 = data8;

    DLOG("trace point 0x%02x 0x%02x\n", tracePhase, traceData8);
    RTC_TRACE();
}

void PMTraceWorker::traceDetail(uint32_t detail)
{
    if (kIOPMTracePointSleepPriorityClients != tracePhase)
        return;

    traceData32 = detail;
    DLOG("trace point 0x%02x detail 0x%08x\n", tracePhase, traceData32);

    RTC_TRACE();
}

void PMTraceWorker::traceLoginWindowPhase(uint8_t phase)
{
    loginWindowPhase = phase;

    DLOG("loginwindow tracepoint 0x%02x\n", loginWindowPhase);
    RTC_TRACE();
}

void PMTraceWorker::tracePCIPowerChange(
	change_t type, IOService *service, uint32_t changeFlags, uint32_t bitNum)
{
    uint32_t	bitMask;
	uint32_t	expectedFlag;

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
        }
        else
        {
            traceData32 &= ~bitMask;
            _LOG("PMTrace: Device %s finished - bit %2d mask 0x%08x => 0x%08x\n",
                service->getName(), bitNum, bitMask, traceData32);
        }

        RTC_TRACE();
    }
}

// MARK: -
// MARK: PMHaltWorker

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
			(gIOKitDebug & kIOLogPMRootDomain))
		{
			LOG("%s driver %s (%p) took %u ms\n",
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
			MSG("%s still waiting on %s\n",
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

//*********************************************************************************
// Sleep/Wake logging
//
//*********************************************************************************

IOMemoryDescriptor *IOPMrootDomain::getPMTraceMemoryDescriptor(void)
{
    if (timeline)
        return timeline->getPMTraceMemoryDescriptor();
    else
        return NULL;
}

// Forwards external reports of detailed events to IOPMTimeline
IOReturn IOPMrootDomain::recordPMEvent(PMEventDetails *details)
{
    if (timeline && details) {
        
		  IOReturn rc;
		
		  // Record a detailed driver power change event, or... 
		  if(details->eventClassifier == kIOPMEventClassDriverEvent) {
			  rc = timeline->recordDetailedPowerEvent( details );
		  }
		
		  // Record a system power management event
		  else if(details->eventClassifier == kIOPMEventClassSystemEvent) {
			  rc = timeline->recordSystemPowerEvent( details );
		  }
		  else {
			  return kIOReturnBadArgument;
		  }
      
      // If we get to record this message, then we've reached the 
      // end of another successful Sleep --> Wake cycle
      // At this point, we pat ourselves in the back and allow
      // our Sleep --> Wake UUID to be published
      if(details->eventType == kIOPMEventTypeWakeDone) {
        timeline->setSleepCycleInProgressFlag(false);
      }

/*
      // Check if its time to clear the timeline buffer
      if(getProperty(kIOPMSleepWakeUUIDKey) 
         && timeline->isSleepCycleInProgress() == false
         && timeline->getNumEventsLoggedThisPeriod() > 500) {
            
        // Clear the old UUID
        if(pmPowerStateQueue) {
            pmPowerStateQueue->submitPowerEvent(kPowerEventPublishSleepWakeUUID, (void *)false );
        }
      }
*/
      return rc;
    }
    else
        return kIOReturnNotReady;
}

IOReturn IOPMrootDomain::recordAndReleasePMEvent(PMEventDetails *details)
{
    IOReturn ret = kIOReturnBadArgument;

    if (details)
    {
        ret = recordPMEvent(details);
        details->release();
    }

    return ret;
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
// MARK: IOPMTimeline

#undef super
#define super OSObject

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

IOPMTimeline *IOPMTimeline::timeline(IOPMrootDomain *root_domain)
{
    IOPMTimeline    *myself;
    
    if (!root_domain)
        return NULL;
    
    myself = new IOPMTimeline;
 
    if (myself) {
        myself->owner = root_domain;
        myself->init();
    }
 
    return myself;
}

bool IOPMTimeline::init(void)
{
    if (!super::init()) {
        return false;
    }

    logLock = IOLockAlloc();
    
    // Fresh timeline, no events logged yet
    this->numEventsLoggedThisPeriod = 0;
    this->sleepCycleInProgress = false;

    //this->setEventsRecordingLevel(1);   // TODO
    this->setEventsTrackedCount(kIOPMDefaultSystemEventsTracked);

    return true;
}

void IOPMTimeline::free(void)
{
    if (pmTraceMemoryDescriptor) {
        pmTraceMemoryDescriptor->release();
        pmTraceMemoryDescriptor = NULL;
    }
    
    IOLockFree(logLock);

    super::free();
}

IOMemoryDescriptor *IOPMTimeline::getPMTraceMemoryDescriptor()
{
    return pmTraceMemoryDescriptor;
}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

bool IOPMTimeline::setProperties(OSDictionary *d)
{
    OSNumber    *n = NULL;
    OSBoolean   *b = NULL;
    bool        changed = false;

    /* Changes size of detailed events buffer */
    n = (OSNumber *)d->getObject(kIOPMTimelineSystemNumberTrackedKey);
    if (OSDynamicCast(OSNumber, n))
    {
        changed = true;
        this->setEventsTrackedCount(n->unsigned32BitValue());        
    }


    /* enables or disables system events */
    b = (OSBoolean *)d->getObject(kIOPMTimelineEnabledKey);
    if (b)
    {
        changed = true;
        this->setEventsRecordingLevel((int)(kOSBooleanTrue == b));        
    }

    return changed;
}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

OSDictionary *IOPMTimeline::copyInfoDictionary(void)
{
    OSDictionary *out = OSDictionary::withCapacity(3);
    OSNumber    *n = NULL;

    if (!out || !hdr)
        return NULL;

    n = OSNumber::withNumber(hdr->sizeEntries, 32);
    out->setObject(kIOPMTimelineSystemNumberTrackedKey, n);
    n->release();
    
    n = OSNumber::withNumber(hdr->sizeBytes, 32);
    out->setObject(kIOPMTimelineSystemBufferSizeKey, n);
    n->release();

    // bool
    out->setObject(kIOPMTimelineEnabledKey, eventsRecordingLevel ? kOSBooleanTrue : kOSBooleanFalse);

    return out;
}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

/* IOPMTimeline::recordSystemPowerEvent()
 *
 * Expected "type" arguments are listed in IOPMPrivate.h under enum "SystemEventTypes"
 * Type arguments include "system events", and "Intermediate events"
 *
 * - System Events have paired "start" and "stop" events.
 * - A start event shall be followed by a stop event.
 * - Any number of Intermediate Events may fall between the 
 *   start and stop events.
 * - Intermediate events are meaningless outside the bounds of a system event's
 *   start & stoup routines.
 * - It's invalid to record a Start event without a following Stop event; e.g. two
 *   Start events without an intervenining Stop event is invalid.
 *
 * Buffer invariants
 * - The first recorded system event shall be preceded by an entry with type == 0
 * - IOPMTimeline may choose not to record intermediate events while there's not
 *   a system event in process.
 */
IOReturn IOPMTimeline::recordSystemPowerEvent( PMEventDetails *details )
{
    static bool                 wakeDonePending = true;
    IOPMSystemEventRecord       *record_to = NULL;
    OSString                    *swUUIDKey = NULL;
    uint32_t                    useIndex = 0;

    if (!details)
        return kIOReturnBadArgument;

    if (!traceBuffer) 
        return kIOReturnNotReady;
    
    if (details->eventType == kIOPMEventTypeWakeDone)
    {
      if(!wakeDonePending)  
        return kIOReturnBadArgument;
    }

    IOLockLock(logLock);
    
    if (details->eventType == kIOPMEventTypeWake) {
        wakeDonePending = true;
    } else if (details->eventType == kIOPMEventTypeWakeDone) {
        wakeDonePending = false;
    }

    systemState = details->eventType;
   
    useIndex = _atomicIndexIncrement(&hdr->index, hdr->sizeEntries);
    
    // The entry immediately after the latest entry (and thus
    //  immediately before the first entry) shall have a type 0.
    if (useIndex + 1 >= hdr->sizeEntries) {
        traceBuffer[useIndex + 1].eventType = 0;
    } else {
        traceBuffer[0].eventType = 0;
    }
    
    record_to = &traceBuffer[useIndex];
    bzero(record_to, sizeof(IOPMSystemEventRecord));

    /*****/
    record_to->eventType    = details->eventType;
    record_to->eventReason  = details->reason;
    record_to->eventResult  = details->result;
    pmEventTimeStamp(&record_to->timestamp);

    // If caller doesn't provide a UUID, we'll use the UUID that's posted
    // on IOPMrootDomain under key kIOPMSleepWakeUUIDKey
    if (!details->uuid)  {
        swUUIDKey = OSDynamicCast(OSString, owner->copyProperty(kIOPMSleepWakeUUIDKey));

        if (swUUIDKey)
            details->uuid = swUUIDKey->getCStringNoCopy();
    }

    if (details->uuid)
        strncpy(record_to->uuid, details->uuid, kMaxPMStringLength);

    if (swUUIDKey) 
        swUUIDKey->release();

    numEventsLoggedThisPeriod++;
    /*****/

    IOLockUnlock(logLock);
    
    return kIOReturnSuccess;

}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

IOReturn IOPMTimeline::recordDetailedPowerEvent( PMEventDetails *details )
{
    IOPMSystemEventRecord *record_to = NULL;
    uint32_t                useIndex;

    if (!details->eventType || !details->ownerName) 
        return kIOReturnBadArgument;
        
    IOLockLock(logLock);

    useIndex = _atomicIndexIncrement(&hdr->index, hdr->sizeEntries);
    
    record_to = (IOPMSystemEventRecord *)&traceBuffer[useIndex];
    bzero(record_to, sizeof(IOPMSystemEventRecord));

    /*****/
    record_to->eventType = details->eventType;
    if (details->ownerName && (strlen(details->ownerName) > 1)) {
        strlcpy( record_to->ownerName, 
                 details->ownerName, 
                 sizeof(record_to->ownerName));
    }
    
    record_to->ownerDisambiguateID = details->ownerUnique;
    
    if (details->interestName && (strlen(details->interestName) > 1)) {
        strlcpy(record_to->interestName, 
                details->interestName, 
                sizeof(record_to->interestName));
    }

    record_to->oldState      = details->oldState;
    record_to->newState      = details->newState;
    record_to->eventResult   = details->result;
    record_to->elapsedTimeUS = details->elapsedTimeUS;
    pmEventTimeStamp(&record_to->timestamp);

    numEventsLoggedThisPeriod++;
    /*****/

    IOLockUnlock(logLock);
    return kIOReturnSuccess;
}

uint32_t IOPMTimeline::getNumEventsLoggedThisPeriod() {
  return this->numEventsLoggedThisPeriod;
}

void IOPMTimeline::setNumEventsLoggedThisPeriod(uint32_t newCount) {
  this->numEventsLoggedThisPeriod = newCount;
}

bool IOPMTimeline::isSleepCycleInProgress() {
  return this->sleepCycleInProgress;
}

void IOPMTimeline::setSleepCycleInProgressFlag(bool flag) {
  this->sleepCycleInProgress = flag;
}
//*********************************************************************************
//*********************************************************************************
//*********************************************************************************
    
void IOPMTimeline::setEventsTrackedCount(uint32_t newTracked)
{
    size_t      make_buf_size = 0;
    
    make_buf_size = sizeof(IOPMTraceBufferHeader) + (newTracked * sizeof(IOPMSystemEventRecord));

    IOLockLock(logLock);

    if (pmTraceMemoryDescriptor) {
        pmTraceMemoryDescriptor->release();
        pmTraceMemoryDescriptor = NULL;
    }

    hdr = NULL;
    traceBuffer = NULL;

    if (0 == newTracked)
    {
        IOLog("IOPMrootDomain -> erased buffer.\n");
        goto exit;
    }

    pmTraceMemoryDescriptor = IOBufferMemoryDescriptor::withOptions(
                    kIOMemoryKernelUserShared | kIODirectionIn, make_buf_size);

    if (!pmTraceMemoryDescriptor)
    {
        IOLog("IOPMRootDomain -> IOBufferMemoryDescriptor(%d) returns NULL\n", (int)make_buf_size);
        goto exit;
    }    

    pmTraceMemoryDescriptor->prepare(kIODirectionIn);
    
    // Header occupies the first sizeof(IOPMTraceBufferHeader) bytes
    hdr = (IOPMTraceBufferHeader *)pmTraceMemoryDescriptor->getBytesNoCopy();

    // Recorded events occupy the remaining bulk of the buffer
    traceBuffer = (IOPMSystemEventRecord *)((uint8_t *)hdr + sizeof(IOPMTraceBufferHeader));

    bzero(hdr, make_buf_size);

    hdr->sizeBytes = make_buf_size;
    hdr->sizeEntries = newTracked;

    IOLog("IOPMRootDomain -> IOBufferMemoryDescriptor(%d) returns bufferMB with address 0x%08x\n", (int)make_buf_size, (unsigned int)(uintptr_t)traceBuffer);

exit:
    IOLockUnlock(logLock);
}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************

void IOPMTimeline::setEventsRecordingLevel(uint32_t eventsTrackedBits)
{

    // TODO

    return;

}

/* static helper to IOPMTimeline 
 */
uint32_t IOPMTimeline::_atomicIndexIncrement(uint32_t *index, uint32_t limit)
{
    uint32_t    was_index;
    uint32_t    inc_index;
    
    if(!index)
        return NULL;
    
    do {
        was_index = *index;
        inc_index = (was_index+1)%limit;
    } while (!OSCompareAndSwap(was_index, inc_index, index));

    return inc_index;
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

