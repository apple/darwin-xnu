/*
 * Copyright (c) 1998-2020 Apple Inc. All rights reserved.
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

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOCPU.h>
#include <IOKit/IOPlatformActions.h>
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
#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>
#include "IOKitKernelInternal.h"
#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#if __arm64__
#include <arm64/ppl/ppl_hib.h>
#endif /* __arm64__ */
#endif /* HIBERNATION */
#include <console/video_console.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>
#include <os/log.h>
#include <pexpert/protos.h>
#include <AssertMacros.h>

#include <sys/time.h>
#include "IOServicePrivate.h"   // _IOServiceInterestNotifier
#include "IOServicePMPrivate.h"

#include <libkern/zlib.h>
#include <os/cpp_util.h>
#include <libkern/c++/OSBoundedArrayRef.h>

__BEGIN_DECLS
#include <mach/shared_region.h>
#include <kern/clock.h>
__END_DECLS

#if defined(__i386__) || defined(__x86_64__)
__BEGIN_DECLS
#include "IOPMrootDomainInternal.h"
const char *processor_to_datastring(const char *prefix, processor_t target_processor);
__END_DECLS
#endif

#define kIOPMrootDomainClass    "IOPMrootDomain"
#define LOG_PREFIX              "PMRD: "


#define MSG(x...) \
    do { kprintf(LOG_PREFIX x); IOLog(x); } while (false)

#define LOG(x...)    \
    do { kprintf(LOG_PREFIX x); } while (false)

#if DEVELOPMENT || DEBUG
#define DEBUG_LOG(x...) do { \
    if (kIOLogPMRootDomain & gIOKitDebug) \
    kprintf(LOG_PREFIX x); \
    os_log_debug(OS_LOG_DEFAULT, LOG_PREFIX x); \
} while (false)
#else
#define DEBUG_LOG(x...)
#endif

#define DLOG(x...)  do { \
    if (kIOLogPMRootDomain & gIOKitDebug) \
	kprintf(LOG_PREFIX x); \
    else \
	os_log(OS_LOG_DEFAULT, LOG_PREFIX x); \
} while (false)

#define DMSG(x...)  do { \
    if (kIOLogPMRootDomain & gIOKitDebug) { \
	kprintf(LOG_PREFIX x); \
    } \
} while (false)


#define _LOG(x...)

#define CHECK_THREAD_CONTEXT
#ifdef  CHECK_THREAD_CONTEXT
static IOWorkLoop * gIOPMWorkLoop = NULL;
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

#define CAP_PENDING(c)  \
	((_pendingCapability & (c)) != 0)

// rdar://problem/9157444
#if defined(__i386__) || defined(__x86_64__)
#define DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY   20
#endif

// Event types for IOPMPowerStateQueue::submitPowerEvent()
enum {
	kPowerEventFeatureChanged = 1,             // 1
	kPowerEventReceivedPowerNotification,      // 2
	kPowerEventSystemBootCompleted,            // 3
	kPowerEventSystemShutdown,                 // 4
	kPowerEventUserDisabledSleep,              // 5
	kPowerEventRegisterSystemCapabilityClient, // 6
	kPowerEventRegisterKernelCapabilityClient, // 7
	kPowerEventPolicyStimulus,                 // 8
	kPowerEventAssertionCreate,                // 9
	kPowerEventAssertionRelease,               // 10
	kPowerEventAssertionSetLevel,              // 11
	kPowerEventQueueSleepWakeUUID,             // 12
	kPowerEventPublishSleepWakeUUID,           // 13
	kPowerEventSetDisplayPowerOn,              // 14
	kPowerEventPublishWakeType,                // 15
	kPowerEventAOTEvaluate                     // 16
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

// Internal power state change reasons
// Must be less than kIOPMSleepReasonClamshell=101
enum {
	kCPSReasonNone = 0,                 // 0
	kCPSReasonInit,                     // 1
	kCPSReasonWake,                     // 2
	kCPSReasonIdleSleepPrevent,         // 3
	kCPSReasonIdleSleepAllow,           // 4
	kCPSReasonPowerOverride,            // 5
	kCPSReasonPowerDownCancel,          // 6
	kCPSReasonAOTExit,                  // 7
	kCPSReasonAdjustPowerState,         // 8
	kCPSReasonDarkWakeCannotSleep,      // 9
	kCPSReasonIdleSleepEnabled,         // 10
	kCPSReasonEvaluatePolicy,           // 11
	kCPSReasonSustainFullWake,          // 12
	kCPSReasonPMInternals = (kIOPMSleepReasonClamshell - 1)
};

extern "C" {
IOReturn OSKextSystemSleepOrWake( UInt32 );
}
extern "C" ppnum_t      pmap_find_phys(pmap_t pmap, addr64_t va);
extern "C" addr64_t     kvtophys(vm_offset_t va);
extern "C" boolean_t    kdp_has_polled_corefile();

static void idleSleepTimerExpired( thread_call_param_t, thread_call_param_t );
static void notifySystemShutdown( IOService * root, uint32_t messageType );
static void handleAggressivesFunction( thread_call_param_t, thread_call_param_t );
static void pmEventTimeStamp(uint64_t *recordTS);
static void powerButtonUpCallout( thread_call_param_t, thread_call_param_t );
static void powerButtonDownCallout( thread_call_param_t, thread_call_param_t );
static OSPtr<const OSSymbol> copyKextIdentifierWithAddress(vm_address_t address);

static int  IOPMConvertSecondsToCalendar(clock_sec_t secs, IOPMCalendarStruct * dt);
static clock_sec_t IOPMConvertCalendarToSeconds(const IOPMCalendarStruct * dt);
#define YMDTF       "%04d/%02d/%d %02d:%02d:%02d"
#define YMDT(cal)   ((int)(cal)->year), (cal)->month, (cal)->day, (cal)->hour, (cal)->minute, (cal)->second

// "IOPMSetSleepSupported"  callPlatformFunction name
static OSSharedPtr<const OSSymbol>         sleepSupportedPEFunction;
static OSSharedPtr<const OSSymbol>         sleepMessagePEFunction;
static OSSharedPtr<const OSSymbol>         gIOPMWakeTypeUserKey;

static OSSharedPtr<const OSSymbol>         gIOPMPSExternalConnectedKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSExternalChargeCapableKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSBatteryInstalledKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSIsChargingKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAtWarnLevelKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAtCriticalLevelKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSCurrentCapacityKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSMaxCapacityKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSDesignCapacityKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSTimeRemainingKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAmperageKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSVoltageKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSCycleCountKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSMaxErrKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterInfoKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSLocationKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSErrorConditionKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSManufacturerKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSManufactureDateKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSModelKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSSerialKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSLegacyBatteryInfoKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSBatteryHealthKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSHealthConfidenceKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSCapacityEstimatedKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSBatteryChargeStatusKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSBatteryTemperatureKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSChargerConfigurationKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsIDKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsWattsKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsRevisionKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsSerialNumberKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsFamilyKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsAmperageKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsDescriptionKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsPMUConfigurationKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsSourceIDKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsErrorFlagsKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsSharedSourceKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSAdapterDetailsCloakedKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSInvalidWakeSecondsKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSPostChargeWaitSecondsKey;
static OSSharedPtr<const OSSymbol>         gIOPMPSPostDishargeWaitSecondsKey;

#define kIOSleepSupportedKey        "IOSleepSupported"
#define kIOPMSystemCapabilitiesKey  "System Capabilities"
#define kIOPMSystemDefaultOverrideKey   "SystemPowerProfileOverrideDict"

#define kIORequestWranglerIdleKey   "IORequestIdle"
#define kDefaultWranglerIdlePeriod  1000 // in milliseconds

#define kIOSleepWakeFailureString   "SleepWakeFailureString"
#define kIOEFIBootRomFailureKey     "wake-failure"
#define kIOSleepWakeFailurePanic    "SleepWakeFailurePanic"

#define kRD_AllPowerSources (kIOPMSupportedOnAC \
	                   | kIOPMSupportedOnBatt \
	                   | kIOPMSupportedOnUPS)

#define kLocalEvalClamshellCommand  (1 << 15)
#define kIdleSleepRetryInterval     (3 * 60)

#define DISPLAY_WRANGLER_PRESENT    (!NO_KERNEL_HID)

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
	AOT_STATE           = 3,
	ON_STATE            = 4,
	NUM_POWER_STATES
};

const char *
getPowerStateString( uint32_t state )
{
#define POWER_STATE(x) {(uint32_t) x, #x}

	static const IONamedValue powerStates[] = {
		POWER_STATE( OFF_STATE ),
		POWER_STATE( RESTART_STATE ),
		POWER_STATE( SLEEP_STATE ),
		POWER_STATE( AOT_STATE ),
		POWER_STATE( ON_STATE ),
		{ 0, NULL }
	};
	return IOFindNameForValue(state, powerStates);
}

#define ON_POWER        kIOPMPowerOn
#define RESTART_POWER   kIOPMRestart
#define SLEEP_POWER     kIOPMAuxPowerOn

static IOPMPowerState
    ourPowerStates[NUM_POWER_STATES] =
{
	{   .version                = 1,
	    .capabilityFlags        = 0,
	    .outputPowerCharacter   = 0,
	    .inputPowerRequirement  = 0 },
	{   .version                = 1,
	    .capabilityFlags        = kIOPMRestartCapability,
	    .outputPowerCharacter   = kIOPMRestart,
	    .inputPowerRequirement  = RESTART_POWER },
	{   .version                = 1,
	    .capabilityFlags        = kIOPMSleepCapability,
	    .outputPowerCharacter   = kIOPMSleep,
	    .inputPowerRequirement  = SLEEP_POWER },
	{   .version                = 1,
	    .capabilityFlags        = kIOPMAOTCapability,
	    .outputPowerCharacter   = kIOPMAOTPower,
	    .inputPowerRequirement  = ON_POWER },
	{   .version                = 1,
	    .capabilityFlags        = kIOPMPowerOn,
	    .outputPowerCharacter   = kIOPMPowerOn,
	    .inputPowerRequirement  = ON_POWER },
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

// Entitlement required for root domain clients
#define kRootDomainEntitlementSetProperty   "com.apple.private.iokit.rootdomain-set-property"

#define WAKEEVENT_LOCK()        IOLockLock(wakeEventLock)
#define WAKEEVENT_UNLOCK()      IOLockUnlock(wakeEventLock)

/*
 * Aggressiveness
 */
#define AGGRESSIVES_LOCK()      IOLockLock(featuresDictLock)
#define AGGRESSIVES_UNLOCK()    IOLockUnlock(featuresDictLock)

#define kAggressivesMinValue    1

const char *
getAggressivenessTypeString( uint32_t type )
{
#define AGGRESSIVENESS_TYPE(x) {(uint32_t) x, #x}

	static const IONamedValue aggressivenessTypes[] = {
		AGGRESSIVENESS_TYPE( kPMGeneralAggressiveness ),
		AGGRESSIVENESS_TYPE( kPMMinutesToDim ),
		AGGRESSIVENESS_TYPE( kPMMinutesToSpinDown ),
		AGGRESSIVENESS_TYPE( kPMMinutesToSleep ),
		AGGRESSIVENESS_TYPE( kPMEthernetWakeOnLANSettings ),
		AGGRESSIVENESS_TYPE( kPMSetProcessorSpeed ),
		AGGRESSIVENESS_TYPE( kPMPowerSource),
		AGGRESSIVENESS_TYPE( kPMMotionSensor ),
		AGGRESSIVENESS_TYPE( kPMLastAggressivenessType ),
		{ 0, NULL }
	};
	return IOFindNameForValue(type, aggressivenessTypes);
}

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
		OSSharedPtr<IOService> service;
		AggressivesRecord      record;
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

// System Sleep Preventers

enum {
	kPMUserDisabledAllSleep = 1,
	kPMSystemRestartBootingInProgress,
	kPMConfigPreventSystemSleep,
	kPMChildPreventSystemSleep,
	kPMCPUAssertion,
	kPMPCIUnsupported,
};

const char *
getSystemSleepPreventerString( uint32_t preventer )
{
#define SYSTEM_SLEEP_PREVENTER(x) {(int) x, #x}
	static const IONamedValue systemSleepPreventers[] = {
		SYSTEM_SLEEP_PREVENTER( kPMUserDisabledAllSleep ),
		SYSTEM_SLEEP_PREVENTER( kPMSystemRestartBootingInProgress ),
		SYSTEM_SLEEP_PREVENTER( kPMConfigPreventSystemSleep ),
		SYSTEM_SLEEP_PREVENTER( kPMChildPreventSystemSleep ),
		SYSTEM_SLEEP_PREVENTER( kPMCPUAssertion ),
		SYSTEM_SLEEP_PREVENTER( kPMPCIUnsupported ),
		{ 0, NULL }
	};
	return IOFindNameForValue(preventer, systemSleepPreventers);
}

// gDarkWakeFlags
enum {
	kDarkWakeFlagPromotionNone       = 0x0000,
	kDarkWakeFlagPromotionEarly      = 0x0001, // promote before gfx clamp
	kDarkWakeFlagPromotionLate       = 0x0002, // promote after gfx clamp
	kDarkWakeFlagPromotionMask       = 0x0003,
	kDarkWakeFlagAlarmIsDark         = 0x0100,
	kDarkWakeFlagAudioNotSuppressed  = 0x0200,
	kDarkWakeFlagUserWakeWorkaround  = 0x1000
};

// gClamshellFlags
// The workaround for 9157444 is enabled at compile time using the
// DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY macro and is not represented below.
enum {
	kClamshell_WAR_38378787 = 0x00000001,
	kClamshell_WAR_47715679 = 0x00000002,
	kClamshell_WAR_58009435 = 0x00000004
};

// acceptSystemWakeEvents()
enum {
	kAcceptSystemWakeEvents_Disable = 0,
	kAcceptSystemWakeEvents_Enable,
	kAcceptSystemWakeEvents_Reenable
};

static IOPMrootDomain * gRootDomain;
static IORootParent *   gPatriarch;
static IONotifier *     gSysPowerDownNotifier = NULL;
static UInt32           gSleepOrShutdownPending = 0;
static UInt32           gWillShutdown = 0;
static UInt32           gPagingOff = 0;
static UInt32           gSleepWakeUUIDIsSet = false;
static uint32_t         gAggressivesState = 0;
static uint32_t         gHaltTimeMaxLog;
static uint32_t         gHaltTimeMaxPanic;
IOLock *                gHaltLogLock;
static char *           gHaltLog;
enum                  { kHaltLogSize = 2048 };
static size_t           gHaltLogPos;
static uint64_t         gHaltStartTime;
static char             gKextNameBuf[64];
static size_t           gKextNamePos;
static bool             gKextNameEnd;

uuid_string_t bootsessionuuid_string;

#if defined(XNU_TARGET_OS_OSX)
#if DISPLAY_WRANGLER_PRESENT
static uint32_t         gDarkWakeFlags = kDarkWakeFlagPromotionNone;
#elif CONFIG_ARROW
// Enable temporary full wake promotion workarounds
static uint32_t         gDarkWakeFlags = kDarkWakeFlagUserWakeWorkaround;
#else
// Enable full wake promotion workarounds
static uint32_t         gDarkWakeFlags = kDarkWakeFlagUserWakeWorkaround;
#endif
#else  /* !defined(XNU_TARGET_OS_OSX) */
static uint32_t         gDarkWakeFlags = kDarkWakeFlagPromotionEarly;
#endif /* !defined(XNU_TARGET_OS_OSX) */

static uint32_t         gNoIdleFlag = 0;
static uint32_t         gSwdPanic = 1;
static uint32_t         gSwdSleepTimeout = 0;
static uint32_t         gSwdWakeTimeout = 0;
static uint32_t         gSwdSleepWakeTimeout = 0;
static PMStatsStruct    gPMStats;
#if DEVELOPMENT || DEBUG
static uint32_t swd_panic_phase;
#endif

static uint32_t         gClamshellFlags = 0
#if defined(__i386__) || defined(__x86_64__)
    | kClamshell_WAR_58009435
#endif
;

#if HIBERNATION

#if defined(__arm64__)
static IOReturn
defaultSleepPolicyHandler(void *ctx, const IOPMSystemSleepPolicyVariables *vars, IOPMSystemSleepParameters *params)
{
	uint32_t sleepType = kIOPMSleepTypeDeepIdle;

	assert(vars->signature == kIOPMSystemSleepPolicySignature);
	assert(vars->version == kIOPMSystemSleepPolicyVersion);

	// Hibernation enabled and either user forced hibernate or low battery sleep
	if ((vars->hibernateMode & kIOHibernateModeOn) &&
	    ppl_hib_hibernation_supported() &&
	    (((vars->hibernateMode & kIOHibernateModeSleep) == 0) ||
	    (vars->sleepFactors & kIOPMSleepFactorBatteryLow))) {
		sleepType = kIOPMSleepTypeHibernate;
	}
	params->version = kIOPMSystemSleepParametersVersion;
	params->sleepType = sleepType;
	return kIOReturnSuccess;
}
static IOPMSystemSleepPolicyHandler     gSleepPolicyHandler = &defaultSleepPolicyHandler;
#else /* defined(__arm64__) */
static IOPMSystemSleepPolicyHandler     gSleepPolicyHandler = NULL;
#endif /* defined(__arm64__) */

static IOPMSystemSleepPolicyVariables * gSleepPolicyVars = NULL;
static void *                           gSleepPolicyTarget;
#endif

struct timeval gIOLastSleepTime;
struct timeval gIOLastWakeTime;
AbsoluteTime gIOLastWakeAbsTime;
AbsoluteTime gIOLastSleepAbsTime;

struct timeval gIOLastUserSleepTime;

static char gWakeReasonString[128];
static char gBootReasonString[80];
static char gShutdownReasonString[80];
static bool gWakeReasonSysctlRegistered = false;
static bool gBootReasonSysctlRegistered = false;
static bool gShutdownReasonSysctlRegistered = false;
static AbsoluteTime gUserActiveAbsTime;
static AbsoluteTime gUserInactiveAbsTime;

#if defined(__i386__) || defined(__x86_64__) || (defined(__arm64__) && HIBERNATION)
static bool gSpinDumpBufferFull = false;
#endif

z_stream          swd_zs;
vm_offset_t swd_zs_zmem;
//size_t swd_zs_zsize;
size_t swd_zs_zoffset;
#if defined(__i386__) || defined(__x86_64__)
IOCPU *currentShutdownTarget = NULL;
#endif

static unsigned int     gPMHaltBusyCount;
static unsigned int     gPMHaltIdleCount;
static int              gPMHaltDepth;
static uint32_t         gPMHaltMessageType;
static IOLock *         gPMHaltLock  = NULL;
static OSSharedPtr<OSArray>        gPMHaltArray;
static OSSharedPtr<const OSSymbol> gPMHaltClientAcknowledgeKey;
static bool             gPMQuiesced;

// Constants used as arguments to IOPMrootDomain::informCPUStateChange
#define kCPUUnknownIndex    9999999
enum {
	kInformAC = 0,
	kInformLid = 1,
	kInformableCount = 2
};

OSSharedPtr<const OSSymbol> gIOPMStatsResponseTimedOut;
OSSharedPtr<const OSSymbol> gIOPMStatsResponseCancel;
OSSharedPtr<const OSSymbol> gIOPMStatsResponseSlow;
OSSharedPtr<const OSSymbol> gIOPMStatsResponsePrompt;
OSSharedPtr<const OSSymbol> gIOPMStatsDriverPSChangeSlow;

#define kBadPMFeatureID     0

/*
 * PMSettingHandle
 * Opaque handle passed to clients of registerPMSettingController()
 */
class PMSettingHandle : public OSObject
{
	OSDeclareFinalStructors( PMSettingHandle );
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
	OSDeclareFinalStructors( PMSettingObject );
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

	IOReturn dispatchPMSetting(const OSSymbol *type, OSObject *object);
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
	OSDeclareDefaultStructors(PMTraceWorker);
public:
	typedef enum { kPowerChangeStart, kPowerChangeCompleted } change_t;

	static OSPtr<PMTraceWorker> tracer( IOPMrootDomain * );
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
	OSSharedPtr<OSArray>         pciDeviceBitMappings;

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
	OSDeclareFinalStructors(PMAssertionsTracker);
public:
	static PMAssertionsTracker  *pmAssertionsTracker( IOPMrootDomain * );

	IOReturn                    createAssertion(IOPMDriverAssertionType, IOPMDriverAssertionLevel, IOService *, const char *, IOPMDriverAssertionID *);
	IOReturn                    releaseAssertion(IOPMDriverAssertionID);
	IOReturn                    setAssertionLevel(IOPMDriverAssertionID, IOPMDriverAssertionLevel);
	IOReturn                    setUserAssertionLevels(IOPMDriverAssertionType);

	OSSharedPtr<OSArray>        copyAssertionsArray(void);
	IOPMDriverAssertionType     getActivatedAssertions(void);
	IOPMDriverAssertionLevel    getAssertionLevel(IOPMDriverAssertionType);

	IOReturn                    handleCreateAssertion(OSData *);
	IOReturn                    handleReleaseAssertion(IOPMDriverAssertionID);
	IOReturn                    handleSetAssertionLevel(IOPMDriverAssertionID, IOPMDriverAssertionLevel);
	IOReturn                    handleSetUserAssertionLevels(void * arg0);
	void                        publishProperties(void);
	void                        reportCPUBitAccounting(void);

private:
	/*
	 * this should be treated as POD, as it's byte-copied around
	 * and we cannot rely on d'tor firing at the right time
	 */
	typedef struct {
		IOPMDriverAssertionID       id;
		IOPMDriverAssertionType     assertionBits;
		uint64_t                    createdTime;
		uint64_t                    modifiedTime;
		const OSSymbol              *ownerString;
		IOService                   *ownerService;
		uint64_t                    registryEntryID;
		IOPMDriverAssertionLevel    level;
		uint64_t                    assertCPUStartTime;
		uint64_t                    assertCPUDuration;
	} PMAssertStruct;

	uint32_t                    tabulateProducerCount;
	uint32_t                    tabulateConsumerCount;

	uint64_t                    maxAssertCPUDuration;
	uint64_t                    maxAssertCPUEntryId;

	PMAssertStruct              *detailsForID(IOPMDriverAssertionID, int *);
	void                        tabulate(void);
	void                        updateCPUBitAccounting(PMAssertStruct * assertStruct);

	IOPMrootDomain              *owner;
	OSSharedPtr<OSArray>        assertionsArray;
	IOLock                      *assertionsArrayLock;
	IOPMDriverAssertionID       issuingUniqueID __attribute__((aligned(8)));/* aligned for atomic access */
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
	OSDeclareFinalStructors( PMHaltWorker );

public:
	IOService *  service;// service being worked on
	AbsoluteTime startTime; // time when work started
	int          depth;  // work on nubs at this PM-tree depth
	int          visits; // number of nodes visited (debug)
	IOLock *     lock;
	bool         timeout;// service took too long

	static  PMHaltWorker * worker( void );
	static  void main( void * arg, wait_result_t waitResult );
	static  void work( PMHaltWorker * me );
	static  void checkTimeout( PMHaltWorker * me, AbsoluteTime * now );
	virtual void free( void ) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndFinalStructors( PMHaltWorker, OSObject )


#define super IOService
OSDefineMetaClassAndFinalStructors(IOPMrootDomain, IOService)

boolean_t
IOPMRootDomainGetWillShutdown(void)
{
	return gWillShutdown != 0;
}

static void
IOPMRootDomainWillShutdown(void)
{
	if (OSCompareAndSwap(0, 1, &gWillShutdown)) {
		IOService::willShutdown();
		for (int i = 0; i < 100; i++) {
			if (OSCompareAndSwap(0, 1, &gSleepOrShutdownPending)) {
				break;
			}
			IOSleep( 100 );
		}
	}
}

extern "C" IONotifier *
registerSleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref)
{
	return gRootDomain->registerInterest( gIOGeneralInterest, handler, self, ref ).detach();
}

extern "C" IONotifier *
registerPrioritySleepWakeInterest(IOServiceInterestHandler handler, void * self, void * ref)
{
	return gRootDomain->registerInterest( gIOPriorityPowerStateInterest, handler, self, ref ).detach();
}

extern "C" IOReturn
acknowledgeSleepWakeNotification(void * PMrefcon)
{
	return gRootDomain->allowPowerChange((unsigned long)PMrefcon );
}

extern "C" IOReturn
vetoSleepWakeNotification(void * PMrefcon)
{
	return gRootDomain->cancelPowerChange((unsigned long)PMrefcon );
}

extern "C" IOReturn
rootDomainRestart( void )
{
	return gRootDomain->restartSystem();
}

extern "C" IOReturn
rootDomainShutdown( void )
{
	return gRootDomain->shutdownSystem();
}

static void
halt_log_putc(char c)
{
	if (gHaltLogPos >= (kHaltLogSize - 2)) {
		return;
	}
	gHaltLog[gHaltLogPos++] = c;
}

extern "C" void
_doprnt_log(const char     *fmt,
    va_list                 *argp,
    void                    (*putc)(char),
    int                     radix);

static int
halt_log(const char *fmt, ...)
{
	va_list listp;

	va_start(listp, fmt);
	_doprnt_log(fmt, &listp, &halt_log_putc, 16);
	va_end(listp);

	return 0;
}

extern "C" void
halt_log_enter(const char * what, const void * pc, uint64_t time)
{
	uint64_t nano, millis;

	if (!gHaltLog) {
		return;
	}
	absolutetime_to_nanoseconds(time, &nano);
	millis = nano / NSEC_PER_MSEC;
	if (millis < 100) {
		return;
	}

	IOLockLock(gHaltLogLock);
	if (pc) {
		halt_log("%s: %qd ms @ 0x%lx, ", what, millis, VM_KERNEL_UNSLIDE(pc));
		OSKext::printKextsInBacktrace((vm_offset_t *) &pc, 1, &halt_log,
		    OSKext::kPrintKextsLock | OSKext::kPrintKextsUnslide | OSKext::kPrintKextsTerse);
	} else {
		halt_log("%s: %qd ms\n", what, millis);
	}

	gHaltLog[gHaltLogPos] = 0;
	IOLockUnlock(gHaltLogLock);
}

extern  uint32_t                           gFSState;

extern "C" void
IOSystemShutdownNotification(int stage)
{
	uint64_t startTime;

	if (kIOSystemShutdownNotificationStageRootUnmount == stage) {
#if defined(XNU_TARGET_OS_OSX)
		uint64_t nano, millis;
		startTime = mach_absolute_time();
		IOService::getPlatform()->waitQuiet(30 * NSEC_PER_SEC);
		absolutetime_to_nanoseconds(mach_absolute_time() - startTime, &nano);
		millis = nano / NSEC_PER_MSEC;
		if (gHaltTimeMaxLog && (millis >= gHaltTimeMaxLog)) {
			printf("waitQuiet() for unmount %qd ms\n", millis);
		}
#endif /* defined(XNU_TARGET_OS_OSX) */
		return;
	}

	assert(kIOSystemShutdownNotificationStageProcessExit == stage);

	IOLockLock(gHaltLogLock);
	if (!gHaltLog) {
		gHaltLog = IONew(char, kHaltLogSize);
		gHaltStartTime = mach_absolute_time();
		if (gHaltLog) {
			halt_log_putc('\n');
		}
	}
	IOLockUnlock(gHaltLogLock);

	startTime = mach_absolute_time();
	IOPMRootDomainWillShutdown();
	halt_log_enter("IOPMRootDomainWillShutdown", NULL, mach_absolute_time() - startTime);
#if HIBERNATION
	startTime = mach_absolute_time();
	IOHibernateSystemPostWake(true);
	halt_log_enter("IOHibernateSystemPostWake", NULL, mach_absolute_time() - startTime);
#endif
	if (OSCompareAndSwap(0, 1, &gPagingOff)) {
		gRootDomain->handlePlatformHaltRestart(kPEPagingOff);
	}
}


extern "C" int sync_internal(void);

/*
 *  A device is always in the highest power state which satisfies its driver,
 *  its policy-maker, and any power children it has, but within the constraint
 *  of the power state provided by its parent.  The driver expresses its desire by
 *  calling changePowerStateTo(), the policy-maker expresses its desire by calling
 *  changePowerStateToPriv(), and the children express their desires by calling
 *  requestPowerDomainState().
 *
 *  The Root Power Domain owns the policy for idle and demand sleep for the system.
 *  It is a power-managed IOService just like the others in the system.
 *  It implements several power states which map to what we see as Sleep and On.
 *
 *  The sleep policy is as follows:
 *  1. Sleep is prevented if the case is open so that nobody will think the machine
 *  is off and plug/unplug cards.
 *  2. Sleep is prevented if the sleep timeout slider in the prefs panel is zero.
 *  3. System cannot Sleep if some object in the tree is in a power state marked
 *  kIOPMPreventSystemSleep.
 *
 *  These three conditions are enforced using the "driver clamp" by calling
 *  changePowerStateTo(). For example, if the case is opened,
 *  changePowerStateTo(ON_STATE) is called to hold the system on regardless
 *  of the desires of the children of the root or the state of the other clamp.
 *
 *  Demand Sleep is initiated by pressing the front panel power button, closing
 *  the clamshell, or selecting the menu item. In this case the root's parent
 *  actually initiates the power state change so that the root domain has no
 *  choice and does not give applications the opportunity to veto the change.
 *
 *  Idle Sleep occurs if no objects in the tree are in a state marked
 *  kIOPMPreventIdleSleep.  When this is true, the root's children are not holding
 *  the root on, so it sets the "policy-maker clamp" by calling
 *  changePowerStateToPriv(ON_STATE) to hold itself on until the sleep timer expires.
 *  This timer is set for the difference between the sleep timeout slider and the
 *  display dim timeout slider. When the timer expires, it releases its clamp and
 *  now nothing is holding it awake, so it falls asleep.
 *
 *  Demand sleep is prevented when the system is booting.  When preferences are
 *  transmitted by the loginwindow at the end of boot, a flag is cleared,
 *  and this allows subsequent Demand Sleep.
 */

//******************************************************************************

IOPMrootDomain *
IOPMrootDomain::construct( void )
{
	IOPMrootDomain  *root;

	root = new IOPMrootDomain;
	if (root) {
		root->init();
	}

	return root;
}

//******************************************************************************
// updateConsoleUsersCallout
//
//******************************************************************************

static void
updateConsoleUsersCallout(thread_call_param_t p0, thread_call_param_t p1)
{
	IOPMrootDomain * rootDomain = (IOPMrootDomain *) p0;
	rootDomain->updateConsoleUsers();
}

void
IOPMrootDomain::updateConsoleUsers(void)
{
	IOService::updateConsoleUsers(NULL, kIOMessageSystemHasPoweredOn);
	if (tasksSuspended) {
		tasksSuspended = FALSE;
		updateTasksSuspend();
	}
}

void
IOPMrootDomain::updateTasksSuspend(void)
{
	bool newSuspend;

	newSuspend = (tasksSuspended || _aotTasksSuspended);
	if (newSuspend == tasksSuspendState) {
		return;
	}
	tasksSuspendState = newSuspend;
	tasks_system_suspend(newSuspend);
}

//******************************************************************************

static void
disk_sync_callout( thread_call_param_t p0, thread_call_param_t p1 )
{
	IOPMrootDomain * rootDomain = (IOPMrootDomain *) p0;
	uint32_t    notifyRef  = (uint32_t)(uintptr_t) p1;
	uint32_t    powerState = rootDomain->getPowerState();

	DLOG("disk_sync_callout ps=%u\n", powerState);

	if (ON_STATE == powerState) {
		sync_internal();

#if HIBERNATION
		// Block sleep until trim issued on previous wake path is completed.
		IOHibernateSystemPostWake(true);
#endif
	}
#if HIBERNATION
	else {
		IOHibernateSystemPostWake(false);

		rootDomain->sleepWakeDebugSaveSpinDumpFile();
	}
#endif

	rootDomain->allowPowerChange(notifyRef);
	DLOG("disk_sync_callout finish\n");
}

//******************************************************************************
static UInt32
computeDeltaTimeMS( const AbsoluteTime * startTime, AbsoluteTime * elapsedTime )
{
	AbsoluteTime    endTime;
	UInt64          nano = 0;

	clock_get_uptime(&endTime);
	if (CMP_ABSOLUTETIME(&endTime, startTime) <= 0) {
		*elapsedTime = 0;
	} else {
		SUB_ABSOLUTETIME(&endTime, startTime);
		absolutetime_to_nanoseconds(endTime, &nano);
		*elapsedTime = endTime;
	}

	return (UInt32)(nano / NSEC_PER_MSEC);
}

//******************************************************************************

static int
sysctl_sleepwaketime SYSCTL_HANDLER_ARGS
{
	struct timeval *swt = (struct timeval *)arg1;
	struct proc *p = req->p;

	if (p == kernproc) {
		return sysctl_io_opaque(req, swt, sizeof(*swt), NULL);
	} else if (proc_is64bit(p)) {
		struct user64_timeval t = {};
		t.tv_sec = swt->tv_sec;
		t.tv_usec = swt->tv_usec;
		return sysctl_io_opaque(req, &t, sizeof(t), NULL);
	} else {
		struct user32_timeval t = {};
		t.tv_sec = (typeof(t.tv_sec))swt->tv_sec;
		t.tv_usec = swt->tv_usec;
		return sysctl_io_opaque(req, &t, sizeof(t), NULL);
	}
}

static SYSCTL_PROC(_kern, OID_AUTO, sleeptime,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    &gIOLastUserSleepTime, 0, sysctl_sleepwaketime, "S,timeval", "");

static SYSCTL_PROC(_kern, OID_AUTO, waketime,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    &gIOLastWakeTime, 0, sysctl_sleepwaketime, "S,timeval", "");

SYSCTL_QUAD(_kern, OID_AUTO, wake_abs_time, CTLFLAG_RD | CTLFLAG_LOCKED, &gIOLastWakeAbsTime, "");
SYSCTL_QUAD(_kern, OID_AUTO, sleep_abs_time, CTLFLAG_RD | CTLFLAG_LOCKED, &gIOLastSleepAbsTime, "");
SYSCTL_QUAD(_kern, OID_AUTO, useractive_abs_time, CTLFLAG_RD | CTLFLAG_LOCKED, &gUserActiveAbsTime, "");
SYSCTL_QUAD(_kern, OID_AUTO, userinactive_abs_time, CTLFLAG_RD | CTLFLAG_LOCKED, &gUserInactiveAbsTime, "");

static int
sysctl_willshutdown
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, gWillShutdown, sizeof(int), &new_value, &changed);
	if (changed) {
		if (!gWillShutdown && (new_value == 1)) {
			IOPMRootDomainWillShutdown();
		} else {
			error = EINVAL;
		}
	}
	return error;
}

static SYSCTL_PROC(_kern, OID_AUTO, willshutdown,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_willshutdown, "I", "");

extern struct sysctl_oid sysctl__kern_iokittest;
extern struct sysctl_oid sysctl__debug_iokit;

#if defined(XNU_TARGET_OS_OSX)

static int
sysctl_progressmeterenable
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	int new_value, changed;

	error = sysctl_io_number(req, vc_progressmeter_enable, sizeof(int), &new_value, &changed);

	if (changed) {
		vc_enable_progressmeter(new_value);
	}

	return error;
}

static int
sysctl_progressmeter
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	int new_value, changed;

	error = sysctl_io_number(req, vc_progressmeter_value, sizeof(int), &new_value, &changed);

	if (changed) {
		vc_set_progressmeter(new_value);
	}

	return error;
}

static SYSCTL_PROC(_kern, OID_AUTO, progressmeterenable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_progressmeterenable, "I", "");

static SYSCTL_PROC(_kern, OID_AUTO, progressmeter,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_progressmeter, "I", "");

#endif /* defined(XNU_TARGET_OS_OSX) */



static int
sysctl_consoleoptions
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, changed;
	uint32_t new_value;

	error = sysctl_io_number(req, vc_user_options.options, sizeof(uint32_t), &new_value, &changed);

	if (changed) {
		vc_user_options.options = new_value;
	}

	return error;
}

static SYSCTL_PROC(_kern, OID_AUTO, consoleoptions,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_consoleoptions, "I", "");


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
	char wr[sizeof(gWakeReasonString)];

	wr[0] = '\0';
	if (gRootDomain) {
		gRootDomain->copyWakeReasonString(wr, sizeof(wr));
	}

	return sysctl_io_string(req, wr, 0, 0, NULL);
}

SYSCTL_PROC(_kern, OID_AUTO, wakereason,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_wakereason, "A", "wakereason");

SYSCTL_STRING(_kern, OID_AUTO, bootreason,
    CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    gBootReasonString, sizeof(gBootReasonString), "");

static int
sysctl_shutdownreason SYSCTL_HANDLER_ARGS
{
	char sr[sizeof(gShutdownReasonString)];

	sr[0] = '\0';
	if (gRootDomain) {
		gRootDomain->copyShutdownReasonString(sr, sizeof(sr));
	}

	return sysctl_io_string(req, sr, 0, 0, NULL);
}

SYSCTL_PROC(_kern, OID_AUTO, shutdownreason,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_shutdownreason, "A", "shutdownreason");

static int
sysctl_targettype SYSCTL_HANDLER_ARGS
{
	IOService * root;
	OSSharedPtr<OSObject>  obj;
	OSData *    data;
	char        tt[32];

	tt[0] = '\0';
	root = IOService::getServiceRoot();
	if (root && (obj = root->copyProperty(gIODTTargetTypeKey))) {
		if ((data = OSDynamicCast(OSData, obj.get()))) {
			strlcpy(tt, (const char *) data->getBytesNoCopy(), sizeof(tt));
		}
	}
	return sysctl_io_string(req, tt, 0, 0, NULL);
}

SYSCTL_PROC(_hw, OID_AUTO, targettype,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_targettype, "A", "targettype");

static SYSCTL_INT(_debug, OID_AUTO, noidle, CTLFLAG_RW, &gNoIdleFlag, 0, "");
static SYSCTL_INT(_debug, OID_AUTO, swd_sleep_timeout, CTLFLAG_RW, &gSwdSleepTimeout, 0, "");
static SYSCTL_INT(_debug, OID_AUTO, swd_wake_timeout, CTLFLAG_RW, &gSwdWakeTimeout, 0, "");
static SYSCTL_INT(_debug, OID_AUTO, swd_timeout, CTLFLAG_RW, &gSwdSleepWakeTimeout, 0, "");
static SYSCTL_INT(_debug, OID_AUTO, swd_panic, CTLFLAG_RW, &gSwdPanic, 0, "");
#if DEVELOPMENT || DEBUG
static SYSCTL_INT(_debug, OID_AUTO, swd_panic_phase, CTLFLAG_RW, &swd_panic_phase, 0, "");
#if defined(XNU_TARGET_OS_OSX)
static SYSCTL_INT(_debug, OID_AUTO, clamshell, CTLFLAG_RW, &gClamshellFlags, 0, "");
static SYSCTL_INT(_debug, OID_AUTO, darkwake, CTLFLAG_RW, &gDarkWakeFlags, 0, "");
#endif /* defined(XNU_TARGET_OS_OSX) */
#endif /* DEVELOPMENT || DEBUG */

//******************************************************************************
// AOT

static int
sysctl_aotmetrics SYSCTL_HANDLER_ARGS
{
	if (NULL == gRootDomain) {
		return ENOENT;
	}
	if (NULL == gRootDomain->_aotMetrics) {
		return ENOENT;
	}
	return sysctl_io_opaque(req, gRootDomain->_aotMetrics, sizeof(IOPMAOTMetrics), NULL);
}

static SYSCTL_PROC(_kern, OID_AUTO, aotmetrics,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    NULL, 0, sysctl_aotmetrics, "S,IOPMAOTMetrics", "");


static int
update_aotmode(uint32_t mode)
{
	int result;

	if (!gIOPMWorkLoop) {
		return ENOENT;
	}
	result = gIOPMWorkLoop->runActionBlock(^IOReturn (void) {
		unsigned int oldCount;

		if (mode && !gRootDomain->_aotMetrics) {
		        gRootDomain->_aotMetrics = IONewZero(IOPMAOTMetrics, 1);
		        if (!gRootDomain->_aotMetrics) {
		                return ENOMEM;
			}
		}

		oldCount = gRootDomain->idleSleepPreventersCount();
		gRootDomain->_aotMode = (mode & kIOPMAOTModeMask);
		gRootDomain->updatePreventIdleSleepListInternal(NULL, false, oldCount);
		return 0;
	});
	return result;
}

static int
sysctl_aotmodebits
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, changed;
	uint32_t new_value;

	if (NULL == gRootDomain) {
		return ENOENT;
	}
	error = sysctl_io_number(req, gRootDomain->_aotMode, sizeof(uint32_t), &new_value, &changed);
	if (changed && gIOPMWorkLoop) {
		error = update_aotmode(new_value);
	}

	return error;
}

static SYSCTL_PROC(_kern, OID_AUTO, aotmodebits,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_aotmodebits, "I", "");

static int
sysctl_aotmode
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, changed;
	uint32_t new_value;

	if (NULL == gRootDomain) {
		return ENOENT;
	}
	error = sysctl_io_number(req, gRootDomain->_aotMode, sizeof(uint32_t), &new_value, &changed);
	if (changed && gIOPMWorkLoop) {
		if (new_value) {
			new_value = kIOPMAOTModeDefault; // & ~kIOPMAOTModeRespectTimers;
		}
		error = update_aotmode(new_value);
	}

	return error;
}

static SYSCTL_PROC(_kern, OID_AUTO, aotmode,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    NULL, 0, sysctl_aotmode, "I", "");

//******************************************************************************

static OSSharedPtr<const OSSymbol> gIOPMSettingAutoWakeCalendarKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingAutoWakeSecondsKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingAutoPowerCalendarKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingAutoPowerSecondsKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingDebugWakeRelativeKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingDebugPowerRelativeKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingMaintenanceWakeCalendarKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingSleepServiceWakeCalendarKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingSilentRunningKey;
static OSSharedPtr<const OSSymbol> gIOPMUserTriggeredFullWakeKey;
static OSSharedPtr<const OSSymbol> gIOPMUserIsActiveKey;
static OSSharedPtr<const OSSymbol> gIOPMSettingLowLatencyAudioModeKey;

//******************************************************************************
// start
//
//******************************************************************************

#define kRootDomainSettingsCount           20
#define kRootDomainNoPublishSettingsCount  4

bool
IOPMrootDomain::start( IOService * nub )
{
	OSSharedPtr<OSIterator>      psIterator;
	OSSharedPtr<OSDictionary>    tmpDict;

	super::start(nub);

	gRootDomain = this;
	gIOPMSettingAutoWakeCalendarKey = OSSymbol::withCString(kIOPMSettingAutoWakeCalendarKey);
	gIOPMSettingAutoWakeSecondsKey = OSSymbol::withCString(kIOPMSettingAutoWakeSecondsKey);
	gIOPMSettingAutoPowerCalendarKey = OSSymbol::withCString(kIOPMSettingAutoPowerCalendarKey);
	gIOPMSettingAutoPowerSecondsKey = OSSymbol::withCString(kIOPMSettingAutoPowerSecondsKey);
	gIOPMSettingDebugWakeRelativeKey = OSSymbol::withCString(kIOPMSettingDebugWakeRelativeKey);
	gIOPMSettingDebugPowerRelativeKey = OSSymbol::withCString(kIOPMSettingDebugPowerRelativeKey);
	gIOPMSettingMaintenanceWakeCalendarKey = OSSymbol::withCString(kIOPMSettingMaintenanceWakeCalendarKey);
	gIOPMSettingSleepServiceWakeCalendarKey = OSSymbol::withCString(kIOPMSettingSleepServiceWakeCalendarKey);
	gIOPMSettingSilentRunningKey = OSSymbol::withCStringNoCopy(kIOPMSettingSilentRunningKey);
	gIOPMUserTriggeredFullWakeKey = OSSymbol::withCStringNoCopy(kIOPMUserTriggeredFullWakeKey);
	gIOPMUserIsActiveKey = OSSymbol::withCStringNoCopy(kIOPMUserIsActiveKey);
	gIOPMSettingLowLatencyAudioModeKey = OSSymbol::withCStringNoCopy(kIOPMSettingLowLatencyAudioModeKey);

	gIOPMStatsResponseTimedOut = OSSymbol::withCString(kIOPMStatsResponseTimedOut);
	gIOPMStatsResponseCancel = OSSymbol::withCString(kIOPMStatsResponseCancel);
	gIOPMStatsResponseSlow = OSSymbol::withCString(kIOPMStatsResponseSlow);
	gIOPMStatsResponsePrompt = OSSymbol::withCString(kIOPMStatsResponsePrompt);
	gIOPMStatsDriverPSChangeSlow = OSSymbol::withCString(kIOPMStatsDriverPSChangeSlow);

	sleepSupportedPEFunction = OSSymbol::withCString("IOPMSetSleepSupported");
	sleepMessagePEFunction = OSSymbol::withCString("IOPMSystemSleepMessage");
	gIOPMWakeTypeUserKey = OSSymbol::withCStringNoCopy(kIOPMRootDomainWakeTypeUser);

	OSSharedPtr<const OSSymbol> settingsArr[kRootDomainSettingsCount] =
	{
		OSSymbol::withCString(kIOPMSettingSleepOnPowerButtonKey),
		gIOPMSettingAutoWakeSecondsKey,
		gIOPMSettingAutoPowerSecondsKey,
		gIOPMSettingAutoWakeCalendarKey,
		gIOPMSettingAutoPowerCalendarKey,
		gIOPMSettingDebugWakeRelativeKey,
		gIOPMSettingDebugPowerRelativeKey,
		OSSymbol::withCString(kIOPMSettingWakeOnRingKey),
		OSSymbol::withCString(kIOPMSettingRestartOnPowerLossKey),
		OSSymbol::withCString(kIOPMSettingWakeOnClamshellKey),
		OSSymbol::withCString(kIOPMSettingWakeOnACChangeKey),
		OSSymbol::withCString(kIOPMSettingTimeZoneOffsetKey),
		OSSymbol::withCString(kIOPMSettingDisplaySleepUsesDimKey),
		OSSymbol::withCString(kIOPMSettingMobileMotionModuleKey),
		OSSymbol::withCString(kIOPMSettingGraphicsSwitchKey),
		OSSymbol::withCString(kIOPMStateConsoleShutdown),
		OSSymbol::withCString(kIOPMSettingProModeControl),
		OSSymbol::withCString(kIOPMSettingProModeDefer),
		gIOPMSettingSilentRunningKey,
		gIOPMSettingLowLatencyAudioModeKey,
	};

	OSSharedPtr<const OSSymbol> noPublishSettingsArr[kRootDomainNoPublishSettingsCount] =
	{
		OSSymbol::withCString(kIOPMSettingProModeControl),
		OSSymbol::withCString(kIOPMSettingProModeDefer),
		gIOPMSettingSilentRunningKey,
		gIOPMSettingLowLatencyAudioModeKey,
	};

#if DEVELOPMENT || DEBUG
#if defined(XNU_TARGET_OS_OSX)
	PE_parse_boot_argn("darkwake", &gDarkWakeFlags, sizeof(gDarkWakeFlags));
	PE_parse_boot_argn("clamshell", &gClamshellFlags, sizeof(gClamshellFlags));
#endif /* defined(XNU_TARGET_OS_OSX) */
#endif /* DEVELOPMENT || DEBUG */

	PE_parse_boot_argn("noidle", &gNoIdleFlag, sizeof(gNoIdleFlag));
	PE_parse_boot_argn("swd_sleeptimeout", &gSwdSleepTimeout, sizeof(gSwdSleepTimeout));
	PE_parse_boot_argn("swd_waketimeout", &gSwdWakeTimeout, sizeof(gSwdWakeTimeout));
	PE_parse_boot_argn("swd_timeout", &gSwdSleepWakeTimeout, sizeof(gSwdSleepWakeTimeout));
	PE_parse_boot_argn("haltmspanic", &gHaltTimeMaxPanic, sizeof(gHaltTimeMaxPanic));
	PE_parse_boot_argn("haltmslog", &gHaltTimeMaxLog, sizeof(gHaltTimeMaxLog));

	queue_init(&aggressivesQueue);
	aggressivesThreadCall = thread_call_allocate(handleAggressivesFunction, this);
	aggressivesData = OSData::withCapacity(
		sizeof(AggressivesRecord) * (kPMLastAggressivenessType + 4));

	featuresDictLock = IOLockAlloc();
	settingsCtrlLock = IOLockAlloc();
	wakeEventLock = IOLockAlloc();
	gHaltLogLock = IOLockAlloc();
	setPMRootDomain(this);

	extraSleepTimer = thread_call_allocate(
		idleSleepTimerExpired,
		(thread_call_param_t) this);

	powerButtonDown = thread_call_allocate(
		powerButtonDownCallout,
		(thread_call_param_t) this);

	powerButtonUp = thread_call_allocate(
		powerButtonUpCallout,
		(thread_call_param_t) this);

	diskSyncCalloutEntry = thread_call_allocate(
		&disk_sync_callout,
		(thread_call_param_t) this);
	updateConsoleUsersEntry = thread_call_allocate(
		&updateConsoleUsersCallout,
		(thread_call_param_t) this);

#if DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY
	fullWakeThreadCall = thread_call_allocate_with_options(
		OSMemberFunctionCast(thread_call_func_t, this,
		&IOPMrootDomain::fullWakeDelayedWork),
		(thread_call_param_t) this, THREAD_CALL_PRIORITY_KERNEL,
		THREAD_CALL_OPTIONS_ONCE);
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
	clamshellClosed = false;
	clamshellExists = false;
#if DISPLAY_WRANGLER_PRESENT
	clamshellDisabled = true;
#else
	clamshellDisabled = false;
#endif
	clamshellIgnoreClose = false;
	acAdaptorConnected = true;
	clamshellSleepDisableMask = 0;
	gWakeReasonString[0] = '\0';

	// Initialize to user active.
	// Will never transition to user inactive w/o wrangler.
	fullWakeReason = kFullWakeReasonLocalUser;
	userIsActive = userWasActive = true;
	clock_get_uptime(&gUserActiveAbsTime);
	setProperty(gIOPMUserIsActiveKey.get(), kOSBooleanTrue);

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
	assertOnWakeSecs        = -1;// Invalid value to prevent updates

	pmStatsLock = IOLockAlloc();
	idxPMCPUClamshell = kCPUUnknownIndex;
	idxPMCPULimitedPower = kCPUUnknownIndex;

	tmpDict = OSDictionary::withCapacity(1);
	setProperty(kRootDomainSupportedFeatures, tmpDict.get());

	// Set a default "SystemPowerProfileOverrideDict" for platform
	// drivers without any overrides.
	if (!propertyExists(kIOPMSystemDefaultOverrideKey)) {
		tmpDict = OSDictionary::withCapacity(1);
		setProperty(kIOPMSystemDefaultOverrideKey, tmpDict.get());
	}

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
		(const OSObject **)noPublishSettingsArr,
		kRootDomainNoPublishSettingsCount,
		0);

	fPMSettingsDict = OSDictionary::withCapacity(5);
	preventIdleSleepList = OSSet::withCapacity(8);
	preventSystemSleepList = OSSet::withCapacity(2);

	PMinit(); // creates gIOPMWorkLoop
	gIOPMWorkLoop = getIOPMWorkloop();

	// Create IOPMPowerStateQueue used to queue external power
	// events, and to handle those events on the PM work loop.
	pmPowerStateQueue = IOPMPowerStateQueue::PMPowerStateQueue(
		this, OSMemberFunctionCast(IOEventSource::Action, this,
		&IOPMrootDomain::dispatchPowerEvent));
	gIOPMWorkLoop->addEventSource(pmPowerStateQueue);

	_aotMode = 0;
	_aotTimerES = IOTimerEventSource::timerEventSource(this,
	    OSMemberFunctionCast(IOTimerEventSource::Action,
	    this, &IOPMrootDomain::aotEvaluate));
	gIOPMWorkLoop->addEventSource(_aotTimerES.get());

	// create our power parent
	gPatriarch = new IORootParent;
	gPatriarch->init();
	gPatriarch->attach(this);
	gPatriarch->start(this);
	gPatriarch->addPowerChild(this);

	registerPowerDriver(this, ourPowerStates, NUM_POWER_STATES);
	changePowerStateWithTagToPriv(ON_STATE, kCPSReasonInit);

	// install power change handler
	gSysPowerDownNotifier = registerPrioritySleepWakeInterest( &sysPowerDownHandler, this, NULL);

#if DISPLAY_WRANGLER_PRESENT
	wranglerIdleSettings = OSDictionary::withCapacity(1);
	OSSharedPtr<OSNumber> wranglerIdlePeriod = OSNumber::withNumber(kDefaultWranglerIdlePeriod, 32);

	if (wranglerIdleSettings && wranglerIdlePeriod) {
		wranglerIdleSettings->setObject(kIORequestWranglerIdleKey,
		    wranglerIdlePeriod.get());
	}

#endif /* DISPLAY_WRANGLER_PRESENT */

	lowLatencyAudioNotifierDict       = OSDictionary::withCapacity(2);
	lowLatencyAudioNotifyStateSym     = OSSymbol::withCString("LowLatencyAudioNotifyState");
	lowLatencyAudioNotifyTimestampSym = OSSymbol::withCString("LowLatencyAudioNotifyTimestamp");
	lowLatencyAudioNotifyStateVal     = OSNumber::withNumber(0ull, 32);
	lowLatencyAudioNotifyTimestampVal = OSNumber::withNumber(0ull, 64);

	if (lowLatencyAudioNotifierDict && lowLatencyAudioNotifyStateSym && lowLatencyAudioNotifyTimestampSym &&
	    lowLatencyAudioNotifyStateVal && lowLatencyAudioNotifyTimestampVal) {
		lowLatencyAudioNotifierDict->setObject(lowLatencyAudioNotifyStateSym.get(), lowLatencyAudioNotifyStateVal.get());
		lowLatencyAudioNotifierDict->setObject(lowLatencyAudioNotifyTimestampSym.get(), lowLatencyAudioNotifyTimestampVal.get());
	}

	OSSharedPtr<const OSSymbol> ucClassName = OSSymbol::withCStringNoCopy("RootDomainUserClient");
	setProperty(gIOUserClientClassKey, const_cast<OSObject *>(static_cast<const OSObject *>(ucClassName.get())));

	// IOBacklightDisplay can take a long time to load at boot, or it may
	// not load at all if you're booting with clamshell closed. We publish
	// 'DisplayDims' here redundantly to get it published early and at all.
	OSSharedPtr<OSDictionary> matching;
	matching = serviceMatching("IOPMPowerSource");
	psIterator = getMatchingServices(matching.get());

	if (psIterator && psIterator->getNextObject()) {
		// There's at least one battery on the system, so we publish
		// 'DisplayDims' support for the LCD.
		publishFeature("DisplayDims");
	}

	// read swd_panic boot-arg
	PE_parse_boot_argn("swd_panic", &gSwdPanic, sizeof(gSwdPanic));
	sysctl_register_oid(&sysctl__kern_sleeptime);
	sysctl_register_oid(&sysctl__kern_waketime);
	sysctl_register_oid(&sysctl__kern_willshutdown);
	sysctl_register_oid(&sysctl__kern_iokittest);
	sysctl_register_oid(&sysctl__debug_iokit);
	sysctl_register_oid(&sysctl__hw_targettype);

#if defined(XNU_TARGET_OS_OSX)
	sysctl_register_oid(&sysctl__kern_progressmeterenable);
	sysctl_register_oid(&sysctl__kern_progressmeter);
	sysctl_register_oid(&sysctl__kern_wakereason);
#endif /* defined(XNU_TARGET_OS_OSX) */
	sysctl_register_oid(&sysctl__kern_consoleoptions);
	sysctl_register_oid(&sysctl__kern_progressoptions);

	sysctl_register_oid(&sysctl__kern_aotmode);
	sysctl_register_oid(&sysctl__kern_aotmodebits);
	sysctl_register_oid(&sysctl__kern_aotmetrics);

#if HIBERNATION
#if defined(__arm64__)
	if (ppl_hib_hibernation_supported()) {
		publishFeature(kIOHibernateFeatureKey);
	}
#endif /* defined(__arm64__) */
	IOHibernateSystemInit(this);
#endif

	registerService();                  // let clients find us

	return true;
}

//******************************************************************************
// setProperties
//
// Receive a setProperty call
// The "System Boot" property means the system is completely booted.
//******************************************************************************

IOReturn
IOPMrootDomain::setProperties( OSObject * props_obj )
{
	IOReturn        return_value = kIOReturnSuccess;
	OSDictionary    *dict = OSDynamicCast(OSDictionary, props_obj);
	OSBoolean       *b = NULL;
	OSNumber        *n = NULL;
	const OSSymbol  *key = NULL;
	OSObject        *obj = NULL;
	OSSharedPtr<OSCollectionIterator> iter;

	if (!dict) {
		return kIOReturnBadArgument;
	}

	bool clientEntitled = false;
	{
		OSSharedPtr<OSObject> obj = IOUserClient::copyClientEntitlement(current_task(), kRootDomainEntitlementSetProperty);
		clientEntitled = (obj == kOSBooleanTrue);
	}

	if (!clientEntitled) {
		const char * errorSuffix = NULL;

		// IOPMSchedulePowerEvent() clients may not be entitled, but must be root.
		// That API can set 6 possible keys that are checked below.
		if ((dict->getCount() == 1) &&
		    (dict->getObject(gIOPMSettingAutoWakeSecondsKey.get()) ||
		    dict->getObject(gIOPMSettingAutoPowerSecondsKey.get()) ||
		    dict->getObject(gIOPMSettingAutoWakeCalendarKey.get()) ||
		    dict->getObject(gIOPMSettingAutoPowerCalendarKey.get()) ||
		    dict->getObject(gIOPMSettingDebugWakeRelativeKey.get()) ||
		    dict->getObject(gIOPMSettingDebugPowerRelativeKey.get()))) {
			return_value = IOUserClient::clientHasPrivilege(current_task(), kIOClientPrivilegeAdministrator);
			if (return_value != kIOReturnSuccess) {
				errorSuffix = "privileged";
			}
		} else {
			return_value = kIOReturnNotPermitted;
			errorSuffix = "entitled";
		}

		if (return_value != kIOReturnSuccess) {
			OSSharedPtr<OSString> procName(IOCopyLogNameForPID(proc_selfpid()), OSNoRetain);
			DLOG("%s failed, process %s is not %s\n", __func__,
			    procName ? procName->getCStringNoCopy() : "", errorSuffix);
			return return_value;
		}
	}

	OSSharedPtr<const OSSymbol> publish_simulated_battery_string    = OSSymbol::withCString("SoftwareSimulatedBatteries");
	OSSharedPtr<const OSSymbol> boot_complete_string                = OSSymbol::withCString("System Boot Complete");
	OSSharedPtr<const OSSymbol> sys_shutdown_string                 = OSSymbol::withCString("System Shutdown");
	OSSharedPtr<const OSSymbol> stall_halt_string                   = OSSymbol::withCString("StallSystemAtHalt");
	OSSharedPtr<const OSSymbol> battery_warning_disabled_string     = OSSymbol::withCString("BatteryWarningsDisabled");
	OSSharedPtr<const OSSymbol> idle_seconds_string                 = OSSymbol::withCString("System Idle Seconds");
	OSSharedPtr<const OSSymbol> sleepdisabled_string                = OSSymbol::withCString("SleepDisabled");
	OSSharedPtr<const OSSymbol> ondeck_sleepwake_uuid_string        = OSSymbol::withCString(kIOPMSleepWakeUUIDKey);
	OSSharedPtr<const OSSymbol> loginwindow_progress_string         = OSSymbol::withCString(kIOPMLoginWindowProgressKey);
	OSSharedPtr<const OSSymbol> coredisplay_progress_string         = OSSymbol::withCString(kIOPMCoreDisplayProgressKey);
	OSSharedPtr<const OSSymbol> coregraphics_progress_string        = OSSymbol::withCString(kIOPMCoreGraphicsProgressKey);
#if DEBUG || DEVELOPMENT
	OSSharedPtr<const OSSymbol> clamshell_close_string              = OSSymbol::withCString("IOPMTestClamshellClose");
	OSSharedPtr<const OSSymbol> clamshell_open_string               = OSSymbol::withCString("IOPMTestClamshellOpen");
	OSSharedPtr<const OSSymbol> ac_detach_string                    = OSSymbol::withCString("IOPMTestACDetach");
	OSSharedPtr<const OSSymbol> ac_attach_string                    = OSSymbol::withCString("IOPMTestACAttach");
	OSSharedPtr<const OSSymbol> desktopmode_set_string              = OSSymbol::withCString("IOPMTestDesktopModeSet");
	OSSharedPtr<const OSSymbol> desktopmode_remove_string           = OSSymbol::withCString("IOPMTestDesktopModeRemove");
#endif

#if HIBERNATION
	OSSharedPtr<const OSSymbol> hibernatemode_string                = OSSymbol::withCString(kIOHibernateModeKey);
	OSSharedPtr<const OSSymbol> hibernatefile_string                = OSSymbol::withCString(kIOHibernateFileKey);
	OSSharedPtr<const OSSymbol> hibernatefilemin_string             = OSSymbol::withCString(kIOHibernateFileMinSizeKey);
	OSSharedPtr<const OSSymbol> hibernatefilemax_string             = OSSymbol::withCString(kIOHibernateFileMaxSizeKey);
	OSSharedPtr<const OSSymbol> hibernatefreeratio_string           = OSSymbol::withCString(kIOHibernateFreeRatioKey);
	OSSharedPtr<const OSSymbol> hibernatefreetime_string            = OSSymbol::withCString(kIOHibernateFreeTimeKey);
#endif

	iter = OSCollectionIterator::withCollection(dict);
	if (!iter) {
		return_value = kIOReturnNoMemory;
		goto exit;
	}

	while ((key = (const OSSymbol *) iter->getNextObject()) &&
	    (obj = dict->getObject(key))) {
		if (key->isEqualTo(publish_simulated_battery_string.get())) {
			if (OSDynamicCast(OSBoolean, obj)) {
				publishResource(key, kOSBooleanTrue);
			}
		} else if (key->isEqualTo(idle_seconds_string.get())) {
			if ((n = OSDynamicCast(OSNumber, obj))) {
				setProperty(key, n);
				idleSeconds = n->unsigned32BitValue();
			}
		} else if (key->isEqualTo(boot_complete_string.get())) {
			pmPowerStateQueue->submitPowerEvent(kPowerEventSystemBootCompleted);
		} else if (key->isEqualTo(sys_shutdown_string.get())) {
			if ((b = OSDynamicCast(OSBoolean, obj))) {
				pmPowerStateQueue->submitPowerEvent(kPowerEventSystemShutdown, (void *) b);
			}
		} else if (key->isEqualTo(battery_warning_disabled_string.get())) {
			setProperty(key, obj);
		}
#if HIBERNATION
		else if (key->isEqualTo(hibernatemode_string.get()) ||
		    key->isEqualTo(hibernatefilemin_string.get()) ||
		    key->isEqualTo(hibernatefilemax_string.get()) ||
		    key->isEqualTo(hibernatefreeratio_string.get()) ||
		    key->isEqualTo(hibernatefreetime_string.get())) {
			if ((n = OSDynamicCast(OSNumber, obj))) {
				setProperty(key, n);
			}
		} else if (key->isEqualTo(hibernatefile_string.get())) {
			OSString * str = OSDynamicCast(OSString, obj);
			if (str) {
				setProperty(key, str);
			}
		}
#endif
		else if (key->isEqualTo(sleepdisabled_string.get())) {
			if ((b = OSDynamicCast(OSBoolean, obj))) {
				setProperty(key, b);
				pmPowerStateQueue->submitPowerEvent(kPowerEventUserDisabledSleep, (void *) b);
			}
		} else if (key->isEqualTo(ondeck_sleepwake_uuid_string.get())) {
			obj->retain();
			pmPowerStateQueue->submitPowerEvent(kPowerEventQueueSleepWakeUUID, (void *)obj);
		} else if (key->isEqualTo(loginwindow_progress_string.get())) {
			if (pmTracer && (n = OSDynamicCast(OSNumber, obj))) {
				uint32_t data = n->unsigned32BitValue();
				pmTracer->traceComponentWakeProgress(kIOPMLoginWindowProgress, data);
				kdebugTrace(kPMLogComponentWakeProgress, 0, kIOPMLoginWindowProgress, data);
			}
		} else if (key->isEqualTo(coredisplay_progress_string.get())) {
			if (pmTracer && (n = OSDynamicCast(OSNumber, obj))) {
				uint32_t data = n->unsigned32BitValue();
				pmTracer->traceComponentWakeProgress(kIOPMCoreDisplayProgress, data);
				kdebugTrace(kPMLogComponentWakeProgress, 0, kIOPMCoreDisplayProgress, data);
			}
		} else if (key->isEqualTo(coregraphics_progress_string.get())) {
			if (pmTracer && (n = OSDynamicCast(OSNumber, obj))) {
				uint32_t data = n->unsigned32BitValue();
				pmTracer->traceComponentWakeProgress(kIOPMCoreGraphicsProgress, data);
				kdebugTrace(kPMLogComponentWakeProgress, 0, kIOPMCoreGraphicsProgress, data);
			}
		} else if (key->isEqualTo(kIOPMDeepSleepEnabledKey) ||
		    key->isEqualTo(kIOPMDestroyFVKeyOnStandbyKey) ||
		    key->isEqualTo(kIOPMAutoPowerOffEnabledKey) ||
		    key->isEqualTo(stall_halt_string.get())) {
			if ((b = OSDynamicCast(OSBoolean, obj))) {
				setProperty(key, b);
			}
		} else if (key->isEqualTo(kIOPMDeepSleepDelayKey) ||
		    key->isEqualTo(kIOPMDeepSleepTimerKey) ||
		    key->isEqualTo(kIOPMAutoPowerOffDelayKey) ||
		    key->isEqualTo(kIOPMAutoPowerOffTimerKey)) {
			if ((n = OSDynamicCast(OSNumber, obj))) {
				setProperty(key, n);
			}
		} else if (key->isEqualTo(kIOPMUserWakeAlarmScheduledKey)) {
			if (kOSBooleanTrue == obj) {
				OSBitOrAtomic(kIOPMAlarmBitCalendarWake, &_userScheduledAlarmMask);
			} else {
				OSBitAndAtomic(~kIOPMAlarmBitCalendarWake, &_userScheduledAlarmMask);
			}
			DLOG("_userScheduledAlarmMask 0x%x\n", (uint32_t) _userScheduledAlarmMask);
		}
#if DEBUG || DEVELOPMENT
		else if (key->isEqualTo(clamshell_close_string.get())) {
			DLOG("SetProperties: setting clamshell close\n");
			UInt32 msg = kIOPMClamshellClosed;
			pmPowerStateQueue->submitPowerEvent(kPowerEventReceivedPowerNotification, (void *)(uintptr_t)msg);
		} else if (key->isEqualTo(clamshell_open_string.get())) {
			DLOG("SetProperties: setting clamshell open\n");
			UInt32 msg = kIOPMClamshellOpened;
			pmPowerStateQueue->submitPowerEvent(kPowerEventReceivedPowerNotification, (void *)(uintptr_t)msg);
		} else if (key->isEqualTo(ac_detach_string.get())) {
			DLOG("SetProperties: setting ac detach\n");
			UInt32 msg = kIOPMSetACAdaptorConnected;
			pmPowerStateQueue->submitPowerEvent(kPowerEventReceivedPowerNotification, (void *)(uintptr_t)msg);
		} else if (key->isEqualTo(ac_attach_string.get())) {
			DLOG("SetProperties: setting ac attach\n");
			UInt32 msg = kIOPMSetACAdaptorConnected | kIOPMSetValue;
			pmPowerStateQueue->submitPowerEvent(kPowerEventReceivedPowerNotification, (void *)(uintptr_t)msg);
		} else if (key->isEqualTo(desktopmode_set_string.get())) {
			DLOG("SetProperties: setting desktopmode");
			UInt32 msg = kIOPMSetDesktopMode | kIOPMSetValue;
			pmPowerStateQueue->submitPowerEvent(kPowerEventReceivedPowerNotification, (void *)(uintptr_t)msg);
		} else if (key->isEqualTo(desktopmode_remove_string.get())) {
			DLOG("SetProperties: removing desktopmode\n");
			UInt32 msg = kIOPMSetDesktopMode;
			pmPowerStateQueue->submitPowerEvent(kPowerEventReceivedPowerNotification, (void *)(uintptr_t)msg);
		}
#endif
		// Relay our allowed PM settings onto our registered PM clients
		else if ((allowedPMSettings->getNextIndexOfObject(key, 0) != (unsigned int) -1)) {
			return_value = setPMSetting(key, obj);
			if (kIOReturnSuccess != return_value) {
				break;
			}
		} else {
			DLOG("setProperties(%s) not handled\n", key->getCStringNoCopy());
		}
	}

exit:
	return return_value;
}

// MARK: -
// MARK: Aggressiveness

//******************************************************************************
// setAggressiveness
//
// Override IOService::setAggressiveness()
//******************************************************************************

IOReturn
IOPMrootDomain::setAggressiveness(
	unsigned long   type,
	unsigned long   value )
{
	return setAggressiveness( type, value, 0 );
}

/*
 * Private setAggressiveness() with an internal options argument.
 */
IOReturn
IOPMrootDomain::setAggressiveness(
	unsigned long   type,
	unsigned long   value,
	IOOptionBits    options )
{
	AggressivesRequest *    entry;
	AggressivesRequest *    request;
	bool                    found = false;

	if ((type > UINT_MAX) || (value > UINT_MAX)) {
		return kIOReturnBadArgument;
	}

	if (type == kPMMinutesToDim || type == kPMMinutesToSleep) {
		DLOG("setAggressiveness(%x) %s = %u\n",
		    (uint32_t) options, getAggressivenessTypeString((uint32_t) type), (uint32_t) value);
	} else {
		DEBUG_LOG("setAggressiveness(%x) %s = %u\n",
		    (uint32_t) options, getAggressivenessTypeString((uint32_t) type), (uint32_t) value);
	}

	request = IONew(AggressivesRequest, 1);
	if (!request) {
		return kIOReturnNoMemory;
	}

	memset(request, 0, sizeof(*request));
	request->options  = options;
	request->dataType = kAggressivesRequestTypeRecord;
	request->data.record.type  = (uint32_t) type;
	request->data.record.value = (uint32_t) value;

	AGGRESSIVES_LOCK();

	// Update disk quick spindown flag used by getAggressiveness().
	// Never merge requests with quick spindown flags set.

	if (options & kAggressivesOptionQuickSpindownEnable) {
		gAggressivesState |= kAggressivesStateQuickSpindown;
	} else if (options & kAggressivesOptionQuickSpindownDisable) {
		gAggressivesState &= ~kAggressivesStateQuickSpindown;
	} else {
		// Coalesce requests with identical aggressives types.
		// Deal with callers that calls us too "aggressively".

		queue_iterate(&aggressivesQueue, entry, AggressivesRequest *, chain)
		{
			if ((entry->dataType == kAggressivesRequestTypeRecord) &&
			    (entry->data.record.type == type) &&
			    ((entry->options & kAggressivesOptionQuickSpindownMask) == 0)) {
				entry->data.record.value = (uint32_t) value;
				found = true;
				break;
			}
		}
	}

	if (!found) {
		queue_enter(&aggressivesQueue, request, AggressivesRequest *, chain);
	}

	AGGRESSIVES_UNLOCK();

	if (found) {
		IODelete(request, AggressivesRequest, 1);
	}

	if (options & kAggressivesOptionSynchronous) {
		handleAggressivesRequests(); // not truly synchronous
	} else {
		thread_call_enter(aggressivesThreadCall);
	}

	return kIOReturnSuccess;
}

//******************************************************************************
// getAggressiveness
//
// Override IOService::setAggressiveness()
// Fetch the aggressiveness factor with the given type.
//******************************************************************************

IOReturn
IOPMrootDomain::getAggressiveness(
	unsigned long   type,
	unsigned long * outLevel )
{
	uint32_t    value  = 0;
	int         source = 0;

	if (!outLevel || (type > UINT_MAX)) {
		return kIOReturnBadArgument;
	}

	AGGRESSIVES_LOCK();

	// Disk quick spindown in effect, report value = 1

	if ((gAggressivesState & kAggressivesStateQuickSpindown) &&
	    (type == kPMMinutesToSpinDown)) {
		value  = kAggressivesMinValue;
		source = 1;
	}

	// Consult the pending request queue.

	if (!source) {
		AggressivesRequest * entry;

		queue_iterate(&aggressivesQueue, entry, AggressivesRequest *, chain)
		{
			if ((entry->dataType == kAggressivesRequestTypeRecord) &&
			    (entry->data.record.type == type) &&
			    ((entry->options & kAggressivesOptionQuickSpindownMask) == 0)) {
				value  = entry->data.record.value;
				source = 2;
				break;
			}
		}
	}

	// Consult the backend records.

	if (!source && aggressivesData) {
		AggressivesRecord * record;
		int                 i, count;

		count  = aggressivesData->getLength() / sizeof(AggressivesRecord);
		record = (AggressivesRecord *) aggressivesData->getBytesNoCopy();

		for (i = 0; i < count; i++, record++) {
			if (record->type == type) {
				value  = record->value;
				source = 3;
				break;
			}
		}
	}

	AGGRESSIVES_UNLOCK();

	if (source) {
		*outLevel = (unsigned long) value;
		return kIOReturnSuccess;
	} else {
		DLOG("getAggressiveness type 0x%x not found\n", (uint32_t) type);
		*outLevel = 0; // default return = 0, driver may not check for error
		return kIOReturnInvalid;
	}
}

//******************************************************************************
// joinAggressiveness
//
// Request from IOService to join future aggressiveness broadcasts.
//******************************************************************************

IOReturn
IOPMrootDomain::joinAggressiveness(
	IOService * service )
{
	AggressivesRequest *    request;

	if (!service || (service == this)) {
		return kIOReturnBadArgument;
	}

	DEBUG_LOG("joinAggressiveness %s %p\n", service->getName(), OBFUSCATE(service));

	request = IONew(AggressivesRequest, 1);
	if (!request) {
		return kIOReturnNoMemory;
	}

	memset(request, 0, sizeof(*request));
	request->dataType = kAggressivesRequestTypeService;
	request->data.service.reset(service, OSRetain); // released by synchronizeAggressives()

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
	if (param1) {
		((IOPMrootDomain *) param1)->handleAggressivesRequests();
	}
}

void
IOPMrootDomain::handleAggressivesRequests( void )
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
	    queue_empty(&aggressivesQueue)) {
		goto unlock_done;
	}

	gAggressivesState |= kAggressivesStateBusy;
	count = aggressivesData->getLength() / sizeof(AggressivesRecord);
	start = (AggressivesRecord *) aggressivesData->getBytesNoCopy();

	do{
		broadcast = false;
		queue_init(&joinedQueue);

		do{
			// Remove request from the incoming queue in FIFO order.
			queue_remove_first(&aggressivesQueue, request, AggressivesRequest *, chain);
			switch (request->dataType) {
			case kAggressivesRequestTypeRecord:
				// Update existing record if found.
				found = false;
				for (i = 0, record = start; i < count; i++, record++) {
					if (record->type == request->data.record.type) {
						found = true;

						if (request->options & kAggressivesOptionQuickSpindownEnable) {
							if ((record->flags & kAggressivesRecordFlagMinValue) == 0) {
								broadcast = true;
								record->flags |= (kAggressivesRecordFlagMinValue |
								    kAggressivesRecordFlagModified);
								DLOG("disk spindown accelerated, was %u min\n",
								    record->value);
							}
						} else if (request->options & kAggressivesOptionQuickSpindownDisable) {
							if (record->flags & kAggressivesRecordFlagMinValue) {
								broadcast = true;
								record->flags |= kAggressivesRecordFlagModified;
								record->flags &= ~kAggressivesRecordFlagMinValue;
								DLOG("disk spindown restored to %u min\n",
								    record->value);
							}
						} else if (record->value != request->data.record.value) {
							record->value = request->data.record.value;
							if ((record->flags & kAggressivesRecordFlagMinValue) == 0) {
								broadcast = true;
								record->flags |= kAggressivesRecordFlagModified;
							}
						}
						break;
					}
				}

				// No matching record, append a new record.
				if (!found &&
				    ((request->options & kAggressivesOptionQuickSpindownDisable) == 0)) {
					AggressivesRecord   newRecord;

					newRecord.flags = kAggressivesRecordFlagModified;
					newRecord.type  = request->data.record.type;
					newRecord.value = request->data.record.value;
					if (request->options & kAggressivesOptionQuickSpindownEnable) {
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
		if (!queue_empty(&joinedQueue) || broadcast) {
			AGGRESSIVES_UNLOCK();
			if (!queue_empty(&joinedQueue)) {
				synchronizeAggressives(&joinedQueue, start, count);
			}
			if (broadcast) {
				broadcastAggressives(start, count);
			}
			AGGRESSIVES_LOCK();
		}

		// Remove the modified flag from all records.
		for (i = 0, record = start; i < count; i++, record++) {
			if ((record->flags & kAggressivesRecordFlagModified) &&
			    ((record->type == kPMMinutesToDim) ||
			    (record->type == kPMMinutesToSleep))) {
				pingSelf = true;
			}

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

void
IOPMrootDomain::synchronizeAggressives(
	queue_head_t *              joinedQueue,
	const AggressivesRecord *   array,
	int                         count )
{
	OSSharedPtr<IOService>      service;
	AggressivesRequest *        request;
	const AggressivesRecord *   record;
	IOPMDriverCallEntry         callEntry;
	uint32_t                    value;
	int                         i;

	while (!queue_empty(joinedQueue)) {
		queue_remove_first(joinedQueue, request, AggressivesRequest *, chain);
		if (request->dataType == kAggressivesRequestTypeService) {
			// retained by joinAggressiveness(), so take ownership
			service = os::move(request->data.service);
		} else {
			service.reset();
		}

		IODelete(request, AggressivesRequest, 1);
		request = NULL;

		if (service) {
			if (service->assertPMDriverCall(&callEntry, kIOPMDriverCallMethodSetAggressive)) {
				for (i = 0, record = array; i < count; i++, record++) {
					value = record->value;
					if (record->flags & kAggressivesRecordFlagMinValue) {
						value = kAggressivesMinValue;
					}

					_LOG("synchronizeAggressives 0x%x = %u to %s\n",
					    record->type, value, service->getName());
					service->setAggressiveness(record->type, value);
				}
				service->deassertPMDriverCall(&callEntry);
			}
		}
	}
}

//******************************************************************************
// broadcastAggressives
//
// Traverse PM tree and call setAggressiveness() for records that have changed.
//******************************************************************************

void
IOPMrootDomain::broadcastAggressives(
	const AggressivesRecord *   array,
	int                         count )
{
	OSSharedPtr<IORegistryIterator> iter;
	IORegistryEntry                *entry;
	OSSharedPtr<IORegistryEntry>    child;
	IOPowerConnection              *connect;
	IOService                      *service;
	const AggressivesRecord        *record;
	IOPMDriverCallEntry             callEntry;
	uint32_t                        value;
	int                             i;

	iter = IORegistryIterator::iterateOver(
		this, gIOPowerPlane, kIORegistryIterateRecursively);
	if (iter) {
		do{
			// !! reset the iterator
			iter->reset();
			while ((entry = iter->getNextObject())) {
				connect = OSDynamicCast(IOPowerConnection, entry);
				if (!connect || !connect->getReadyFlag()) {
					continue;
				}

				child = connect->copyChildEntry(gIOPowerPlane);
				if (child) {
					if ((service = OSDynamicCast(IOService, child.get()))) {
						if (service->assertPMDriverCall(&callEntry, kIOPMDriverCallMethodSetAggressive)) {
							for (i = 0, record = array; i < count; i++, record++) {
								if (record->flags & kAggressivesRecordFlagModified) {
									value = record->value;
									if (record->flags & kAggressivesRecordFlagMinValue) {
										value = kAggressivesMinValue;
									}
									_LOG("broadcastAggressives %x = %u to %s\n",
									    record->type, value, service->getName());
									service->setAggressiveness(record->type, value);
								}
							}
							service->deassertPMDriverCall(&callEntry);
						}
					}
				}
			}
		}while (!entry && !iter->isValid());
	}
}

//*****************************************
// stackshot on power button press
// ***************************************
static void
powerButtonDownCallout(thread_call_param_t us, thread_call_param_t )
{
	/* Power button pressed during wake
	 * Take a stackshot
	 */
	DEBUG_LOG("Powerbutton: down. Taking stackshot\n");
	((IOPMrootDomain *)us)->takeStackshot(false);
}

static void
powerButtonUpCallout(thread_call_param_t us, thread_call_param_t)
{
	/* Power button released.
	 * Delete any stackshot data
	 */
	DEBUG_LOG("PowerButton: up callout. Delete stackshot\n");
	((IOPMrootDomain *)us)->deleteStackshot();
}
//*************************************************************************
//

// MARK: -
// MARK: System Sleep

//******************************************************************************
// startIdleSleepTimer
//
//******************************************************************************

void
IOPMrootDomain::startIdleSleepTimer( uint32_t inSeconds )
{
	AbsoluteTime deadline;

	ASSERT_GATED();
	if (gNoIdleFlag) {
		DLOG("idle timer not set (noidle=%d)\n", gNoIdleFlag);
		return;
	}
	if (inSeconds) {
		clock_interval_to_deadline(inSeconds, kSecondScale, &deadline);
		thread_call_enter_delayed(extraSleepTimer, deadline);
		idleSleepTimerPending = true;
	} else {
		thread_call_enter(extraSleepTimer);
	}
	DLOG("idle timer set for %u seconds\n", inSeconds);
}

//******************************************************************************
// cancelIdleSleepTimer
//
//******************************************************************************

void
IOPMrootDomain::cancelIdleSleepTimer( void )
{
	ASSERT_GATED();
	if (idleSleepTimerPending) {
		DLOG("idle timer cancelled\n");
		thread_call_cancel(extraSleepTimer);
		idleSleepTimerPending = false;

		if (!assertOnWakeSecs && gIOLastWakeAbsTime) {
			AbsoluteTime    now;
			clock_usec_t    microsecs;
			clock_get_uptime(&now);
			SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
			absolutetime_to_microtime(now, &assertOnWakeSecs, &microsecs);
			if (assertOnWakeReport) {
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

static void
idleSleepTimerExpired(
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

void
IOPMrootDomain::handleSleepTimerExpiration( void )
{
	if (!gIOPMWorkLoop->inGate()) {
		gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(IOWorkLoop::Action, this,
			&IOPMrootDomain::handleSleepTimerExpiration),
			this);
		return;
	}

	DLOG("sleep timer expired\n");
	ASSERT_GATED();

	idleSleepTimerPending = false;
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

uint32_t
IOPMrootDomain::getTimeToIdleSleep( void )
{
	AbsoluteTime    now, lastActivityTime;
	uint64_t        nanos;
	uint32_t        minutesSinceUserInactive = 0;
	uint32_t        sleepDelay = 0;

	if (!idleSleepEnabled) {
		return 0xffffffff;
	}

	if (userActivityTime) {
		lastActivityTime = userActivityTime;
	} else {
		lastActivityTime = userBecameInactiveTime;
	}

	// Ignore any lastActivityTime that predates the last system wake.
	// The goal is to avoid a sudden idle sleep right after a dark wake
	// due to sleepDelay=0 computed below. The alternative 60s minimum
	// timeout should be large enough to allow dark wake to complete,
	// at which point the idle timer will be promptly cancelled.
	clock_get_uptime(&now);
	if ((CMP_ABSOLUTETIME(&lastActivityTime, &gIOLastWakeAbsTime) >= 0) &&
	    (CMP_ABSOLUTETIME(&now, &lastActivityTime) > 0)) {
		SUB_ABSOLUTETIME(&now, &lastActivityTime);
		absolutetime_to_nanoseconds(now, &nanos);
		minutesSinceUserInactive = nanos / (60000000000ULL);

		if (minutesSinceUserInactive >= sleepSlider) {
			sleepDelay = 0;
		} else {
			sleepDelay = sleepSlider - minutesSinceUserInactive;
		}
	} else {
		DLOG("ignoring lastActivityTime 0x%qx, now 0x%qx, wake 0x%qx\n",
		    lastActivityTime, now, gIOLastWakeAbsTime);
		sleepDelay = sleepSlider;
	}

	DLOG("user inactive %u min, time to idle sleep %u min\n",
	    minutesSinceUserInactive, sleepDelay);

	return sleepDelay * 60;
}

//******************************************************************************
// setQuickSpinDownTimeout
//
//******************************************************************************

void
IOPMrootDomain::setQuickSpinDownTimeout( void )
{
	ASSERT_GATED();
	setAggressiveness(
		kPMMinutesToSpinDown, 0, kAggressivesOptionQuickSpindownEnable );
}

//******************************************************************************
// restoreUserSpinDownTimeout
//
//******************************************************************************

void
IOPMrootDomain::restoreUserSpinDownTimeout( void )
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
IOReturn
IOPMrootDomain::sleepSystem( void )
{
	return sleepSystemOptions(NULL);
}

/* private */
IOReturn
IOPMrootDomain::sleepSystemOptions( OSDictionary *options )
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

	if (options && options->getObject("OSSwitch")) {
		// Log specific sleep cause for OS Switch hibernation
		return privateSleepSystem( kIOPMSleepReasonOSSwitchHibernate);
	}

	if (options && (obj = options->getObject("Sleep Reason"))) {
		reason = OSDynamicCast(OSString, obj);
		if (reason && reason->isEqualTo(kIOPMDarkWakeThermalEmergencyKey)) {
			return privateSleepSystem(kIOPMSleepReasonDarkWakeThermalEmergency);
		}
		if (reason && reason->isEqualTo(kIOPMNotificationWakeExitKey)) {
			return privateSleepSystem(kIOPMSleepReasonNotificationWakeExit);
		}
	}

	return privateSleepSystem( kIOPMSleepReasonSoftware);
}

/* private */
IOReturn
IOPMrootDomain::privateSleepSystem( uint32_t sleepReason )
{
	/* Called from both gated and non-gated context */

	if (!checkSystemSleepEnabled() || !pmPowerStateQueue) {
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
void
IOPMrootDomain::powerChangeDone( unsigned long previousPowerState )
{
#if !__i386__ && !__x86_64__
	uint64_t    timeSinceReset = 0;
#endif
	uint64_t           now;
	unsigned long      newState;
	clock_sec_t        secs;
	clock_usec_t       microsecs;
	uint32_t           lastDebugWakeSeconds;
	clock_sec_t        adjWakeTime;
	IOPMCalendarStruct nowCalendar;

	ASSERT_GATED();
	newState = getPowerState();
	DLOG("PowerChangeDone: %s->%s\n",
	    getPowerStateString((uint32_t) previousPowerState), getPowerStateString((uint32_t) getPowerState()));

	if (previousPowerState == newState) {
		return;
	}

	notifierThread = current_thread();
	switch (getPowerState()) {
	case SLEEP_STATE: {
		if (kPMCalendarTypeInvalid != _aotWakeTimeCalendar.selector) {
			secs = 0;
			microsecs = 0;
			PEGetUTCTimeOfDay(&secs, &microsecs);

			adjWakeTime = 0;
			if ((kIOPMAOTModeRespectTimers & _aotMode) && (_calendarWakeAlarmUTC < _aotWakeTimeUTC)) {
				IOLog("use _calendarWakeAlarmUTC\n");
				adjWakeTime = _calendarWakeAlarmUTC;
			} else if (_aotExit || (kIOPMWakeEventAOTExitFlags & _aotPendingFlags)) {
				IOLog("accelerate _aotWakeTime for exit\n");
				adjWakeTime = secs;
			} else if (kIOPMDriverAssertionLevelOn == getPMAssertionLevel(kIOPMDriverAssertionCPUBit)) {
				IOLog("accelerate _aotWakeTime for assertion\n");
				adjWakeTime = secs;
			}
			if (adjWakeTime) {
				IOPMConvertSecondsToCalendar(adjWakeTime, &_aotWakeTimeCalendar);
			}

			IOPMConvertSecondsToCalendar(secs, &nowCalendar);
			IOLog("aotSleep at " YMDTF " sched: " YMDTF "\n", YMDT(&nowCalendar), YMDT(&_aotWakeTimeCalendar));

			IOReturn __unused ret = setMaintenanceWakeCalendar(&_aotWakeTimeCalendar);
			assert(kIOReturnSuccess == ret);
		}
		if (_aotLastWakeTime) {
			_aotMetrics->totalTime += mach_absolute_time() - _aotLastWakeTime;
			if (_aotMetrics->sleepCount && (_aotMetrics->sleepCount <= kIOPMAOTMetricsKernelWakeCountMax)) {
				strlcpy(&_aotMetrics->kernelWakeReason[_aotMetrics->sleepCount - 1][0],
				    gWakeReasonString,
				    sizeof(_aotMetrics->kernelWakeReason[_aotMetrics->sleepCount]));
			}
		}
		_aotPendingFlags &= ~kIOPMWakeEventAOTPerCycleFlags;
		if (_aotTimerScheduled) {
			_aotTimerES->cancelTimeout();
			_aotTimerScheduled = false;
		}
		acceptSystemWakeEvents(kAcceptSystemWakeEvents_Enable);

		// re-enable this timer for next sleep
		cancelIdleSleepTimer();

		if (clamshellExists) {
#if DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY
			if (gClamshellFlags & kClamshell_WAR_58009435) {
				// Disable clamshell sleep until system has completed full wake.
				// This prevents a system sleep request (due to a clamshell close)
				// from being queued until the end of system full wake - even if
				// other clamshell disable bits outside of our control is wrong.
				setClamShellSleepDisable(true, kClamshellSleepDisableInternal);
			}
#endif

			// Log the last known clamshell state before system sleep
			DLOG("clamshell closed %d, disabled %d/%x, desktopMode %d, ac %d\n",
			    clamshellClosed, clamshellDisabled, clamshellSleepDisableMask,
			    desktopMode, acAdaptorConnected);
		}

		clock_get_calendar_absolute_and_microtime(&secs, &microsecs, &now);
		logtime(secs);
		gIOLastSleepTime.tv_sec  = secs;
		gIOLastSleepTime.tv_usec = microsecs;
		if (!_aotLastWakeTime) {
			gIOLastUserSleepTime = gIOLastSleepTime;
		}

		gIOLastWakeTime.tv_sec = 0;
		gIOLastWakeTime.tv_usec = 0;
		gIOLastSleepAbsTime = now;

		if (wake2DarkwakeDelay && sleepDelaysReport) {
			clock_sec_t     wake2DarkwakeSecs, darkwake2SleepSecs;
			// Update 'wake2DarkwakeDelay' histogram if this is a fullwake->sleep transition

			SUB_ABSOLUTETIME(&now, &ts_sleepStart);
			absolutetime_to_microtime(now, &darkwake2SleepSecs, &microsecs);
			absolutetime_to_microtime(wake2DarkwakeDelay, &wake2DarkwakeSecs, &microsecs);
			HISTREPORT_TALLYVALUE(sleepDelaysReport,
			    (int64_t)(wake2DarkwakeSecs + darkwake2SleepSecs));

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
			OSSharedPtr<const OSSymbol> event = OSSymbol::withCString(kIOPMThermalLevelWarningKey);
			if (event) {
				systemPowerEventOccurred(event.get(), kIOPMThermalLevelUnknown);
			}
		}
		assertOnWakeSecs = 0;
		lowBatteryCondition = false;
		thermalEmergencyState = false;

#if DEVELOPMENT || DEBUG
		extern int g_should_log_clock_adjustments;
		if (g_should_log_clock_adjustments) {
			clock_sec_t  secs = 0;
			clock_usec_t microsecs = 0;
			uint64_t now_b = mach_absolute_time();

			secs = 0;
			microsecs = 0;
			PEGetUTCTimeOfDay(&secs, &microsecs);

			uint64_t now_a = mach_absolute_time();
			os_log(OS_LOG_DEFAULT, "%s PMU before going to sleep %lu s %d u %llu abs_b_PEG %llu abs_a_PEG \n",
			    __func__, (unsigned long)secs, microsecs, now_b, now_a);
		}
#endif

		getPlatform()->sleepKernel();

		// The CPU(s) are off at this point,
		// Code will resume execution here upon wake.

		clock_get_uptime(&gIOLastWakeAbsTime);
		IOLog("gIOLastWakeAbsTime: %lld\n", gIOLastWakeAbsTime);
		_highestCapability = 0;

#if HIBERNATION
		IOHibernateSystemWake();
#endif

		// sleep transition complete
		gSleepOrShutdownPending = 0;

		// trip the reset of the calendar clock
		clock_wakeup_calendar();
		clock_get_calendar_microtime(&secs, &microsecs);
		gIOLastWakeTime.tv_sec  = secs;
		gIOLastWakeTime.tv_usec = microsecs;

		// aot
		if (_aotWakeTimeCalendar.selector != kPMCalendarTypeInvalid) {
			_aotWakeTimeCalendar.selector = kPMCalendarTypeInvalid;
			secs = 0;
			microsecs = 0;
			PEGetUTCTimeOfDay(&secs, &microsecs);
			IOPMConvertSecondsToCalendar(secs, &nowCalendar);
			IOLog("aotWake at " YMDTF " sched: " YMDTF "\n", YMDT(&nowCalendar), YMDT(&_aotWakeTimeCalendar));
			_aotMetrics->sleepCount++;
			_aotLastWakeTime = gIOLastWakeAbsTime;
			if (_aotMetrics->sleepCount <= kIOPMAOTMetricsKernelWakeCountMax) {
				_aotMetrics->kernelSleepTime[_aotMetrics->sleepCount - 1]
				        = (((uint64_t) gIOLastSleepTime.tv_sec) << 10) + (gIOLastSleepTime.tv_usec / 1000);
				_aotMetrics->kernelWakeTime[_aotMetrics->sleepCount - 1]
				        = (((uint64_t) gIOLastWakeTime.tv_sec) << 10) + (gIOLastWakeTime.tv_usec / 1000);
			}

			if (_aotTestTime) {
				if (_aotWakeTimeUTC <= secs) {
					_aotTestTime = _aotTestTime + _aotTestInterval;
				}
				setWakeTime(_aotTestTime);
			}
		}

#if HIBERNATION
		LOG("System %sWake\n", gIOHibernateState ? "SafeSleep " : "");
#endif

		lastSleepReason = 0;

		lastDebugWakeSeconds    = _debugWakeSeconds;
		_debugWakeSeconds       = 0;
		_scheduledAlarmMask     = 0;
		_nextScheduledAlarmType = NULL;

		darkWakeExit            = false;
		darkWakePowerClamped    = false;
		darkWakePostTickle      = false;
		darkWakeHibernateError  = false;
		darkWakeToSleepASAP     = true;
		darkWakeLogClamp        = true;
		sleepTimerMaintenance   = false;
		sleepToStandby          = false;
		wranglerTickled         = false;
		userWasActive           = false;
		isRTCAlarmWake          = false;
		clamshellIgnoreClose    = false;
		fullWakeReason = kFullWakeReasonNone;

#if defined(__i386__) || defined(__x86_64__)
		kdebugTrace(kPMLogSystemWake, 0, 0, 0);

		OSSharedPtr<OSObject> wakeTypeProp   = copyProperty(kIOPMRootDomainWakeTypeKey);
		OSSharedPtr<OSObject> wakeReasonProp = copyProperty(kIOPMRootDomainWakeReasonKey);
		OSString * wakeType = OSDynamicCast(OSString, wakeTypeProp.get());
		OSString * wakeReason = OSDynamicCast(OSString, wakeReasonProp.get());

		if (wakeReason && (wakeReason->getLength() >= 2) &&
		    gWakeReasonString[0] == '\0') {
			WAKEEVENT_LOCK();
			// Until the platform driver can claim its wake reasons
			strlcat(gWakeReasonString, wakeReason->getCStringNoCopy(),
			    sizeof(gWakeReasonString));
			WAKEEVENT_UNLOCK();
		}

		if (wakeType && wakeType->isEqualTo(kIOPMrootDomainWakeTypeLowBattery)) {
			lowBatteryCondition = true;
			darkWakeMaintenance = true;
		} else {
#if HIBERNATION
			OSSharedPtr<OSObject> hibOptionsProp = copyProperty(kIOHibernateOptionsKey);
			OSNumber * hibOptions = OSDynamicCast(  OSNumber, hibOptionsProp.get());
			if (hibernateAborted || ((hibOptions &&
			    !(hibOptions->unsigned32BitValue() & kIOHibernateOptionDarkWake)))) {
				// Hibernate aborted, or EFI brought up graphics
				darkWakeExit = true;
				if (hibernateAborted) {
					DLOG("Hibernation aborted\n");
				} else {
					DLOG("EFI brought up graphics. Going to full wake. HibOptions: 0x%x\n", hibOptions->unsigned32BitValue());
				}
			} else
#endif
			if (wakeType && (
				    wakeType->isEqualTo(kIOPMRootDomainWakeTypeUser) ||
				    wakeType->isEqualTo(kIOPMRootDomainWakeTypeAlarm))) {
				// User wake or RTC alarm
				darkWakeExit = true;
				if (wakeType->isEqualTo(kIOPMRootDomainWakeTypeAlarm)) {
					isRTCAlarmWake = true;
				}
			} else if (wakeType &&
			    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepTimer)) {
				// SMC standby timer trumps SleepX
				darkWakeMaintenance = true;
				sleepTimerMaintenance = true;
			} else if ((lastDebugWakeSeconds != 0) &&
			    ((gDarkWakeFlags & kDarkWakeFlagAlarmIsDark) == 0)) {
				// SleepX before maintenance
				darkWakeExit = true;
			} else if (wakeType &&
			    wakeType->isEqualTo(kIOPMRootDomainWakeTypeMaintenance)) {
				darkWakeMaintenance = true;
			} else if (wakeType &&
			    wakeType->isEqualTo(kIOPMRootDomainWakeTypeSleepService)) {
				darkWakeMaintenance = true;
				darkWakeSleepService = true;
#if HIBERNATION
				if (kIOHibernateStateWakingFromHibernate == gIOHibernateState) {
					sleepToStandby = true;
				}
#endif
			} else if (wakeType &&
			    wakeType->isEqualTo(kIOPMRootDomainWakeTypeHibernateError)) {
				darkWakeMaintenance = true;
				darkWakeHibernateError = true;
			} else {
				// Unidentified wake source, resume to full wake if debug
				// alarm is pending.

				if (lastDebugWakeSeconds &&
				    (!wakeReason || wakeReason->isEqualTo(""))) {
					darkWakeExit = true;
				}
			}
		}

		if (darkWakeExit) {
			darkWakeToSleepASAP = false;
			fullWakeReason = kFullWakeReasonLocalUser;
			reportUserInput();
		} else if (displayPowerOnRequested && checkSystemCanSustainFullWake()) {
			handleSetDisplayPowerOn(true);
		} else if (!darkWakeMaintenance) {
			// Early/late tickle for non-maintenance wake.
			if ((gDarkWakeFlags & kDarkWakeFlagPromotionMask) != kDarkWakeFlagPromotionNone) {
				darkWakePostTickle = true;
			}
		}
#else   /* !__i386__ && !__x86_64__ */
		timeSinceReset = ml_get_time_since_reset();
		kdebugTrace(kPMLogSystemWake, 0, (uintptr_t)(timeSinceReset >> 32), (uintptr_t) timeSinceReset);

		if ((gDarkWakeFlags & kDarkWakeFlagPromotionMask) == kDarkWakeFlagPromotionEarly) {
			wranglerTickled = true;
			fullWakeReason = kFullWakeReasonLocalUser;
			requestUserActive(this, "Full wake on dark wake promotion boot-arg");
		} else if ((lastDebugWakeSeconds != 0) && !(gDarkWakeFlags & kDarkWakeFlagAlarmIsDark)) {
			isRTCAlarmWake = true;
			fullWakeReason = kFullWakeReasonLocalUser;
			requestUserActive(this, "RTC debug alarm");
		}

		// stay awake for at least 30 seconds
		startIdleSleepTimer(30);
#endif
		sleepCnt++;

		thread_call_enter(updateConsoleUsersEntry);

		changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonWake);
		break;
	}
#if !__i386__ && !__x86_64__
	case ON_STATE:
	case AOT_STATE:
	{
		DLOG("Force re-evaluating aggressiveness\n");
		/* Force re-evaluate the aggressiveness values to set appropriate idle sleep timer */
		pmPowerStateQueue->submitPowerEvent(
			kPowerEventPolicyStimulus,
			(void *) kStimulusNoIdleSleepPreventers );

		// After changing to ON_STATE, invalidate any previously queued
		// request to change to a state less than ON_STATE. This isn't
		// necessary for AOT_STATE or if the device has only one running
		// state since the changePowerStateToPriv() issued at the tail
		// end of SLEEP_STATE case should take care of that.
		if (getPowerState() == ON_STATE) {
			changePowerStateWithTagToPriv(ON_STATE, kCPSReasonWake);
		}
		break;
	}
#endif /* !__i386__ && !__x86_64__ */
	}
	notifierThread = NULL;
}

//******************************************************************************
// requestPowerDomainState
//
// Extend implementation in IOService. Running on PM work loop thread.
//******************************************************************************

IOReturn
IOPMrootDomain::requestPowerDomainState(
	IOPMPowerFlags      childDesire,
	IOPowerConnection * childConnection,
	unsigned long       specification )
{
	// Idle and system sleep prevention flags affects driver desire.
	// Children desire are irrelevant so they are cleared.

	return super::requestPowerDomainState(0, childConnection, specification);
}


static void
makeSleepPreventersListLog(const OSSharedPtr<OSSet> &preventers, char *buf, size_t buf_size)
{
	if (!preventers->getCount()) {
		return;
	}

	char *buf_iter = buf + strlen(buf);
	char *buf_end = buf + buf_size;

	OSSharedPtr<OSCollectionIterator> iterator = OSCollectionIterator::withCollection(preventers.get());
	OSObject *obj = NULL;

	while ((obj = iterator->getNextObject())) {
		IOService *srv = OSDynamicCast(IOService, obj);
		if (buf_iter < buf_end) {
			buf_iter += snprintf(buf_iter, buf_end - buf_iter, " %s", srv->getName());
		} else {
			DLOG("Print buffer exhausted for sleep preventers list\n");
			break;
		}
	}
}

//******************************************************************************
// updatePreventIdleSleepList
//
// Called by IOService on PM work loop.
// Returns true if PM policy recognized the driver's desire to prevent idle
// sleep and updated the list of idle sleep preventers. Returns false otherwise
//******************************************************************************

bool
IOPMrootDomain::updatePreventIdleSleepList(
	IOService * service, bool addNotRemove)
{
	unsigned int oldCount;

	oldCount = idleSleepPreventersCount();
	return updatePreventIdleSleepListInternal(service, addNotRemove, oldCount);
}

bool
IOPMrootDomain::updatePreventIdleSleepListInternal(
	IOService * service, bool addNotRemove, unsigned int oldCount)
{
	unsigned int newCount;

	ASSERT_GATED();

#if defined(XNU_TARGET_OS_OSX)
	// Only the display wrangler and no-idle-sleep kernel assertions
	// can prevent idle sleep. The kIOPMPreventIdleSleep capability flag
	// reported by drivers in their power state table is ignored.
	if (service && (service != wrangler) && (service != this)) {
		return false;
	}
#endif

	if (service) {
		if (addNotRemove) {
			preventIdleSleepList->setObject(service);
			DLOG("Added %s to idle sleep preventers list (Total %u)\n",
			    service->getName(), preventIdleSleepList->getCount());
		} else if (preventIdleSleepList->member(service)) {
			preventIdleSleepList->removeObject(service);
			DLOG("Removed %s from idle sleep preventers list (Total %u)\n",
			    service->getName(), preventIdleSleepList->getCount());
		}

		if (preventIdleSleepList->getCount()) {
			char buf[256] = "Idle Sleep Preventers:";
			makeSleepPreventersListLog(preventIdleSleepList, buf, sizeof(buf));
			DLOG("%s\n", buf);
		}
	}

	newCount = idleSleepPreventersCount();

	if ((oldCount == 0) && (newCount != 0)) {
		// Driver added to empty prevent list.
		// Update the driver desire to prevent idle sleep.
		// Driver desire does not prevent demand sleep.

		changePowerStateWithTagTo(getRUN_STATE(), kCPSReasonIdleSleepPrevent);
	} else if ((oldCount != 0) && (newCount == 0)) {
		// Last driver removed from prevent list.
		// Drop the driver clamp to allow idle sleep.

		changePowerStateWithTagTo(SLEEP_STATE, kCPSReasonIdleSleepAllow);
		evaluatePolicy( kStimulusNoIdleSleepPreventers );
	}
	messageClient(kIOPMMessageIdleSleepPreventers, systemCapabilityNotifier.get(),
	    &newCount, sizeof(newCount));

#if defined(XNU_TARGET_OS_OSX)
	if (addNotRemove && (service == wrangler) && !checkSystemCanSustainFullWake()) {
		DLOG("Cannot cancel idle sleep\n");
		return false; // do not idle-cancel
	}
#endif

	return true;
}

//******************************************************************************
// startSpinDump
//******************************************************************************

void
IOPMrootDomain::startSpinDump(uint32_t spindumpKind)
{
	messageClients(kIOPMMessageLaunchBootSpinDump, (void *)(uintptr_t)spindumpKind);
}

//******************************************************************************
// preventSystemSleepListUpdate
//
// Called by IOService on PM work loop.
//******************************************************************************

void
IOPMrootDomain::updatePreventSystemSleepList(
	IOService * service, bool addNotRemove )
{
	unsigned int oldCount, newCount;

	ASSERT_GATED();
	if (this == service) {
		return;
	}

	oldCount = preventSystemSleepList->getCount();
	if (addNotRemove) {
		preventSystemSleepList->setObject(service);
		DLOG("Added %s to system sleep preventers list (Total %u)\n",
		    service->getName(), preventSystemSleepList->getCount());
		if (!assertOnWakeSecs && gIOLastWakeAbsTime) {
			AbsoluteTime    now;
			clock_usec_t    microsecs;
			clock_get_uptime(&now);
			SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
			absolutetime_to_microtime(now, &assertOnWakeSecs, &microsecs);
			if (assertOnWakeReport) {
				HISTREPORT_TALLYVALUE(assertOnWakeReport, (int64_t)assertOnWakeSecs);
				DLOG("Updated assertOnWake %lu\n", (unsigned long)assertOnWakeSecs);
			}
		}
	} else if (preventSystemSleepList->member(service)) {
		preventSystemSleepList->removeObject(service);
		DLOG("Removed %s from system sleep preventers list (Total %u)\n",
		    service->getName(), preventSystemSleepList->getCount());

		if ((oldCount != 0) && (preventSystemSleepList->getCount() == 0)) {
			// Lost all system sleep preventers.
			// Send stimulus if system sleep was blocked, and is in dark wake.
			evaluatePolicy( kStimulusDarkWakeEvaluate );
		}
	}

	newCount = preventSystemSleepList->getCount();
	if (newCount) {
		char buf[256] = "System Sleep Preventers:";
		makeSleepPreventersListLog(preventSystemSleepList, buf, sizeof(buf));
		DLOG("%s\n", buf);
	}

	messageClient(kIOPMMessageSystemSleepPreventers, systemCapabilityNotifier.get(),
	    &newCount, sizeof(newCount));
}

void
IOPMrootDomain::copySleepPreventersList(OSArray **idleSleepList, OSArray **systemSleepList)
{
	OSSharedPtr<OSCollectionIterator> iterator;
	OSObject    *object = NULL;
	OSSharedPtr<OSArray>     array;

	if (!gIOPMWorkLoop->inGate()) {
		gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(IOWorkLoop::Action, this,
			&IOPMrootDomain::IOPMrootDomain::copySleepPreventersList),
			this, (void *)idleSleepList, (void *)systemSleepList);
		return;
	}

	if (idleSleepList && preventIdleSleepList && (preventIdleSleepList->getCount() != 0)) {
		iterator = OSCollectionIterator::withCollection(preventIdleSleepList.get());
		array = OSArray::withCapacity(5);

		if (iterator && array) {
			while ((object = iterator->getNextObject())) {
				IOService *service = OSDynamicCast(IOService, object);
				if (service) {
					OSSharedPtr<const OSSymbol> name = service->copyName();
					if (name) {
						array->setObject(name.get());
					}
				}
			}
		}
		*idleSleepList = array.detach();
	}

	if (systemSleepList && preventSystemSleepList && (preventSystemSleepList->getCount() != 0)) {
		iterator = OSCollectionIterator::withCollection(preventSystemSleepList.get());
		array = OSArray::withCapacity(5);

		if (iterator && array) {
			while ((object = iterator->getNextObject())) {
				IOService *service = OSDynamicCast(IOService, object);
				if (service) {
					OSSharedPtr<const OSSymbol> name = service->copyName();
					if (name) {
						array->setObject(name.get());
					}
				}
			}
		}
		*systemSleepList = array.detach();
	}
}

void
IOPMrootDomain::copySleepPreventersListWithID(OSArray **idleSleepList, OSArray **systemSleepList)
{
	OSSharedPtr<OSCollectionIterator> iterator;
	OSObject    *object = NULL;
	OSSharedPtr<OSArray>     array;

	if (!gIOPMWorkLoop->inGate()) {
		gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(IOWorkLoop::Action, this,
			&IOPMrootDomain::IOPMrootDomain::copySleepPreventersListWithID),
			this, (void *)idleSleepList, (void *)systemSleepList);
		return;
	}

	if (idleSleepList && preventIdleSleepList && (preventIdleSleepList->getCount() != 0)) {
		iterator = OSCollectionIterator::withCollection(preventIdleSleepList.get());
		array = OSArray::withCapacity(5);

		if (iterator && array) {
			while ((object = iterator->getNextObject())) {
				IOService *service = OSDynamicCast(IOService, object);
				if (service) {
					OSSharedPtr<OSDictionary> dict = OSDictionary::withCapacity(2);
					OSSharedPtr<const OSSymbol> name = service->copyName();
					OSSharedPtr<OSNumber> id = OSNumber::withNumber(service->getRegistryEntryID(), 64);
					if (dict && name && id) {
						dict->setObject(kIOPMDriverAssertionRegistryEntryIDKey, id.get());
						dict->setObject(kIOPMDriverAssertionOwnerStringKey, name.get());
						array->setObject(dict.get());
					}
				}
			}
		}
		*idleSleepList = array.detach();
	}

	if (systemSleepList && preventSystemSleepList && (preventSystemSleepList->getCount() != 0)) {
		iterator = OSCollectionIterator::withCollection(preventSystemSleepList.get());
		array = OSArray::withCapacity(5);

		if (iterator && array) {
			while ((object = iterator->getNextObject())) {
				IOService *service = OSDynamicCast(IOService, object);
				if (service) {
					OSSharedPtr<OSDictionary> dict = OSDictionary::withCapacity(2);
					OSSharedPtr<const OSSymbol> name = service->copyName();
					OSSharedPtr<OSNumber> id = OSNumber::withNumber(service->getRegistryEntryID(), 64);
					if (dict && name && id) {
						dict->setObject(kIOPMDriverAssertionRegistryEntryIDKey, id.get());
						dict->setObject(kIOPMDriverAssertionOwnerStringKey, name.get());
						array->setObject(dict.get());
					}
				}
			}
		}
		*systemSleepList = array.detach();
	}
}

//******************************************************************************
// tellChangeDown
//
// Override the superclass implementation to send a different message type.
//******************************************************************************

bool
IOPMrootDomain::tellChangeDown( unsigned long stateNum )
{
	DLOG("tellChangeDown %s->%s\n",
	    getPowerStateString((uint32_t) getPowerState()), getPowerStateString((uint32_t) stateNum));

	if (SLEEP_STATE == stateNum) {
		// Legacy apps were already told in the full->dark transition
		if (!ignoreTellChangeDown) {
			tracePoint( kIOPMTracePointSleepApplications );
		} else {
			tracePoint( kIOPMTracePointSleepPriorityClients );
		}
	}

	if (!ignoreTellChangeDown) {
		userActivityAtSleep = userActivityCount;
		DLOG("tellChangeDown::userActivityAtSleep %d\n", userActivityAtSleep);

		if (SLEEP_STATE == stateNum) {
			hibernateAborted = false;

			// Direct callout into OSKext so it can disable kext unloads
			// during sleep/wake to prevent deadlocks.
			OSKextSystemSleepOrWake( kIOMessageSystemWillSleep );

			IOService::updateConsoleUsers(NULL, kIOMessageSystemWillSleep);

			// Two change downs are sent by IOServicePM. Ignore the 2nd.
			// But tellClientsWithResponse() must be called for both.
			ignoreTellChangeDown = true;
		}
	}

	return super::tellClientsWithResponse( kIOMessageSystemWillSleep );
}

//******************************************************************************
// askChangeDown
//
// Override the superclass implementation to send a different message type.
// This must be idle sleep since we don't ask during any other power change.
//******************************************************************************

bool
IOPMrootDomain::askChangeDown( unsigned long stateNum )
{
	DLOG("askChangeDown %s->%s\n",
	    getPowerStateString((uint32_t) getPowerState()), getPowerStateString((uint32_t) stateNum));

	// Don't log for dark wake entry
	if (kSystemTransitionSleep == _systemTransitionType) {
		tracePoint( kIOPMTracePointSleepApplications );
	}

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

void
IOPMrootDomain::askChangeDownDone(
	IOPMPowerChangeFlags * inOutChangeFlags, bool * cancel )
{
	DLOG("askChangeDownDone(0x%x, %u) type %x, cap %x->%x\n",
	    *inOutChangeFlags, *cancel,
	    _systemTransitionType,
	    _currentCapability, _pendingCapability);

	if ((false == *cancel) && (kSystemTransitionSleep == _systemTransitionType)) {
		// Dark->Sleep transition.
		// Check if there are any deny sleep assertions.
		// lastSleepReason already set by handleOurPowerChangeStart()

		if (!checkSystemCanSleep(lastSleepReason)) {
			// Cancel dark wake to sleep transition.
			// Must re-scan assertions upon entering dark wake.

			*cancel = true;
			DLOG("cancel dark->sleep\n");
		}
		if (_aotMode && (kPMCalendarTypeInvalid != _aotWakeTimeCalendar.selector)) {
			uint64_t now = mach_continuous_time();
			if (((now + _aotWakePreWindow) >= _aotWakeTimeContinuous)
			    && (now < (_aotWakeTimeContinuous + _aotWakePostWindow))) {
				*cancel = true;
				IOLog("AOT wake window cancel: %qd, %qd\n", now, _aotWakeTimeContinuous);
			}
		}
	}
}

//******************************************************************************
// systemDidNotSleep
//
// Work common to both canceled or aborted sleep.
//******************************************************************************

void
IOPMrootDomain::systemDidNotSleep( void )
{
	// reset console lock state
	thread_call_enter(updateConsoleUsersEntry);

	if (idleSleepEnabled) {
		if (!wrangler) {
#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
			startIdleSleepTimer(kIdleSleepRetryInterval);
#else
			startIdleSleepTimer(idleSeconds);
#endif
		} else if (!userIsActive) {
			// Manually start the idle sleep timer besides waiting for
			// the user to become inactive.
			startIdleSleepTimer(kIdleSleepRetryInterval);
		}
	}

	preventTransitionToUserActive(false);
	IOService::setAdvisoryTickleEnable( true );

	// After idle revert and cancel, send a did-change message to powerd
	// to balance the previous will-change message. Kernel clients do not
	// need this since sleep cannot be canceled once they are notified.

	if (toldPowerdCapWillChange && systemCapabilityNotifier &&
	    (_pendingCapability != _currentCapability) &&
	    ((_systemMessageClientMask & kSystemMessageClientPowerd) != 0)) {
		// Differs from a real capability gain change where notifyRef != 0,
		// but it is zero here since no response is expected.

		IOPMSystemCapabilityChangeParameters params;

		bzero(&params, sizeof(params));
		params.fromCapabilities = _pendingCapability;
		params.toCapabilities = _currentCapability;
		params.changeFlags = kIOPMSystemCapabilityDidChange;

		DLOG("MESG cap %x->%x did change\n",
		    params.fromCapabilities, params.toCapabilities);
		messageClient(kIOMessageSystemCapabilityChange, systemCapabilityNotifier.get(),
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

void
IOPMrootDomain::tellNoChangeDown( unsigned long stateNum )
{
	DLOG("tellNoChangeDown %s->%s\n",
	    getPowerStateString((uint32_t) getPowerState()), getPowerStateString((uint32_t) stateNum));

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

void
IOPMrootDomain::tellChangeUp( unsigned long stateNum )
{
	DLOG("tellChangeUp %s->%s\n",
	    getPowerStateString((uint32_t) getPowerState()), getPowerStateString((uint32_t) stateNum));

	ignoreTellChangeDown = false;

	if (stateNum == ON_STATE) {
		// Direct callout into OSKext so it can disable kext unloads
		// during sleep/wake to prevent deadlocks.
		OSKextSystemSleepOrWake( kIOMessageSystemHasPoweredOn );

		// Notify platform that sleep was cancelled or resumed.
		getPlatform()->callPlatformFunction(
			sleepMessagePEFunction.get(), false,
			(void *)(uintptr_t) kIOMessageSystemHasPoweredOn,
			NULL, NULL, NULL);

		if (getPowerState() == ON_STATE) {
			// Sleep was cancelled by idle cancel or revert
			if (!CAP_CURRENT(kIOPMSystemCapabilityGraphics)) {
				// rdar://problem/50363791
				// If system is in dark wake and sleep is cancelled, do not
				// send SystemWillPowerOn/HasPoweredOn messages to kernel
				// priority clients. They haven't yet seen a SystemWillSleep
				// message before the cancellation. So make sure the kernel
				// client bit is cleared in _systemMessageClientMask before
				// invoking the tellClients() below. This bit may have been
				// set by handleOurPowerChangeStart() anticipating a successful
				// sleep and setting the filter mask ahead of time allows the
				// SystemWillSleep message to go through.
				_systemMessageClientMask &= ~kSystemMessageClientKernel;
			}

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

IOReturn
IOPMrootDomain::sysPowerDownHandler(
	void * target, void * refCon,
	UInt32 messageType, IOService * service,
	void * messageArgs, vm_size_t argSize )
{
	static UInt32 lastSystemMessageType = 0;
	IOReturn    ret = 0;

	DLOG("sysPowerDownHandler message %s\n", getIOMessageString(messageType));

	// rdar://problem/50363791
	// Sanity check to make sure the SystemWill/Has message types are
	// received in the expected order for all kernel priority clients.
	if (messageType == kIOMessageSystemWillSleep ||
	    messageType == kIOMessageSystemWillPowerOn ||
	    messageType == kIOMessageSystemHasPoweredOn) {
		switch (messageType) {
		case kIOMessageSystemWillPowerOn:
			assert(lastSystemMessageType == kIOMessageSystemWillSleep);
			break;
		case kIOMessageSystemHasPoweredOn:
			assert(lastSystemMessageType == kIOMessageSystemWillPowerOn);
			break;
		}

		lastSystemMessageType = messageType;
	}

	if (!gRootDomain) {
		return kIOReturnUnsupported;
	}

	if (messageType == kIOMessageSystemCapabilityChange) {
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

		if (CAP_WILL_CHANGE_TO_OFF(params, kIOPMSystemCapabilityCPU)) {
			// We will ack within 20 seconds
			params->maxWaitForReply = 20 * 1000 * 1000;

#if HIBERNATION
			gRootDomain->evaluateSystemSleepPolicyEarly();

			// add in time we could spend freeing pages
			if (gRootDomain->hibernateMode && !gRootDomain->hibernateDisabled) {
				params->maxWaitForReply = kCapabilityClientMaxWait;
			}
			DLOG("sysPowerDownHandler max wait %d s\n",
			    (int) (params->maxWaitForReply / 1000 / 1000));
#endif

			// Notify platform that sleep has begun, after the early
			// sleep policy evaluation.
			getPlatform()->callPlatformFunction(
				sleepMessagePEFunction.get(), false,
				(void *)(uintptr_t) kIOMessageSystemWillSleep,
				NULL, NULL, NULL);

			if (!OSCompareAndSwap( 0, 1, &gSleepOrShutdownPending )) {
				// Purposely delay the ack and hope that shutdown occurs quickly.
				// Another option is not to schedule the thread and wait for
				// ack timeout...
				AbsoluteTime deadline;
				clock_interval_to_deadline( 30, kSecondScale, &deadline );
				thread_call_enter1_delayed(
					gRootDomain->diskSyncCalloutEntry,
					(thread_call_param_t)(uintptr_t) params->notifyRef,
					deadline );
			} else {
				thread_call_enter1(
					gRootDomain->diskSyncCalloutEntry,
					(thread_call_param_t)(uintptr_t) params->notifyRef);
			}
		}
#if HIBERNATION
		else if (CAP_DID_CHANGE_TO_ON(params, kIOPMSystemCapabilityCPU)) {
			// We will ack within 110 seconds
			params->maxWaitForReply = 110 * 1000 * 1000;

			thread_call_enter1(
				gRootDomain->diskSyncCalloutEntry,
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

void
IOPMrootDomain::handleQueueSleepWakeUUID(OSObject *obj)
{
	OSSharedPtr<OSString>    str;

	if (kOSBooleanFalse == obj) {
		handlePublishSleepWakeUUID(false);
	} else {
		str.reset(OSDynamicCast(OSString, obj), OSNoRetain);
		if (str) {
			// This branch caches the UUID for an upcoming sleep/wake
			queuedSleepWakeUUIDString = str;
			DLOG("SleepWake UUID queued: %s\n", queuedSleepWakeUUIDString->getCStringNoCopy());
		}
	}
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

void
IOPMrootDomain::handlePublishSleepWakeUUID( bool shouldPublish )
{
	ASSERT_GATED();

	/*
	 * Clear the current UUID
	 */
	if (gSleepWakeUUIDIsSet) {
		DLOG("SleepWake UUID cleared\n");

		gSleepWakeUUIDIsSet = false;

		removeProperty(kIOPMSleepWakeUUIDKey);
		messageClients(kIOPMMessageSleepWakeUUIDChange, kIOPMMessageSleepWakeUUIDCleared);
	}

	/*
	 * Optionally, publish a new UUID
	 */
	if (queuedSleepWakeUUIDString && shouldPublish) {
		OSSharedPtr<OSString> publishThisUUID;

		publishThisUUID = queuedSleepWakeUUIDString;

		if (publishThisUUID) {
			setProperty(kIOPMSleepWakeUUIDKey, publishThisUUID.get());
		}

		gSleepWakeUUIDIsSet = true;
		messageClients(kIOPMMessageSleepWakeUUIDChange, kIOPMMessageSleepWakeUUIDSet);

		queuedSleepWakeUUIDString.reset();
	}
}

//******************************************************************************
// IOPMGetSleepWakeUUIDKey
//
// Return the truth value of gSleepWakeUUIDIsSet and optionally copy the key.
// To get the full key -- a C string -- the buffer must large enough for
// the end-of-string character.
// The key is expected to be an UUID string
//******************************************************************************

extern "C" bool
IOPMCopySleepWakeUUIDKey(char *buffer, size_t buf_len)
{
	if (!gSleepWakeUUIDIsSet) {
		return false;
	}

	if (buffer != NULL) {
		OSSharedPtr<OSString> string =
		    OSDynamicPtrCast<OSString>(gRootDomain->copyProperty(kIOPMSleepWakeUUIDKey));

		if (!string) {
			*buffer = '\0';
		} else {
			strlcpy(buffer, string->getCStringNoCopy(), buf_len);
		}
	}

	return true;
}

//******************************************************************************
// lowLatencyAudioNotify
//
// Used to send an update about low latency audio activity to interested
// clients. To keep the overhead minimal the OSDictionary used here
// is initialized at boot.
//******************************************************************************

void
IOPMrootDomain::lowLatencyAudioNotify(uint64_t time, boolean_t state)
{
	if (lowLatencyAudioNotifierDict && lowLatencyAudioNotifyStateSym && lowLatencyAudioNotifyTimestampSym &&
	    lowLatencyAudioNotifyStateVal && lowLatencyAudioNotifyTimestampVal) {
		lowLatencyAudioNotifyTimestampVal->setValue(time);
		lowLatencyAudioNotifyStateVal->setValue(state);
		setPMSetting(gIOPMSettingLowLatencyAudioModeKey.get(), lowLatencyAudioNotifierDict.get());
	} else {
		DLOG("LowLatencyAudioNotify error\n");
	}
	return;
}

//******************************************************************************
// IOPMrootDomainRTNotifier
//
// Used by performance controller to update the timestamp and state associated
// with low latency audio activity in the system.
//******************************************************************************

extern "C" void
IOPMrootDomainRTNotifier(uint64_t time, boolean_t state)
{
	gRootDomain->lowLatencyAudioNotify(time, state);
	return;
}

//******************************************************************************
// initializeBootSessionUUID
//
// Initialize the boot session uuid at boot up and sets it into registry.
//******************************************************************************

void
IOPMrootDomain::initializeBootSessionUUID(void)
{
	uuid_t          new_uuid;
	uuid_string_t   new_uuid_string;

	uuid_generate(new_uuid);
	uuid_unparse_upper(new_uuid, new_uuid_string);
	memcpy(bootsessionuuid_string, new_uuid_string, sizeof(uuid_string_t));

	setProperty(kIOPMBootSessionUUIDKey, new_uuid_string);
}

//******************************************************************************
// Root domain uses the private and tagged changePowerState methods for
// tracking and logging purposes.
//******************************************************************************

#define REQUEST_TAG_TO_REASON(x)        ((uint16_t)x)

static uint32_t
nextRequestTag( IOPMRequestTag tag )
{
	static SInt16 msb16 = 1;
	uint16_t id = OSAddAtomic16(1, &msb16);
	return ((uint32_t)id << 16) | REQUEST_TAG_TO_REASON(tag);
}

// TODO: remove this shim function and exported symbol
IOReturn
IOPMrootDomain::changePowerStateTo( unsigned long ordinal )
{
	return changePowerStateWithTagTo(ordinal, kCPSReasonNone);
}

// TODO: remove this shim function and exported symbol
IOReturn
IOPMrootDomain::changePowerStateToPriv( unsigned long ordinal )
{
	return changePowerStateWithTagToPriv(ordinal, kCPSReasonNone);
}

IOReturn
IOPMrootDomain::changePowerStateWithOverrideTo(
	IOPMPowerStateIndex ordinal, IOPMRequestTag reason )
{
	uint32_t tag = nextRequestTag(reason);
	DLOG("%s(%s, %x)\n", __FUNCTION__, getPowerStateString((uint32_t) ordinal), tag);

	if ((ordinal != ON_STATE) && (ordinal != AOT_STATE) && (ordinal != SLEEP_STATE)) {
		return kIOReturnUnsupported;
	}

	return super::changePowerStateWithOverrideTo(ordinal, tag);
}

IOReturn
IOPMrootDomain::changePowerStateWithTagTo(
	IOPMPowerStateIndex ordinal, IOPMRequestTag reason )
{
	uint32_t tag = nextRequestTag(reason);
	DLOG("%s(%s, %x)\n", __FUNCTION__, getPowerStateString((uint32_t) ordinal), tag);

	if ((ordinal != ON_STATE) && (ordinal != AOT_STATE) && (ordinal != SLEEP_STATE)) {
		return kIOReturnUnsupported;
	}

	return super::changePowerStateWithTagTo(ordinal, tag);
}

IOReturn
IOPMrootDomain::changePowerStateWithTagToPriv(
	IOPMPowerStateIndex ordinal, IOPMRequestTag reason )
{
	uint32_t tag = nextRequestTag(reason);
	DLOG("%s(%s, %x)\n", __FUNCTION__, getPowerStateString((uint32_t) ordinal), tag);

	if ((ordinal != ON_STATE) && (ordinal != AOT_STATE) && (ordinal != SLEEP_STATE)) {
		return kIOReturnUnsupported;
	}

	return super::changePowerStateWithTagToPriv(ordinal, tag);
}

//******************************************************************************
// activity detect
//
//******************************************************************************

bool
IOPMrootDomain::activitySinceSleep(void)
{
	return userActivityCount != userActivityAtSleep;
}

bool
IOPMrootDomain::abortHibernation(void)
{
#if __arm64__
	// don't allow hibernation to be aborted on ARM due to user activity
	// since once ApplePMGR decides we're hibernating, we can't turn back
	// see: <rdar://problem/63848862> Tonga ApplePMGR diff quiesce path support
	return false;
#else
	bool ret = activitySinceSleep();

	if (ret && !hibernateAborted && checkSystemCanSustainFullWake()) {
		DLOG("activitySinceSleep ABORT [%d, %d]\n", userActivityCount, userActivityAtSleep);
		hibernateAborted = true;
	}
	return ret;
#endif
}

extern "C" int
hibernate_should_abort(void)
{
	if (gRootDomain) {
		return gRootDomain->abortHibernation();
	} else {
		return 0;
	}
}

//******************************************************************************
// willNotifyPowerChildren
//
// Called after all interested drivers have all acknowledged the power change,
// but before any power children is informed. Dispatched though a thread call,
// so it is safe to perform work that might block on a sleeping disk. PM state
// machine (not thread) will block w/o timeout until this function returns.
//******************************************************************************

void
IOPMrootDomain::willNotifyPowerChildren( IOPMPowerStateIndex newPowerState )
{
	OSSharedPtr<OSDictionary> dict;
	OSSharedPtr<OSNumber> secs;

	if (SLEEP_STATE == newPowerState) {
		notifierThread = current_thread();
		if (!tasksSuspended) {
			AbsoluteTime deadline;
			tasksSuspended = TRUE;
			updateTasksSuspend();

			clock_interval_to_deadline(10, kSecondScale, &deadline);
#if defined(XNU_TARGET_OS_OSX)
			vm_pageout_wait(AbsoluteTime_to_scalar(&deadline));
#endif /* defined(XNU_TARGET_OS_OSX) */
		}

		_aotReadyToFullWake = false;
#if 0
		if (_aotLingerTime) {
			uint64_t deadline;
			IOLog("aot linger no return\n");
			clock_absolutetime_interval_to_deadline(_aotLingerTime, &deadline);
			clock_delay_until(deadline);
		}
#endif
		if (!_aotMode) {
			_aotTestTime = 0;
			_aotWakeTimeCalendar.selector = kPMCalendarTypeInvalid;
			if (_aotMetrics) {
				bzero(_aotMetrics, sizeof(IOPMAOTMetrics));
			}
		} else if (!_aotNow && !_debugWakeSeconds) {
			_aotNow            = true;
			_aotExit           = false;
			_aotPendingFlags   = 0;
			_aotTasksSuspended = true;
			_aotLastWakeTime   = 0;
			bzero(_aotMetrics, sizeof(IOPMAOTMetrics));
			if (kIOPMAOTModeCycle & _aotMode) {
				clock_interval_to_absolutetime_interval(60, kSecondScale, &_aotTestInterval);
				_aotTestTime = mach_continuous_time() + _aotTestInterval;
				setWakeTime(_aotTestTime);
			}
			uint32_t lingerSecs;
			if (!PE_parse_boot_argn("aotlinger", &lingerSecs, sizeof(lingerSecs))) {
				lingerSecs = 0;
			}
			clock_interval_to_absolutetime_interval(lingerSecs, kSecondScale, &_aotLingerTime);
			clock_interval_to_absolutetime_interval(2000, kMillisecondScale, &_aotWakePreWindow);
			clock_interval_to_absolutetime_interval(1100, kMillisecondScale, &_aotWakePostWindow);
		}

#if HIBERNATION
		IOHibernateSystemSleep();
		IOHibernateIOKitSleep();
#endif
		if (gRootDomain->activitySinceSleep()) {
			dict = OSDictionary::withCapacity(1);
			secs = OSNumber::withNumber(1, 32);

			if (dict && secs) {
				dict->setObject(gIOPMSettingDebugWakeRelativeKey.get(), secs.get());
				gRootDomain->setProperties(dict.get());
				MSG("Reverting sleep with relative wake\n");
			}
		}

		notifierThread = NULL;
	}
}

//******************************************************************************
// willTellSystemCapabilityDidChange
//
// IOServicePM calls this from OurChangeTellCapabilityDidChange() when root
// domain is raising its power state, immediately after notifying interested
// drivers and power children.
//******************************************************************************

void
IOPMrootDomain::willTellSystemCapabilityDidChange( void )
{
	if ((_systemTransitionType == kSystemTransitionWake) &&
	    !CAP_GAIN(kIOPMSystemCapabilityGraphics)) {
		// After powering up drivers, dark->full promotion on the current wake
		// transition is no longer possible. That is because the next machine
		// state will issue the system capability change messages.
		// The darkWakePowerClamped flag may already be set if the system has
		// at least one driver that was power clamped due to dark wake.
		// This function sets the darkWakePowerClamped flag in case there
		// is no power-clamped driver in the system.
		//
		// Last opportunity to exit dark wake using:
		// requestFullWake( kFullWakeReasonLocalUser );

		if (!darkWakePowerClamped) {
			if (darkWakeLogClamp) {
				AbsoluteTime    now;
				uint64_t        nsec;

				clock_get_uptime(&now);
				SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
				absolutetime_to_nanoseconds(now, &nsec);
				DLOG("dark wake promotion disabled at %u ms\n",
				    ((int)((nsec) / NSEC_PER_MSEC)));
			}
			darkWakePowerClamped = true;
		}
	}
}

//******************************************************************************
// sleepOnClamshellClosed
//
// contains the logic to determine if the system should sleep when the clamshell
// is closed.
//******************************************************************************

bool
IOPMrootDomain::shouldSleepOnClamshellClosed( void )
{
	if (!clamshellExists) {
		return false;
	}

	DLOG("clamshell closed %d, disabled %d/%x, desktopMode %d, ac %d\n",
	    clamshellClosed, clamshellDisabled, clamshellSleepDisableMask, desktopMode, acAdaptorConnected);

	return !clamshellDisabled && !(desktopMode && acAdaptorConnected) && !clamshellSleepDisableMask;
}

bool
IOPMrootDomain::shouldSleepOnRTCAlarmWake( void )
{
	// Called once every RTC/Alarm wake. Device should go to sleep if on clamshell
	// closed && battery
	if (!clamshellExists) {
		return false;
	}

	DLOG("shouldSleepOnRTCAlarmWake: clamshell closed %d, disabled %d/%x, desktopMode %d, ac %d\n",
	    clamshellClosed, clamshellDisabled, clamshellSleepDisableMask, desktopMode, acAdaptorConnected);

	return !acAdaptorConnected && !clamshellSleepDisableMask;
}

void
IOPMrootDomain::sendClientClamshellNotification( void )
{
	/* Only broadcast clamshell alert if clamshell exists. */
	if (!clamshellExists) {
		return;
	}

	setProperty(kAppleClamshellStateKey,
	    clamshellClosed ? kOSBooleanTrue : kOSBooleanFalse);

	setProperty(kAppleClamshellCausesSleepKey,
	    shouldSleepOnClamshellClosed() ? kOSBooleanTrue : kOSBooleanFalse);

	/* Argument to message is a bitfiel of
	 *      ( kClamshellStateBit | kClamshellSleepBit )
	 */
	messageClients(kIOPMMessageClamshellStateChange,
	    (void *)(uintptr_t) ((clamshellClosed ? kClamshellStateBit : 0)
	    | (shouldSleepOnClamshellClosed() ? kClamshellSleepBit : 0)));
}

//******************************************************************************
// getSleepSupported
//
// Deprecated
//******************************************************************************

IOOptionBits
IOPMrootDomain::getSleepSupported( void )
{
	return platformSleepSupport;
}

//******************************************************************************
// setSleepSupported
//
// Deprecated
//******************************************************************************

void
IOPMrootDomain::setSleepSupported( IOOptionBits flags )
{
	DLOG("setSleepSupported(%x)\n", (uint32_t) flags);
	OSBitOrAtomic(flags, &platformSleepSupport);
}

//******************************************************************************
// setClamShellSleepDisable
//
//******************************************************************************

void
IOPMrootDomain::setClamShellSleepDisable( bool disable, uint32_t bitmask )
{
	uint32_t oldMask;

	// User client calls this in non-gated context
	if (gIOPMWorkLoop->inGate() == false) {
		gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(IOWorkLoop::Action, this,
			&IOPMrootDomain::setClamShellSleepDisable),
			(OSObject *) this,
			(void *) disable, (void *)(uintptr_t) bitmask);
		return;
	}

	oldMask = clamshellSleepDisableMask;
	if (disable) {
		clamshellSleepDisableMask |= bitmask;
	} else {
		clamshellSleepDisableMask &= ~bitmask;
	}
	DLOG("setClamShellSleepDisable(%x->%x)\n", oldMask, clamshellSleepDisableMask);

	if (clamshellExists && clamshellClosed &&
	    (clamshellSleepDisableMask != oldMask) &&
	    (clamshellSleepDisableMask == 0)) {
		handlePowerNotification(kLocalEvalClamshellCommand);
	}
}

//******************************************************************************
// wakeFromDoze
//
// Deprecated.
//******************************************************************************

void
IOPMrootDomain::wakeFromDoze( void )
{
	// Preserve symbol for familes (IOUSBFamily and IOGraphics)
}

//******************************************************************************
// recordRTCAlarm
//
// Record the earliest scheduled RTC alarm to determine whether a RTC wake
// should be a dark wake or a full wake. Both Maintenance and SleepService
// alarms are dark wake, while AutoWake (WakeByCalendarDate) and DebugWake
// (WakeRelativeToSleep) should trigger a full wake. Scheduled power-on
// PMSettings are ignored.
//
// Caller serialized using settingsCtrlLock.
//******************************************************************************

void
IOPMrootDomain::recordRTCAlarm(
	const OSSymbol  *type,
	OSObject        *object )
{
	uint32_t previousAlarmMask = _scheduledAlarmMask;

	if (type == gIOPMSettingDebugWakeRelativeKey) {
		OSNumber * n = OSDynamicCast(OSNumber, object);
		if (n) {
			// Debug wake has highest scheduling priority so it overrides any
			// pre-existing alarm.
			uint32_t debugSecs = n->unsigned32BitValue();
			_nextScheduledAlarmType.reset(type, OSRetain);
			_nextScheduledAlarmUTC = debugSecs;

			_debugWakeSeconds = debugSecs;
			OSBitOrAtomic(kIOPMAlarmBitDebugWake, &_scheduledAlarmMask);
			DLOG("next alarm (%s) in %u secs\n",
			    type->getCStringNoCopy(), debugSecs);
		}
	} else if ((type == gIOPMSettingAutoWakeCalendarKey.get()) ||
	    (type == gIOPMSettingMaintenanceWakeCalendarKey.get()) ||
	    (type == gIOPMSettingSleepServiceWakeCalendarKey.get())) {
		OSData * data = OSDynamicCast(OSData, object);
		if (data && (data->getLength() == sizeof(IOPMCalendarStruct))) {
			const IOPMCalendarStruct * cs;
			bool replaceNextAlarm = false;
			clock_sec_t secs;

			cs = (const IOPMCalendarStruct *) data->getBytesNoCopy();
			secs = IOPMConvertCalendarToSeconds(cs);
			DLOG("%s " YMDTF "\n", type->getCStringNoCopy(), YMDT(cs));

			// Update the next scheduled alarm type
			if ((_nextScheduledAlarmType == NULL) ||
			    ((_nextScheduledAlarmType != gIOPMSettingDebugWakeRelativeKey) &&
			    (secs < _nextScheduledAlarmUTC))) {
				replaceNextAlarm = true;
			}

			if (type == gIOPMSettingAutoWakeCalendarKey.get()) {
				if (cs->year) {
					_calendarWakeAlarmUTC = IOPMConvertCalendarToSeconds(cs);
					OSBitOrAtomic(kIOPMAlarmBitCalendarWake, &_scheduledAlarmMask);
				} else {
					// TODO: can this else-block be removed?
					_calendarWakeAlarmUTC = 0;
					OSBitAndAtomic(~kIOPMAlarmBitCalendarWake, &_scheduledAlarmMask);
				}
			}
			if (type == gIOPMSettingMaintenanceWakeCalendarKey.get()) {
				OSBitOrAtomic(kIOPMAlarmBitMaintenanceWake, &_scheduledAlarmMask);
			}
			if (type == gIOPMSettingSleepServiceWakeCalendarKey.get()) {
				OSBitOrAtomic(kIOPMAlarmBitSleepServiceWake, &_scheduledAlarmMask);
			}

			if (replaceNextAlarm) {
				_nextScheduledAlarmType.reset(type, OSRetain);
				_nextScheduledAlarmUTC = secs;
				DLOG("next alarm (%s) " YMDTF "\n", type->getCStringNoCopy(), YMDT(cs));
			}
		}
	}

	if (_scheduledAlarmMask != previousAlarmMask) {
		DLOG("scheduled alarm mask 0x%x\n", (uint32_t) _scheduledAlarmMask);
	}
}

// MARK: -
// MARK: Features

//******************************************************************************
// publishFeature
//
// Adds a new feature to the supported features dictionary
//******************************************************************************

void
IOPMrootDomain::publishFeature( const char * feature )
{
	publishFeature(feature, kRD_AllPowerSources, NULL);
}

//******************************************************************************
// publishFeature (with supported power source specified)
//
// Adds a new feature to the supported features dictionary
//******************************************************************************

void
IOPMrootDomain::publishFeature(
	const char *feature,
	uint32_t supportedWhere,
	uint32_t *uniqueFeatureID)
{
	static uint16_t       next_feature_id = 500;

	OSSharedPtr<OSNumber> new_feature_data;
	OSNumber             *existing_feature = NULL;
	OSArray              *existing_feature_arr_raw = NULL;
	OSSharedPtr<OSArray>  existing_feature_arr;
	OSObject             *osObj = NULL;
	uint32_t              feature_value = 0;

	supportedWhere &= kRD_AllPowerSources; // mask off any craziness!

	if (!supportedWhere) {
		// Feature isn't supported anywhere!
		return;
	}

	if (next_feature_id > 5000) {
		// Far, far too many features!
		return;
	}

	if (featuresDictLock) {
		IOLockLock(featuresDictLock);
	}

	OSSharedPtr<OSObject> origFeaturesProp = copyProperty(kRootDomainSupportedFeatures);
	OSDictionary *origFeatures = OSDynamicCast(OSDictionary, origFeaturesProp.get());
	OSSharedPtr<OSDictionary> features;

	// Create new features dict if necessary
	if (origFeatures) {
		features = OSDictionary::withDictionary(origFeatures);
	} else {
		features = OSDictionary::withCapacity(1);
	}

	// Create OSNumber to track new feature

	next_feature_id += 1;
	if (uniqueFeatureID) {
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
	if ((osObj = features->getObject(feature))) {
		if ((existing_feature = OSDynamicCast(OSNumber, osObj))) {
			// We need to create an OSArray to hold the now 2 elements.
			existing_feature_arr = OSArray::withObjects(
				(const OSObject **)&existing_feature, 1, 2);
		} else if ((existing_feature_arr_raw = OSDynamicCast(OSArray, osObj))) {
			// Add object to existing array
			existing_feature_arr = OSArray::withArray(
				existing_feature_arr_raw,
				existing_feature_arr_raw->getCount() + 1);
		}

		if (existing_feature_arr) {
			existing_feature_arr->setObject(new_feature_data.get());
			features->setObject(feature, existing_feature_arr.get());
		}
	} else {
		// The easy case: no previously existing features listed. We simply
		// set the OSNumber at key 'feature' and we're on our way.
		features->setObject(feature, new_feature_data.get());
	}

	setProperty(kRootDomainSupportedFeatures, features.get());

	if (featuresDictLock) {
		IOLockUnlock(featuresDictLock);
	}

	// Notify EnergySaver and all those in user space so they might
	// re-populate their feature specific UI
	if (pmPowerStateQueue) {
		pmPowerStateQueue->submitPowerEvent( kPowerEventFeatureChanged );
	}
}

//******************************************************************************
// removePublishedFeature
//
// Removes previously published feature
//******************************************************************************

IOReturn
IOPMrootDomain::removePublishedFeature( uint32_t removeFeatureID )
{
	IOReturn                ret = kIOReturnError;
	uint32_t                feature_value = 0;
	uint16_t                feature_id = 0;
	bool                    madeAChange = false;

	OSSymbol                *dictKey = NULL;
	OSSharedPtr<OSCollectionIterator>    dictIterator;
	OSArray                 *arrayMember  = NULL;
	OSNumber                *numberMember = NULL;
	OSObject                *osObj        = NULL;
	OSNumber                *osNum        = NULL;
	OSSharedPtr<OSArray>    arrayMemberCopy;

	if (kBadPMFeatureID == removeFeatureID) {
		return kIOReturnNotFound;
	}

	if (featuresDictLock) {
		IOLockLock(featuresDictLock);
	}

	OSSharedPtr<OSObject> origFeaturesProp = copyProperty(kRootDomainSupportedFeatures);
	OSDictionary *origFeatures = OSDynamicCast(OSDictionary, origFeaturesProp.get());
	OSSharedPtr<OSDictionary> features;

	if (origFeatures) {
		// Any modifications to the dictionary are made to the copy to prevent
		// races & crashes with userland clients. Dictionary updated
		// automically later.
		features = OSDictionary::withDictionary(origFeatures);
	} else {
		features = NULL;
		ret = kIOReturnNotFound;
		goto exit;
	}

	// We iterate 'features' dictionary looking for an entry tagged
	// with 'removeFeatureID'. If found, we remove it from our tracking
	// structures and notify the OS via a general interest message.

	dictIterator = OSCollectionIterator::withCollection(features.get());
	if (!dictIterator) {
		goto exit;
	}

	while ((dictKey = OSDynamicCast(OSSymbol, dictIterator->getNextObject()))) {
		osObj = features->getObject(dictKey);

		// Each Feature is either tracked by an OSNumber
		if (osObj && (numberMember = OSDynamicCast(OSNumber, osObj))) {
			feature_value = numberMember->unsigned32BitValue();
			feature_id = (uint16_t)(feature_value >> 16);

			if (feature_id == (uint16_t)removeFeatureID) {
				// Remove this node
				features->removeObject(dictKey);
				madeAChange = true;
				break;
			}

			// Or tracked by an OSArray of OSNumbers
		} else if (osObj && (arrayMember = OSDynamicCast(OSArray, osObj))) {
			unsigned int arrayCount = arrayMember->getCount();

			for (unsigned int i = 0; i < arrayCount; i++) {
				osNum = OSDynamicCast(OSNumber, arrayMember->getObject(i));
				if (!osNum) {
					continue;
				}

				feature_value = osNum->unsigned32BitValue();
				feature_id = (uint16_t)(feature_value >> 16);

				if (feature_id == (uint16_t)removeFeatureID) {
					// Remove this node
					if (1 == arrayCount) {
						// If the array only contains one element, remove
						// the whole thing.
						features->removeObject(dictKey);
					} else {
						// Otherwise remove the element from a copy of the array.
						arrayMemberCopy = OSArray::withArray(arrayMember);
						if (arrayMemberCopy) {
							arrayMemberCopy->removeObject(i);
							features->setObject(dictKey, arrayMemberCopy.get());
						}
					}

					madeAChange = true;
					break;
				}
			}
		}
	}

	if (madeAChange) {
		ret = kIOReturnSuccess;

		setProperty(kRootDomainSupportedFeatures, features.get());

		// Notify EnergySaver and all those in user space so they might
		// re-populate their feature specific UI
		if (pmPowerStateQueue) {
			pmPowerStateQueue->submitPowerEvent( kPowerEventFeatureChanged );
		}
	} else {
		ret = kIOReturnNotFound;
	}

exit:
	if (featuresDictLock) {
		IOLockUnlock(featuresDictLock);
	}
	return ret;
}

//******************************************************************************
// publishPMSetting (private)
//
// Should only be called by PMSettingObject to publish a PM Setting as a
// supported feature.
//******************************************************************************

void
IOPMrootDomain::publishPMSetting(
	const OSSymbol * feature, uint32_t where, uint32_t * featureID )
{
	if (noPublishPMSettings &&
	    (noPublishPMSettings->getNextIndexOfObject(feature, 0) != (unsigned int)-1)) {
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

IOReturn
IOPMrootDomain::setPMSetting(
	const OSSymbol  *type,
	OSObject        *object )
{
	PMSettingCallEntry  *entries = NULL;
	OSSharedPtr<OSArray>    chosen;
	const OSArray       *array;
	PMSettingObject     *pmso;
	thread_t            thisThread;
	int                 i, j, count, capacity;
	bool                ok = false;
	IOReturn            ret;

	if (NULL == type) {
		return kIOReturnBadArgument;
	}

	PMSETTING_LOCK();

	// Update settings dict so changes are visible from copyPMSetting().
	fPMSettingsDict->setObject(type, object);

	// Prep all PMSetting objects with the given 'type' for callout.
	array = OSDynamicCast(OSArray, settingsCallbacks->getObject(type));
	if (!array || ((capacity = array->getCount()) == 0)) {
		goto unlock_exit;
	}

	// Array to retain PMSetting objects targeted for callout.
	chosen = OSArray::withCapacity(capacity);
	if (!chosen) {
		goto unlock_exit; // error
	}
	entries = IONew(PMSettingCallEntry, capacity);
	if (!entries) {
		goto unlock_exit; // error
	}
	memset(entries, 0, sizeof(PMSettingCallEntry) * capacity);

	thisThread = current_thread();

	for (i = 0, j = 0; i < capacity; i++) {
		pmso = (PMSettingObject *) array->getObject(i);
		if (pmso->disabled) {
			continue;
		}
		entries[j].thread = thisThread;
		queue_enter(&pmso->calloutQueue, &entries[j], PMSettingCallEntry *, link);
		chosen->setObject(pmso);
		j++;
	}
	count = j;
	if (!count) {
		goto unlock_exit;
	}

	PMSETTING_UNLOCK();

	// Call each pmso in the chosen array.
	for (i = 0; i < count; i++) {
		pmso = (PMSettingObject *) chosen->getObject(i);
		ret = pmso->dispatchPMSetting(type, object);
		if (ret == kIOReturnSuccess) {
			// At least one setting handler was successful
			ok = true;
#if DEVELOPMENT || DEBUG
		} else {
			// Log the handler and kext that failed
			OSSharedPtr<const OSSymbol> kextName = copyKextIdentifierWithAddress((vm_address_t) pmso->func);
			if (kextName) {
				DLOG("PMSetting(%s) error 0x%x from %s\n",
				    type->getCStringNoCopy(), ret, kextName->getCStringNoCopy());
			}
#endif
		}
	}

	PMSETTING_LOCK();
	for (i = 0; i < count; i++) {
		pmso = (PMSettingObject *) chosen->getObject(i);
		queue_remove(&pmso->calloutQueue, &entries[i], PMSettingCallEntry *, link);
		if (pmso->waitThread) {
			PMSETTING_WAKEUP(pmso);
		}
	}

	if (ok) {
		recordRTCAlarm(type, object);
	}
unlock_exit:
	PMSETTING_UNLOCK();

	if (entries) {
		IODelete(entries, PMSettingCallEntry, capacity);
	}

	return kIOReturnSuccess;
}

//******************************************************************************
// copyPMSetting (public)
//
// Allows kexts to safely read setting values, without being subscribed to
// notifications.
//******************************************************************************

OSSharedPtr<OSObject>
IOPMrootDomain::copyPMSetting(
	OSSymbol *whichSetting)
{
	OSSharedPtr<OSObject> obj;

	if (!whichSetting) {
		return NULL;
	}

	PMSETTING_LOCK();
	obj.reset(fPMSettingsDict->getObject(whichSetting), OSRetain);
	PMSETTING_UNLOCK();

	return obj;
}

//******************************************************************************
// registerPMSettingController (public)
//
// direct wrapper to registerPMSettingController with uint32_t power source arg
//******************************************************************************

IOReturn
IOPMrootDomain::registerPMSettingController(
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

IOReturn
IOPMrootDomain::registerPMSettingController(
	const OSSymbol *                settings[],
	uint32_t                        supportedPowerSources,
	IOPMSettingControllerCallback   func,
	OSObject                        *target,
	uintptr_t                       refcon,
	OSObject                        **handle)
{
	PMSettingObject *pmso = NULL;
	OSObject        *pmsh = NULL;
	int             i;

	if (NULL == settings ||
	    NULL == func ||
	    NULL == handle) {
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
	for (i = 0; settings[i]; i++) {
		OSSharedPtr<OSArray> newList;
		OSArray *list = OSDynamicCast(OSArray, settingsCallbacks->getObject(settings[i]));
		if (!list) {
			// New array of callbacks for this setting
			newList = OSArray::withCapacity(1);
			settingsCallbacks->setObject(settings[i], newList.get());
			list = newList.get();
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

void
IOPMrootDomain::deregisterPMSettingObject( PMSettingObject * pmso )
{
	thread_t                thisThread = current_thread();
	PMSettingCallEntry      *callEntry;
	OSSharedPtr<OSCollectionIterator>    iter;
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
			if (callEntry->thread != thisThread) {
				wait = true;
				break;
			}
		}
		if (wait) {
			assert(NULL == pmso->waitThread);
			pmso->waitThread = thisThread;
			PMSETTING_WAIT(pmso);
			pmso->waitThread = NULL;
		}
	} while (wait);

	// Search each PM settings array in the kernel.
	iter = OSCollectionIterator::withCollection(settingsCallbacks.get());
	if (iter) {
		while ((sym = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			array = OSDynamicCast(OSArray, settingsCallbacks->getObject(sym));
			index = array->getNextIndexOfObject(pmso, 0);
			if (-1 != index) {
				array->removeObject(index);
			}
		}
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

void
IOPMrootDomain::informCPUStateChange(
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
	strlcpy((char *)varInfoStruct.varName,
	    (const char *)varNameStr,
	    sizeof(varInfoStruct.varName));

	// Set!
	pmCPUret = pmCPUControl( PMIOCSETVARINFO, (void *)&varInfoStruct );

	// pmCPU only assigns numerical id's when a new varName is specified
	if ((0 == pmCPUret)
	    && (*varIndex == kCPUUnknownIndex)) {
		// pmCPUControl has assigned us a new variable ID.
		// Let's re-read the structure we just SET to learn that ID.
		pmCPUret = pmCPUControl( PMIOCGETVARNAMEINFO, (void *)&varInfoStruct );

		if (0 == pmCPUret) {
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

struct IOPMSystemSleepPolicyEntry {
	uint32_t    factorMask;
	uint32_t    factorBits;
	uint32_t    sleepFlags;
	uint32_t    wakeEvents;
} __attribute__((packed));

struct IOPMSystemSleepPolicyTable {
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
	static const uint32_t sleepTypeAttributes[kIOPMSleepTypeLast] =
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

	if (sleepType >= kIOPMSleepTypeLast) {
		return 0;
	}

	return sleepTypeAttributes[sleepType];
}

bool
IOPMrootDomain::evaluateSystemSleepPolicy(
	IOPMSystemSleepParameters * params, int sleepPhase, uint32_t * hibMode )
{
#define SLEEP_FACTOR(x) {(uint32_t) kIOPMSleepFactor ## x, #x}

	static const IONamedValue factorValues[] = {
		SLEEP_FACTOR( SleepTimerWake ),
		SLEEP_FACTOR( LidOpen ),
		SLEEP_FACTOR( ACPower ),
		SLEEP_FACTOR( BatteryLow ),
		SLEEP_FACTOR( StandbyNoDelay ),
		SLEEP_FACTOR( StandbyForced ),
		SLEEP_FACTOR( StandbyDisabled ),
		SLEEP_FACTOR( USBExternalDevice ),
		SLEEP_FACTOR( BluetoothHIDDevice ),
		SLEEP_FACTOR( ExternalMediaMounted ),
		SLEEP_FACTOR( ThunderboltDevice ),
		SLEEP_FACTOR( RTCAlarmScheduled ),
		SLEEP_FACTOR( MagicPacketWakeEnabled ),
		SLEEP_FACTOR( HibernateForced ),
		SLEEP_FACTOR( AutoPowerOffDisabled ),
		SLEEP_FACTOR( AutoPowerOffForced ),
		SLEEP_FACTOR( ExternalDisplay ),
		SLEEP_FACTOR( NetworkKeepAliveActive ),
		SLEEP_FACTOR( LocalUserActivity ),
		SLEEP_FACTOR( HibernateFailed ),
		SLEEP_FACTOR( ThermalWarning ),
		SLEEP_FACTOR( DisplayCaptured ),
		{ 0, NULL }
	};

	const IOPMSystemSleepPolicyTable * pt;
	OSSharedPtr<OSObject>  prop;
	OSData *    policyData;
	uint64_t    currentFactors = 0;
	char        currentFactorsBuf[512];
	uint32_t    standbyDelay   = 0;
	uint32_t    powerOffDelay  = 0;
	uint32_t    powerOffTimer  = 0;
	uint32_t    standbyTimer  = 0;
	uint32_t    mismatch;
	bool        standbyEnabled;
	bool        powerOffEnabled;
	bool        found = false;

	// Get platform's sleep policy table
	if (!gSleepPolicyHandler) {
		prop = getServiceRoot()->copyProperty(kIOPlatformSystemSleepPolicyKey);
		if (!prop) {
			goto done;
		}
	}

	// Fetch additional settings
	standbyEnabled = (getSleepOption(kIOPMDeepSleepDelayKey, &standbyDelay)
	    && propertyHasValue(kIOPMDeepSleepEnabledKey, kOSBooleanTrue));
	powerOffEnabled = (getSleepOption(kIOPMAutoPowerOffDelayKey, &powerOffDelay)
	    && propertyHasValue(kIOPMAutoPowerOffEnabledKey, kOSBooleanTrue));
	if (!getSleepOption(kIOPMAutoPowerOffTimerKey, &powerOffTimer)) {
		powerOffTimer = powerOffDelay;
	}
	if (!getSleepOption(kIOPMDeepSleepTimerKey, &standbyTimer)) {
		standbyTimer = standbyDelay;
	}

	DLOG("phase %d, standby %d delay %u timer %u, poweroff %d delay %u timer %u, hibernate 0x%x\n",
	    sleepPhase, standbyEnabled, standbyDelay, standbyTimer,
	    powerOffEnabled, powerOffDelay, powerOffTimer, *hibMode);

	currentFactorsBuf[0] = 0;
	// pmset level overrides
	if ((*hibMode & kIOHibernateModeOn) == 0) {
		if (!gSleepPolicyHandler) {
			standbyEnabled  = false;
			powerOffEnabled = false;
		}
	} else if (!(*hibMode & kIOHibernateModeSleep)) {
		// Force hibernate (i.e. mode 25)
		// If standby is enabled, force standy.
		// If poweroff is enabled, force poweroff.
		if (standbyEnabled) {
			currentFactors |= kIOPMSleepFactorStandbyForced;
		} else if (powerOffEnabled) {
			currentFactors |= kIOPMSleepFactorAutoPowerOffForced;
		} else {
			currentFactors |= kIOPMSleepFactorHibernateForced;
		}
	}

	// Current factors based on environment and assertions
	if (sleepTimerMaintenance) {
		currentFactors |= kIOPMSleepFactorSleepTimerWake;
	}
	if (standbyEnabled && sleepToStandby && !gSleepPolicyHandler) {
		currentFactors |= kIOPMSleepFactorSleepTimerWake;
	}
	if (!clamshellClosed) {
		currentFactors |= kIOPMSleepFactorLidOpen;
	}
	if (acAdaptorConnected) {
		currentFactors |= kIOPMSleepFactorACPower;
	}
	if (lowBatteryCondition) {
		hibernateMode = 0;
		getSleepOption(kIOHibernateModeKey, &hibernateMode);
		if ((hibernateMode & kIOHibernateModeOn) == 0) {
			DLOG("HibernateMode is 0. Not sending LowBattery factor to IOPPF\n");
		} else {
			currentFactors |= kIOPMSleepFactorBatteryLow;
		}
	}
	if (!standbyDelay || !standbyTimer) {
		currentFactors |= kIOPMSleepFactorStandbyNoDelay;
	}
	if (standbyNixed || !standbyEnabled) {
		currentFactors |= kIOPMSleepFactorStandbyDisabled;
	}
	if (resetTimers) {
		currentFactors |= kIOPMSleepFactorLocalUserActivity;
		currentFactors &= ~kIOPMSleepFactorSleepTimerWake;
	}
	if (getPMAssertionLevel(kIOPMDriverAssertionUSBExternalDeviceBit) !=
	    kIOPMDriverAssertionLevelOff) {
		currentFactors |= kIOPMSleepFactorUSBExternalDevice;
	}
	if (getPMAssertionLevel(kIOPMDriverAssertionBluetoothHIDDevicePairedBit) !=
	    kIOPMDriverAssertionLevelOff) {
		currentFactors |= kIOPMSleepFactorBluetoothHIDDevice;
	}
	if (getPMAssertionLevel(kIOPMDriverAssertionExternalMediaMountedBit) !=
	    kIOPMDriverAssertionLevelOff) {
		currentFactors |= kIOPMSleepFactorExternalMediaMounted;
	}
	if (getPMAssertionLevel(kIOPMDriverAssertionReservedBit5) !=
	    kIOPMDriverAssertionLevelOff) {
		currentFactors |= kIOPMSleepFactorThunderboltDevice;
	}
	if (_scheduledAlarmMask != 0) {
		currentFactors |= kIOPMSleepFactorRTCAlarmScheduled;
	}
	if (getPMAssertionLevel(kIOPMDriverAssertionMagicPacketWakeEnabledBit) !=
	    kIOPMDriverAssertionLevelOff) {
		currentFactors |= kIOPMSleepFactorMagicPacketWakeEnabled;
	}
#define TCPKEEPALIVE 1
#if TCPKEEPALIVE
	if (getPMAssertionLevel(kIOPMDriverAssertionNetworkKeepAliveActiveBit) !=
	    kIOPMDriverAssertionLevelOff) {
		currentFactors |= kIOPMSleepFactorNetworkKeepAliveActive;
	}
#endif
	if (!powerOffEnabled) {
		currentFactors |= kIOPMSleepFactorAutoPowerOffDisabled;
	}
	if (desktopMode) {
		currentFactors |= kIOPMSleepFactorExternalDisplay;
	}
	if (userWasActive) {
		currentFactors |= kIOPMSleepFactorLocalUserActivity;
	}
	if (darkWakeHibernateError && !CAP_HIGHEST(kIOPMSystemCapabilityGraphics)) {
		currentFactors |= kIOPMSleepFactorHibernateFailed;
	}
	if (thermalWarningState) {
		currentFactors |= kIOPMSleepFactorThermalWarning;
	}

	for (int factorBit = 0; factorBit < (8 * sizeof(uint32_t)); factorBit++) {
		uint32_t factor = 1 << factorBit;
		if (factor & currentFactors) {
			strlcat(currentFactorsBuf, ", ", sizeof(currentFactorsBuf));
			strlcat(currentFactorsBuf, IOFindNameForValue(factor, factorValues), sizeof(currentFactorsBuf));
		}
	}
	DLOG("sleep factors 0x%llx%s\n", currentFactors, currentFactorsBuf);

	if (gSleepPolicyHandler) {
		uint32_t    savedHibernateMode;
		IOReturn    result;

		if (!gSleepPolicyVars) {
			gSleepPolicyVars = IONew(IOPMSystemSleepPolicyVariables, 1);
			if (!gSleepPolicyVars) {
				goto done;
			}
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
		gSleepPolicyVars->standbyTimer      = standbyTimer;
		gSleepPolicyVars->poweroffDelay     = powerOffDelay;
		gSleepPolicyVars->scheduledAlarms   = _scheduledAlarmMask | _userScheduledAlarmMask;
		gSleepPolicyVars->poweroffTimer     = powerOffTimer;

		if (kIOPMSleepPhase0 == sleepPhase) {
			// preserve hibernateMode
			savedHibernateMode = gSleepPolicyVars->hibernateMode;
			gSleepPolicyVars->hibernateMode = *hibMode;
		} else if (kIOPMSleepPhase1 == sleepPhase) {
			// use original hibernateMode for phase2
			gSleepPolicyVars->hibernateMode = *hibMode;
		}

		result = gSleepPolicyHandler(gSleepPolicyTarget, gSleepPolicyVars, params);

		if (kIOPMSleepPhase0 == sleepPhase) {
			// restore hibernateMode
			gSleepPolicyVars->hibernateMode = savedHibernateMode;
		}

		if ((result != kIOReturnSuccess) ||
		    (kIOPMSleepTypeInvalid == params->sleepType) ||
		    (params->sleepType >= kIOPMSleepTypeLast) ||
		    (kIOPMSystemSleepParametersVersion != params->version)) {
			MSG("sleep policy handler error\n");
			goto done;
		}

		if ((getSleepTypeAttributes(params->sleepType) &
		    kIOPMSleepAttributeHibernateSetup) &&
		    ((*hibMode & kIOHibernateModeOn) == 0)) {
			*hibMode |= (kIOHibernateModeOn | kIOHibernateModeSleep);
		}

		DLOG("sleep params v%u, type %u, flags 0x%x, wake 0x%x, timer %u, poweroff %u\n",
		    params->version, params->sleepType, params->sleepFlags,
		    params->ecWakeEvents, params->ecWakeTimer, params->ecPoweroffTimer);
		found = true;
		goto done;
	}

	// Policy table is meaningless without standby enabled
	if (!standbyEnabled) {
		goto done;
	}

	// Validate the sleep policy table
	policyData = OSDynamicCast(OSData, prop.get());
	if (!policyData || (policyData->getLength() <= sizeof(IOPMSystemSleepPolicyTable))) {
		goto done;
	}

	pt = (const IOPMSystemSleepPolicyTable *) policyData->getBytesNoCopy();
	if ((pt->signature != kIOPMSystemSleepPolicySignature) ||
	    (pt->version != 1) || (0 == pt->entryCount)) {
		goto done;
	}

	if (((policyData->getLength() - sizeof(IOPMSystemSleepPolicyTable)) !=
	    (sizeof(IOPMSystemSleepPolicyEntry) * pt->entryCount))) {
		goto done;
	}

	for (uint32_t i = 0; i < pt->entryCount; i++) {
		const IOPMSystemSleepPolicyEntry * entry = &pt->entries[i];
		mismatch = (((uint32_t)currentFactors ^ entry->factorBits) & entry->factorMask);

		DLOG("mask 0x%08x, bits 0x%08x, flags 0x%08x, wake 0x%08x, mismatch 0x%08x\n",
		    entry->factorMask, entry->factorBits,
		    entry->sleepFlags, entry->wakeEvents, mismatch);
		if (mismatch) {
			continue;
		}

		DLOG("^ found match\n");
		found = true;

		params->version = kIOPMSystemSleepParametersVersion;
		params->reserved1 = 1;
		if (entry->sleepFlags & kIOPMSleepFlagHibernate) {
			params->sleepType = kIOPMSleepTypeStandby;
		} else {
			params->sleepType = kIOPMSleepTypeNormalSleep;
		}

		params->ecWakeEvents = entry->wakeEvents;
		if (entry->sleepFlags & kIOPMSleepFlagSleepTimerEnable) {
			if (kIOPMSleepPhase2 == sleepPhase) {
				clock_sec_t now_secs = gIOLastSleepTime.tv_sec;

				if (!_standbyTimerResetSeconds ||
				    (now_secs <= _standbyTimerResetSeconds)) {
					// Reset standby timer adjustment
					_standbyTimerResetSeconds = now_secs;
					DLOG("standby delay %u, reset %u\n",
					    standbyDelay, (uint32_t) _standbyTimerResetSeconds);
				} else if (standbyDelay) {
					// Shorten the standby delay timer
					clock_sec_t elapsed = now_secs - _standbyTimerResetSeconds;
					if (standbyDelay > elapsed) {
						standbyDelay -= elapsed;
					} else {
						standbyDelay = 1; // must be > 0
					}
					DLOG("standby delay %u, elapsed %u\n",
					    standbyDelay, (uint32_t) elapsed);
				}
			}
			params->ecWakeTimer = standbyDelay;
		} else if (kIOPMSleepPhase2 == sleepPhase) {
			// A sleep that does not enable the sleep timer will reset
			// the standby delay adjustment.
			_standbyTimerResetSeconds = 0;
		}
		break;
	}

done:
	return found;
}

static IOPMSystemSleepParameters gEarlySystemSleepParams;

void
IOPMrootDomain::evaluateSystemSleepPolicyEarly( void )
{
	// Evaluate early (priority interest phase), before drivers sleep.

	DLOG("%s\n", __FUNCTION__);
	removeProperty(kIOPMSystemSleepParametersKey);

	// Full wake resets the standby timer delay adjustment
	if (_highestCapability & kIOPMSystemCapabilityGraphics) {
		_standbyTimerResetSeconds = 0;
	}

	hibernateDisabled = false;
	hibernateMode = 0;
	getSleepOption(kIOHibernateModeKey, &hibernateMode);

	// Save for late evaluation if sleep is aborted
	bzero(&gEarlySystemSleepParams, sizeof(gEarlySystemSleepParams));

	if (evaluateSystemSleepPolicy(&gEarlySystemSleepParams, kIOPMSleepPhase1,
	    &hibernateMode)) {
		if (!hibernateRetry &&
		    ((getSleepTypeAttributes(gEarlySystemSleepParams.sleepType) &
		    kIOPMSleepAttributeHibernateSetup) == 0)) {
			// skip hibernate setup
			hibernateDisabled = true;
		}
	}

	// Publish IOPMSystemSleepType
	uint32_t sleepType = gEarlySystemSleepParams.sleepType;
	if (sleepType == kIOPMSleepTypeInvalid) {
		// no sleep policy
		sleepType = kIOPMSleepTypeNormalSleep;
		if (hibernateMode & kIOHibernateModeOn) {
			sleepType = (hibernateMode & kIOHibernateModeSleep) ?
			    kIOPMSleepTypeSafeSleep : kIOPMSleepTypeHibernate;
		}
	} else if ((sleepType == kIOPMSleepTypeStandby) &&
	    (gEarlySystemSleepParams.ecPoweroffTimer)) {
		// report the lowest possible sleep state
		sleepType = kIOPMSleepTypePowerOff;
	}

	setProperty(kIOPMSystemSleepTypeKey, sleepType, 32);
}

void
IOPMrootDomain::evaluateSystemSleepPolicyFinal( void )
{
	IOPMSystemSleepParameters   params;
	OSSharedPtr<OSData>         paramsData;
	bool                        wakeNow;
	// Evaluate sleep policy after sleeping drivers but before platform sleep.

	DLOG("%s\n", __FUNCTION__);

	bzero(&params, sizeof(params));
	wakeNow = false;
	if (evaluateSystemSleepPolicy(&params, kIOPMSleepPhase2, &hibernateMode)) {
		if ((kIOPMSleepTypeStandby == params.sleepType)
		    && gIOHibernateStandbyDisabled && gSleepPolicyVars
		    && (!((kIOPMSleepFactorStandbyForced | kIOPMSleepFactorAutoPowerOffForced | kIOPMSleepFactorHibernateForced)
		    & gSleepPolicyVars->sleepFactors))) {
			standbyNixed = true;
			wakeNow = true;
		}
		if (wakeNow
		    || ((hibernateDisabled || hibernateAborted) &&
		    (getSleepTypeAttributes(params.sleepType) &
		    kIOPMSleepAttributeHibernateSetup))) {
			// Final evaluation picked a state requiring hibernation,
			// but hibernate isn't going to proceed. Arm a short sleep using
			// the early non-hibernate sleep parameters.
			bcopy(&gEarlySystemSleepParams, &params, sizeof(params));
			params.sleepType = kIOPMSleepTypeAbortedSleep;
			params.ecWakeTimer = 1;
			if (standbyNixed) {
				resetTimers = true;
			} else {
				// Set hibernateRetry flag to force hibernate setup on the
				// next sleep.
				hibernateRetry = true;
			}
			DLOG("wake in %u secs for hibernateDisabled %d, hibernateAborted %d, standbyNixed %d\n",
			    params.ecWakeTimer, hibernateDisabled, hibernateAborted, standbyNixed);
		} else {
			hibernateRetry = false;
		}

		if (kIOPMSleepTypeAbortedSleep != params.sleepType) {
			resetTimers = false;
		}

		paramsData = OSData::withBytes(&params, sizeof(params));
		if (paramsData) {
			setProperty(kIOPMSystemSleepParametersKey, paramsData.get());
		}

		if (getSleepTypeAttributes(params.sleepType) &
		    kIOPMSleepAttributeHibernateSleep) {
			// Disable sleep to force hibernation
			gIOHibernateMode &= ~kIOHibernateModeSleep;
		}
	}
}

bool
IOPMrootDomain::getHibernateSettings(
	uint32_t *  hibernateModePtr,
	uint32_t *  hibernateFreeRatio,
	uint32_t *  hibernateFreeTime )
{
	// Called by IOHibernateSystemSleep() after evaluateSystemSleepPolicyEarly()
	// has updated the hibernateDisabled flag.

	bool ok = getSleepOption(kIOHibernateModeKey, hibernateModePtr);
	getSleepOption(kIOHibernateFreeRatioKey, hibernateFreeRatio);
	getSleepOption(kIOHibernateFreeTimeKey, hibernateFreeTime);
	if (hibernateDisabled) {
		*hibernateModePtr = 0;
	} else if (gSleepPolicyHandler) {
		*hibernateModePtr = hibernateMode;
	}
	DLOG("hibernateMode 0x%x\n", *hibernateModePtr);
	return ok;
}

bool
IOPMrootDomain::getSleepOption( const char * key, uint32_t * option )
{
	OSSharedPtr<OSObject>       optionsProp;
	OSDictionary *              optionsDict;
	OSSharedPtr<OSObject>       obj;
	OSNumber *                  num;
	bool                        ok = false;

	optionsProp = copyProperty(kRootDomainSleepOptionsKey);
	optionsDict = OSDynamicCast(OSDictionary, optionsProp.get());

	if (optionsDict) {
		obj.reset(optionsDict->getObject(key), OSRetain);
	}
	if (!obj) {
		obj = copyProperty(key);
	}
	if (obj) {
		if ((num = OSDynamicCast(OSNumber, obj.get()))) {
			*option = num->unsigned32BitValue();
			ok = true;
		} else if (OSDynamicCast(OSBoolean, obj.get())) {
			*option = (obj == kOSBooleanTrue) ? 1 : 0;
			ok = true;
		}
	}

	return ok;
}
#endif /* HIBERNATION */

IOReturn
IOPMrootDomain::getSystemSleepType( uint32_t * sleepType, uint32_t * standbyTimer )
{
#if HIBERNATION
	IOPMSystemSleepParameters   params;
	uint32_t                    hibMode = 0;
	bool                        ok;

	if (gIOPMWorkLoop->inGate() == false) {
		IOReturn ret = gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(IOWorkLoop::Action, this,
			&IOPMrootDomain::getSystemSleepType),
			(OSObject *) this,
			(void *) sleepType, (void *) standbyTimer);
		return ret;
	}

	getSleepOption(kIOHibernateModeKey, &hibMode);
	bzero(&params, sizeof(params));

	ok = evaluateSystemSleepPolicy(&params, kIOPMSleepPhase0, &hibMode);
	if (ok) {
		*sleepType = params.sleepType;
		if (!getSleepOption(kIOPMDeepSleepTimerKey, standbyTimer) &&
		    !getSleepOption(kIOPMDeepSleepDelayKey, standbyTimer)) {
			DLOG("Standby delay is not set\n");
			*standbyTimer = 0;
		}
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

// Phases while performing shutdown/restart
typedef enum {
	kNotifyDone                 = 0x00,
	kNotifyPriorityClients      = 0x10,
	kNotifyPowerPlaneDrivers    = 0x20,
	kNotifyHaltRestartAction    = 0x30,
	kQuiescePM                  = 0x40,
} shutdownPhase_t;


struct HaltRestartApplierContext {
	IOPMrootDomain *    RootDomain;
	unsigned long       PowerState;
	IOPMPowerFlags      PowerFlags;
	UInt32              MessageType;
	UInt32              Counter;
	const char *        LogString;
	shutdownPhase_t     phase;

	IOServiceInterestHandler    handler;
} gHaltRestartCtx;

const char *
shutdownPhase2String(shutdownPhase_t phase)
{
	switch (phase) {
	case kNotifyDone:
		return "Notifications completed";
	case kNotifyPriorityClients:
		return "Notifying priority clients";
	case kNotifyPowerPlaneDrivers:
		return "Notifying power plane drivers";
	case kNotifyHaltRestartAction:
		return "Notifying HaltRestart action handlers";
	case kQuiescePM:
		return "Quiescing PM";
	default:
		return "Unknown";
	}
}

static void
platformHaltRestartApplier( OSObject * object, void * context )
{
	IOPowerStateChangeNotification  notify;
	HaltRestartApplierContext *     ctx;
	AbsoluteTime                    startTime, elapsedTime;
	uint32_t                        deltaTime;

	ctx = (HaltRestartApplierContext *) context;

	_IOServiceInterestNotifier * notifier;
	notifier = OSDynamicCast(_IOServiceInterestNotifier, object);
	memset(&notify, 0, sizeof(notify));
	notify.powerRef    = (void *)(uintptr_t)ctx->Counter;
	notify.returnValue = 0;
	notify.stateNumber = ctx->PowerState;
	notify.stateFlags  = ctx->PowerFlags;

	if (notifier) {
		ctx->handler = notifier->handler;
	}

	clock_get_uptime(&startTime);
	ctx->RootDomain->messageClient( ctx->MessageType, object, (void *)&notify );
	deltaTime = computeDeltaTimeMS(&startTime, &elapsedTime);

	if ((deltaTime > kPMHaltTimeoutMS) && notifier) {
		LOG("%s handler %p took %u ms\n",
		    ctx->LogString, OBFUSCATE(notifier->handler), deltaTime);
		halt_log_enter("PowerOff/Restart message to priority client", (const void *) notifier->handler, elapsedTime);
	}

	ctx->handler = NULL;
	ctx->Counter++;
}

static void
quiescePowerTreeCallback( void * target, void * param )
{
	IOLockLock(gPMHaltLock);
	gPMQuiesced = true;
	thread_wakeup(param);
	IOLockUnlock(gPMHaltLock);
}

void
IOPMrootDomain::handlePlatformHaltRestart( UInt32 pe_type )
{
	AbsoluteTime                startTime, elapsedTime;
	uint32_t                    deltaTime;

	memset(&gHaltRestartCtx, 0, sizeof(gHaltRestartCtx));
	gHaltRestartCtx.RootDomain = this;

	clock_get_uptime(&startTime);
	switch (pe_type) {
	case kPEHaltCPU:
	case kPEUPSDelayHaltCPU:
		gHaltRestartCtx.PowerState  = OFF_STATE;
		gHaltRestartCtx.MessageType = kIOMessageSystemWillPowerOff;
		gHaltRestartCtx.LogString   = "PowerOff";
		break;

	case kPERestartCPU:
		gHaltRestartCtx.PowerState  = RESTART_STATE;
		gHaltRestartCtx.MessageType = kIOMessageSystemWillRestart;
		gHaltRestartCtx.LogString   = "Restart";
		break;

	case kPEPagingOff:
		gHaltRestartCtx.PowerState  = ON_STATE;
		gHaltRestartCtx.MessageType = kIOMessageSystemPagingOff;
		gHaltRestartCtx.LogString   = "PagingOff";
		IOService::updateConsoleUsers(NULL, kIOMessageSystemPagingOff);
#if HIBERNATION
		IOHibernateSystemRestart();
#endif
		break;

	default:
		return;
	}

	gHaltRestartCtx.phase = kNotifyPriorityClients;
	// Notify legacy clients
	applyToInterested(gIOPriorityPowerStateInterest, platformHaltRestartApplier, &gHaltRestartCtx);

	// For normal shutdown, turn off File Server Mode.
	if (kPEHaltCPU == pe_type) {
		OSSharedPtr<const OSSymbol> setting = OSSymbol::withCString(kIOPMSettingRestartOnPowerLossKey);
		OSSharedPtr<OSNumber> num = OSNumber::withNumber((unsigned long long) 0, 32);
		if (setting && num) {
			setPMSetting(setting.get(), num.get());
		}
	}

	if (kPEPagingOff != pe_type) {
		gHaltRestartCtx.phase = kNotifyPowerPlaneDrivers;
		// Notify in power tree order
		notifySystemShutdown(this, gHaltRestartCtx.MessageType);
	}

	gHaltRestartCtx.phase = kNotifyHaltRestartAction;
#if defined(XNU_TARGET_OS_OSX)
	IOCPURunPlatformHaltRestartActions(pe_type);
#else /* !defined(XNU_TARGET_OS_OSX) */
	if (kPEPagingOff != pe_type) {
		IOCPURunPlatformHaltRestartActions(pe_type);
	}
#endif /* !defined(XNU_TARGET_OS_OSX) */

	// Wait for PM to quiesce
	if ((kPEPagingOff != pe_type) && gPMHaltLock) {
		gHaltRestartCtx.phase = kQuiescePM;
		AbsoluteTime quiesceTime = mach_absolute_time();

		IOLockLock(gPMHaltLock);
		gPMQuiesced = false;
		if (quiescePowerTree(this, &quiescePowerTreeCallback, &gPMQuiesced) ==
		    kIOReturnSuccess) {
			while (!gPMQuiesced) {
				IOLockSleep(gPMHaltLock, &gPMQuiesced, THREAD_UNINT);
			}
		}
		IOLockUnlock(gPMHaltLock);
		deltaTime = computeDeltaTimeMS(&quiesceTime, &elapsedTime);
		DLOG("PM quiesce took %u ms\n", deltaTime);
		halt_log_enter("Quiesce", NULL, elapsedTime);
	}
	gHaltRestartCtx.phase = kNotifyDone;

	deltaTime = computeDeltaTimeMS(&startTime, &elapsedTime);
	LOG("%s all drivers took %u ms\n", gHaltRestartCtx.LogString, deltaTime);

	halt_log_enter(gHaltRestartCtx.LogString, NULL, elapsedTime);

	deltaTime = computeDeltaTimeMS(&gHaltStartTime, &elapsedTime);
	LOG("%s total %u ms\n", gHaltRestartCtx.LogString, deltaTime);

	if (gHaltLog && gHaltTimeMaxLog && (deltaTime >= gHaltTimeMaxLog)) {
		printf("%s total %d ms:%s\n", gHaltRestartCtx.LogString, deltaTime, gHaltLog);
	}

	checkShutdownTimeout();
}

bool
IOPMrootDomain::checkShutdownTimeout()
{
	AbsoluteTime   elapsedTime;
	uint32_t deltaTime = computeDeltaTimeMS(&gHaltStartTime, &elapsedTime);

	if (gHaltTimeMaxPanic && (deltaTime >= gHaltTimeMaxPanic)) {
		return true;
	}
	return false;
}

void
IOPMrootDomain::panicWithShutdownLog(uint32_t timeoutInMs)
{
	if (gHaltLog) {
		if ((gHaltRestartCtx.phase == kNotifyPriorityClients) && gHaltRestartCtx.handler) {
			halt_log_enter("Blocked on priority client", (void *)gHaltRestartCtx.handler, mach_absolute_time() - gHaltStartTime);
		}
		panic("%s timed out in phase '%s'. Total %d ms:%s",
		    gHaltRestartCtx.LogString, shutdownPhase2String(gHaltRestartCtx.phase), timeoutInMs, gHaltLog);
	} else {
		panic("%s timed out in phase \'%s\'. Total %d ms",
		    gHaltRestartCtx.LogString, shutdownPhase2String(gHaltRestartCtx.phase), timeoutInMs);
	}
}

//******************************************************************************
// shutdownSystem
//
//******************************************************************************

IOReturn
IOPMrootDomain::shutdownSystem( void )
{
	return kIOReturnUnsupported;
}

//******************************************************************************
// restartSystem
//
//******************************************************************************

IOReturn
IOPMrootDomain::restartSystem( void )
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

void
IOPMrootDomain::tagPowerPlaneService(
	IOService *         service,
	IOPMActions *       actions,
	IOPMPowerStateIndex maxPowerState )
{
	uint32_t    flags = 0;

	memset(actions, 0, sizeof(*actions));
	actions->target = this;

	if (service == this) {
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

#if DISPLAY_WRANGLER_PRESENT
	if (NULL != service->metaCast("IODisplayWrangler")) {
		// XXX should this really retain?
		wrangler.reset(service, OSRetain);
		wrangler->registerInterest(gIOGeneralInterest,
		    &displayWranglerNotification, this, NULL);

		// found the display wrangler, check for any display assertions already created
		if (pmAssertions->getActivatedAssertions() & kIOPMDriverAssertionPreventDisplaySleepBit) {
			DLOG("wrangler setIgnoreIdleTimer\(1) due to pre-existing assertion\n");
			wrangler->setIgnoreIdleTimer( true );
		}
		flags |= kPMActionsFlagIsDisplayWrangler;
	}
#endif /* DISPLAY_WRANGLER_PRESENT */

	if (service->propertyExists("IOPMStrictTreeOrder")) {
		flags |= kPMActionsFlagIsGraphicsDriver;
	}
	if (service->propertyExists("IOPMUnattendedWakePowerState")) {
		flags |= kPMActionsFlagIsAudioDriver;
	}

	OSSharedPtr<OSObject> prop = service->copyProperty(kIOPMDarkWakeMaxPowerStateKey);
	if (prop) {
		OSNumber * num = OSDynamicCast(OSNumber, prop.get());
		if (num) {
			actions->darkWakePowerState = num->unsigned32BitValue();
			if (actions->darkWakePowerState < maxPowerState) {
				flags |= kPMActionsFlagHasDarkWakePowerState;
			}
		}
	}

	// Find the power connection object that is a child of the PCI host
	// bridge, and has a graphics/audio device attached below. Mark the
	// power branch for delayed child notifications.

	if (flags) {
		IORegistryEntry * child  = service;
		IORegistryEntry * parent = child->getParentEntry(gIOPowerPlane);

		while (child != this) {
			if (child->propertyHasValue("IOPCITunnelled", kOSBooleanTrue)) {
				// Skip delaying notifications and clamping power on external graphics and audio devices.
				DLOG("Avoiding delayChildNotification on object 0x%llx. flags: 0x%x\n", service->getRegistryEntryID(), flags);
				flags = 0;
				break;
			}
			if ((parent == pciHostBridgeDriver) ||
			    (parent == this)) {
				if (OSDynamicCast(IOPowerConnection, child)) {
					IOPowerConnection * conn = (IOPowerConnection *) child;
					conn->delayChildNotification = true;
					DLOG("delayChildNotification for 0x%llx\n", conn->getRegistryEntryID());
				}
				break;
			}
			child = parent;
			parent = child->getParentEntry(gIOPowerPlane);
		}
	}

	if (flags) {
		DLOG("%s tag flags %x\n", service->getName(), flags);
		actions->flags |= flags;
		actions->actionPowerChangeOverride =
		    OSMemberFunctionCast(
			IOPMActionPowerChangeOverride, this,
			&IOPMrootDomain::overridePowerChangeForService);

		if (flags & kPMActionsFlagIsDisplayWrangler) {
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
	if (!pciHostBridgeDevice && service->metaCast("IOPCIBridge")) {
		IOService * provider = service->getProvider();
		if (OSDynamicCast(IOPlatformDevice, provider) &&
		    provider->inPlane(gIODTPlane)) {
			pciHostBridgeDevice.reset(provider, OSNoRetain);
			pciHostBridgeDriver.reset(service, OSNoRetain);
			DLOG("PMTrace found PCI host bridge %s->%s\n",
			    provider->getName(), service->getName());
		}
	}

	// Tag top-level PCI devices. The order of PMinit() call does not
	// change across boots and is used as the PCI bit number.
	if (pciHostBridgeDevice && service->metaCast("IOPCIDevice")) {
		// Would prefer to check built-in property, but tagPowerPlaneService()
		// is called before pciDevice->registerService().
		IORegistryEntry * parent = service->getParentEntry(gIODTPlane);
		if ((parent == pciHostBridgeDevice) && service->propertyExists("acpi-device")) {
			int bit = pmTracer->recordTopLevelPCIDevice( service );
			if (bit >= 0) {
				// Save the assigned bit for fast lookup.
				actions->flags |= (bit & kPMActionsPCIBitNumberMask);

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

void
IOPMrootDomain::overrideOurPowerChange(
	IOService *             service,
	IOPMActions *           actions,
	const IOPMRequest *     request,
	IOPMPowerStateIndex *   inOutPowerState,
	IOPMPowerChangeFlags *  inOutChangeFlags )
{
	uint32_t changeFlags = *inOutChangeFlags;
	uint32_t desiredPowerState = (uint32_t) *inOutPowerState;
	uint32_t currentPowerState = (uint32_t) getPowerState();

	if (request->getTag() == 0) {
		// Set a tag for any request that originates from IOServicePM
		(const_cast<IOPMRequest *>(request))->fTag = nextRequestTag(kCPSReasonPMInternals);
	}

	DLOG("PowerChangeOverride (%s->%s, %x, 0x%x) tag 0x%x\n",
	    getPowerStateString(currentPowerState),
	    getPowerStateString(desiredPowerState),
	    _currentCapability, changeFlags,
	    request->getTag());

	if ((AOT_STATE == desiredPowerState) && (ON_STATE == currentPowerState)) {
		// Assertion may have been taken in AOT leading to changePowerStateTo(AOT)
		*inOutChangeFlags |= kIOPMNotDone;
		return;
	}

	if (changeFlags & kIOPMParentInitiated) {
		// Root parent is permanently pegged at max power,
		// a parent initiated power change is unexpected.
		*inOutChangeFlags |= kIOPMNotDone;
		return;
	}

#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
	if (lowBatteryCondition && (desiredPowerState < currentPowerState)) {
		// Reject sleep requests when lowBatteryCondition is TRUE to
		// avoid racing with the impending system shutdown.
		*inOutChangeFlags |= kIOPMNotDone;
		return;
	}
#endif

	if (desiredPowerState < currentPowerState) {
		if (CAP_CURRENT(kIOPMSystemCapabilityGraphics)) {
			// Root domain is dropping power state from ON->SLEEP.
			// If system is in full wake, first enter dark wake by
			// converting the power drop to a capability change.
			// Once in dark wake, transition to sleep state ASAP.

			darkWakeToSleepASAP = true;

			// Drop graphics and audio capability
			_desiredCapability &= ~(
				kIOPMSystemCapabilityGraphics |
				kIOPMSystemCapabilityAudio);

			// Convert to capability change (ON->ON)
			*inOutPowerState = getRUN_STATE();
			*inOutChangeFlags |= kIOPMSynchronize;

			// Revert device desire from SLEEP to ON
			changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonPowerOverride);
		} else {
			// System is already in dark wake, ok to drop power state.
			// Broadcast root power down to entire tree.
			*inOutChangeFlags |= kIOPMRootChangeDown;
		}
	} else if (desiredPowerState > currentPowerState) {
		if ((_currentCapability & kIOPMSystemCapabilityCPU) == 0) {
			// Broadcast power up when waking from sleep, but not for the
			// initial power change at boot by checking for cpu capability.
			*inOutChangeFlags |= kIOPMRootChangeUp;
		}
	}
}

void
IOPMrootDomain::handleOurPowerChangeStart(
	IOService *             service,
	IOPMActions *           actions,
	const IOPMRequest *     request,
	IOPMPowerStateIndex     newPowerState,
	IOPMPowerChangeFlags *  inOutChangeFlags )
{
	IOPMRequestTag requestTag = request->getTag();
	IOPMRequestTag sleepReason;

	uint32_t changeFlags        = *inOutChangeFlags;
	uint32_t currentPowerState  = (uint32_t) getPowerState();
	bool     publishSleepReason = false;

	// Check if request has a valid sleep reason
	sleepReason = REQUEST_TAG_TO_REASON(requestTag);
	if (sleepReason < kIOPMSleepReasonClamshell) {
		sleepReason = kIOPMSleepReasonIdle;
	}

	_systemTransitionType    = kSystemTransitionNone;
	_systemMessageClientMask = 0;
	capabilityLoss           = false;
	toldPowerdCapWillChange  = false;

	// Emergency notifications may arrive after the initial sleep request
	// has been queued. Override the sleep reason so powerd and others can
	// treat this as an emergency sleep.
	if (lowBatteryCondition) {
		sleepReason = kIOPMSleepReasonLowPower;
	} else if (thermalEmergencyState) {
		sleepReason = kIOPMSleepReasonThermalEmergency;
	}

	// 1. Explicit capability change.
	if (changeFlags & kIOPMSynchronize) {
		if (newPowerState == ON_STATE) {
			if (changeFlags & kIOPMSyncNoChildNotify) {
				_systemTransitionType = kSystemTransitionNewCapClient;
			} else {
				_systemTransitionType = kSystemTransitionCapability;
			}
		}
	}
	// 2. Going to sleep (cancellation still possible).
	else if (newPowerState < currentPowerState) {
		_systemTransitionType = kSystemTransitionSleep;
	}
	// 3. Woke from (idle or demand) sleep.
	else if (!systemBooting &&
	    (changeFlags & kIOPMSelfInitiated) &&
	    (newPowerState > currentPowerState)) {
		_systemTransitionType = kSystemTransitionWake;
		_desiredCapability = kIOPMSystemCapabilityCPU | kIOPMSystemCapabilityNetwork;

		// Early exit from dark wake to full (e.g. LID open)
		if (kFullWakeReasonNone != fullWakeReason) {
			_desiredCapability |= (
				kIOPMSystemCapabilityGraphics |
				kIOPMSystemCapabilityAudio);

#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
			if (fullWakeReason == kFullWakeReasonLocalUser) {
				darkWakeExit = true;
				darkWakeToSleepASAP = false;
				setProperty(kIOPMRootDomainWakeTypeKey, isRTCAlarmWake ?
				    kIOPMRootDomainWakeTypeAlarm : kIOPMRootDomainWakeTypeUser);
			}
#endif
		}
#if HIBERNATION
		IOHibernateSetWakeCapabilities(_desiredCapability);
#endif
	}

	// Update pending wake capability at the beginning of every
	// state transition (including synchronize). This will become
	// the current capability at the end of the transition.

	if (kSystemTransitionSleep == _systemTransitionType) {
		_pendingCapability = 0;
		capabilityLoss = true;
	} else if (kSystemTransitionNewCapClient != _systemTransitionType) {
		_pendingCapability = _desiredCapability |
		    kIOPMSystemCapabilityCPU |
		    kIOPMSystemCapabilityNetwork;

		if (_pendingCapability & kIOPMSystemCapabilityGraphics) {
			_pendingCapability |= kIOPMSystemCapabilityAudio;
		}

		if ((kSystemTransitionCapability == _systemTransitionType) &&
		    (_pendingCapability == _currentCapability)) {
			// Cancel the PM state change.
			_systemTransitionType = kSystemTransitionNone;
			*inOutChangeFlags |= kIOPMNotDone;
		}
		if (__builtin_popcount(_pendingCapability) <
		    __builtin_popcount(_currentCapability)) {
			capabilityLoss = true;
		}
	}

	// 1. Capability change.
	if (kSystemTransitionCapability == _systemTransitionType) {
		// Dark to Full transition.
		if (CAP_GAIN(kIOPMSystemCapabilityGraphics)) {
			tracePoint( kIOPMTracePointDarkWakeExit );

#if defined(XNU_TARGET_OS_OSX)
			// rdar://problem/65627936
			// When a dark->full wake promotion is scheduled before an ON->SLEEP
			// power state drop, invalidate any request to drop power state already
			// in the queue, including the override variant, unless full wake cannot
			// be sustained. Any power state drop queued after this SustainFullWake
			// request will not be affected.
			if (checkSystemCanSustainFullWake()) {
				changePowerStateWithOverrideTo(getRUN_STATE(), kCPSReasonSustainFullWake);
			}
#endif

			willEnterFullWake();
		}

		// Full to Dark transition.
		if (CAP_LOSS(kIOPMSystemCapabilityGraphics)) {
			// Clear previous stats
			IOLockLock(pmStatsLock);
			if (pmStatsAppResponses) {
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

			darkWakeExit = false;
		}
	}
	// 2. System sleep.
	else if (kSystemTransitionSleep == _systemTransitionType) {
		// Beginning of a system sleep transition.
		// Cancellation is still possible.
		tracePoint( kIOPMTracePointSleepStarted );

		_systemMessageClientMask = kSystemMessageClientAll;
		if ((_currentCapability & kIOPMSystemCapabilityGraphics) == 0) {
			_systemMessageClientMask &= ~kSystemMessageClientLegacyApp;
		}
		if ((_highestCapability & kIOPMSystemCapabilityGraphics) == 0) {
			// Kernel priority clients are only notified on the initial
			// transition to full wake, so don't notify them unless system
			// has gained graphics capability since the last system wake.
			_systemMessageClientMask &= ~kSystemMessageClientKernel;
		} else {
			// System was in full wake, but the downwards power transition is driven
			// by a request that originates from IOServicePM, so it isn't tagged with
			// a valid system sleep reason.
			if (REQUEST_TAG_TO_REASON(requestTag) == kCPSReasonPMInternals) {
				// Publish the same reason for full to dark
				sleepReason = fullToDarkReason;
			}
		}
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
	else if (kSystemTransitionWake == _systemTransitionType) {
		tracePoint( kIOPMTracePointWakeWillPowerOnClients );
		// Clear stats about sleep

		if (AOT_STATE == newPowerState) {
			_pendingCapability = 0;
		}

		if (AOT_STATE == currentPowerState) {
			// Wake events are no longer accepted after waking to AOT_STATE.
			// Re-enable wake event acceptance to append wake events claimed
			// during the AOT to ON_STATE transition.
			acceptSystemWakeEvents(kAcceptSystemWakeEvents_Reenable);
		}

		if (_pendingCapability & kIOPMSystemCapabilityGraphics) {
			willEnterFullWake();
		}
	}

	// The only location where the sleep reason is published. At this point
	// sleep can still be cancelled, but sleep reason should be published
	// early for logging purposes.

	if (publishSleepReason) {
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
			kIOPMDarkWakeThermalEmergencyKey,
			kIOPMNotificationWakeExitKey
		};

		// Record sleep cause in IORegistry
		uint32_t reasonIndex = sleepReason - kIOPMSleepReasonClamshell;
		if (reasonIndex < sizeof(IOPMSleepReasons) / sizeof(IOPMSleepReasons[0])) {
			DLOG("sleep reason %s\n", IOPMSleepReasons[reasonIndex]);
			setProperty(kRootDomainSleepReasonKey, IOPMSleepReasons[reasonIndex]);
		}
	}

	if ((kSystemTransitionNone != _systemTransitionType) &&
	    (kSystemTransitionNewCapClient != _systemTransitionType)) {
		_systemStateGeneration++;
		systemDarkWake = false;

		DLOG("=== START (%s->%s, %x->%x, 0x%x) gen %u, msg %x, tag %x\n",
		    getPowerStateString(currentPowerState),
		    getPowerStateString((uint32_t) newPowerState),
		    _currentCapability, _pendingCapability,
		    *inOutChangeFlags, _systemStateGeneration, _systemMessageClientMask,
		    requestTag);
	}

	if ((AOT_STATE == newPowerState) && (SLEEP_STATE != currentPowerState)) {
		panic("illegal AOT entry from %s", getPowerStateString(currentPowerState));
	}
	if (_aotNow && (ON_STATE == newPowerState)) {
		WAKEEVENT_LOCK();
		aotShouldExit(false, true);
		WAKEEVENT_UNLOCK();
		aotExit(false);
	}
}

void
IOPMrootDomain::handleOurPowerChangeDone(
	IOService *             service,
	IOPMActions *           actions,
	const IOPMRequest *     request,
	IOPMPowerStateIndex     oldPowerState,
	IOPMPowerChangeFlags    changeFlags )
{
	if (kSystemTransitionNewCapClient == _systemTransitionType) {
		_systemTransitionType = kSystemTransitionNone;
		return;
	}

	if (_systemTransitionType != kSystemTransitionNone) {
		uint32_t currentPowerState = (uint32_t) getPowerState();

		if (changeFlags & kIOPMNotDone) {
			// Power down was cancelled or vetoed.
			_pendingCapability = _currentCapability;
			lastSleepReason = 0;

			// When sleep is cancelled or reverted, don't report
			// the target (lower) power state as the previous state.
			oldPowerState = currentPowerState;

			if (!CAP_CURRENT(kIOPMSystemCapabilityGraphics) &&
			    CAP_CURRENT(kIOPMSystemCapabilityCPU)) {
#if defined(XNU_TARGET_OS_OSX)
				pmPowerStateQueue->submitPowerEvent(
					kPowerEventPolicyStimulus,
					(void *) kStimulusDarkWakeReentry,
					_systemStateGeneration );
#else /* !defined(XNU_TARGET_OS_OSX) */
				// On embedded, there are no factors that can prolong a
				// "darkWake" when a power down is vetoed. We need to
				// promote to "fullWake" at least once so that factors
				// that prevent idle sleep can assert themselves if required
				pmPowerStateQueue->submitPowerEvent(
					kPowerEventPolicyStimulus,
					(void *) kStimulusDarkWakeActivityTickle);
#endif /* !defined(XNU_TARGET_OS_OSX) */
			}

			// Revert device desire to max.
			changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonPowerDownCancel);
		} else {
			// Send message on dark wake to full wake promotion.
			// tellChangeUp() handles the normal SLEEP->ON case.

			if (kSystemTransitionCapability == _systemTransitionType) {
				if (CAP_GAIN(kIOPMSystemCapabilityGraphics)) {
					lastSleepReason = 0; // stop logging wrangler tickles
					tellClients(kIOMessageSystemHasPoweredOn);
				}
				if (CAP_LOSS(kIOPMSystemCapabilityGraphics)) {
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
			    CAP_LOSS(kIOPMSystemCapabilityCPU)) {
				darkWakeMaintenance = false;
				darkWakeToSleepASAP = false;
				pciCantSleepValid   = false;
				darkWakeSleepService = false;

				if (CAP_LOSS(kIOPMSystemCapabilityCPU)) {
					// Remove the influence of display power assertion
					// before next system wake.
					if (wrangler) {
						wrangler->changePowerStateForRootDomain(
							kWranglerPowerStateMin );
					}
					removeProperty(gIOPMUserTriggeredFullWakeKey.get());
				}
			}

			// Entered dark mode.

			if (((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0) &&
			    (_pendingCapability & kIOPMSystemCapabilityCPU)) {
				// Queue an evaluation of whether to remain in dark wake,
				// and for how long. This serves the purpose of draining
				// any assertions from the queue.

				pmPowerStateQueue->submitPowerEvent(
					kPowerEventPolicyStimulus,
					(void *) kStimulusDarkWakeEntry,
					_systemStateGeneration );
			}
		}

		DLOG("=== FINISH (%s->%s, %x->%x, 0x%x) gen %u, msg %x, tag %x\n",
		    getPowerStateString((uint32_t) oldPowerState), getPowerStateString(currentPowerState),
		    _currentCapability, _pendingCapability,
		    changeFlags, _systemStateGeneration, _systemMessageClientMask,
		    request->getTag());

		if ((currentPowerState == ON_STATE) && pmAssertions) {
			pmAssertions->reportCPUBitAccounting();
		}

		if (_pendingCapability & kIOPMSystemCapabilityGraphics) {
			displayWakeCnt++;
#if DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY
			if (clamshellExists && fullWakeThreadCall) {
				AbsoluteTime deadline;
				clock_interval_to_deadline(DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY, kSecondScale, &deadline);
				thread_call_enter_delayed(fullWakeThreadCall, deadline);
			}
#endif
		} else if (CAP_GAIN(kIOPMSystemCapabilityCPU)) {
			darkWakeCnt++;
		}

		// Update current system capability.
		if (_currentCapability != _pendingCapability) {
			_currentCapability = _pendingCapability;
		}

		// Update highest system capability.

		_highestCapability |= _currentCapability;

		if (darkWakePostTickle &&
		    (kSystemTransitionWake == _systemTransitionType) &&
		    (gDarkWakeFlags & kDarkWakeFlagPromotionMask) ==
		    kDarkWakeFlagPromotionLate) {
			darkWakePostTickle = false;
			reportUserInput();
		} else if (darkWakeExit) {
			requestFullWake( kFullWakeReasonLocalUser );
		}

		// Reset tracepoint at completion of capability change,
		// completion of wake transition, and aborted sleep transition.

		if ((_systemTransitionType == kSystemTransitionCapability) ||
		    (_systemTransitionType == kSystemTransitionWake) ||
		    ((_systemTransitionType == kSystemTransitionSleep) &&
		    (changeFlags & kIOPMNotDone))) {
			setProperty(kIOPMSystemCapabilitiesKey, _currentCapability, 64);
			tracePoint( kIOPMTracePointSystemUp );
		}

		_systemTransitionType = kSystemTransitionNone;
		_systemMessageClientMask = 0;
		toldPowerdCapWillChange  = false;

		darkWakeLogClamp = false;

		if (lowBatteryCondition) {
			privateSleepSystem(kIOPMSleepReasonLowPower);
		} else if (thermalEmergencyState) {
			privateSleepSystem(kIOPMSleepReasonThermalEmergency);
		} else if ((fullWakeReason == kFullWakeReasonDisplayOn) && !displayPowerOnRequested) {
			// Request for full wake is removed while system is waking up to full wake
			DLOG("DisplayOn fullwake request is removed\n");
			handleSetDisplayPowerOn(false);
		}

		if ((gClamshellFlags & kClamshell_WAR_47715679) && isRTCAlarmWake) {
			pmPowerStateQueue->submitPowerEvent(
				kPowerEventReceivedPowerNotification, (void *)(uintptr_t) kLocalEvalClamshellCommand );
		}
	}
}

//******************************************************************************
// PM actions for graphics and audio.
//******************************************************************************

void
IOPMrootDomain::overridePowerChangeForService(
	IOService *             service,
	IOPMActions *           actions,
	const IOPMRequest *     request,
	IOPMPowerStateIndex *   inOutPowerState,
	IOPMPowerChangeFlags *  inOutChangeFlags )
{
	uint32_t powerState  = (uint32_t) *inOutPowerState;
	uint32_t changeFlags = (uint32_t) *inOutChangeFlags;
	const uint32_t actionFlags = actions->flags;

	if (kSystemTransitionNone == _systemTransitionType) {
		// Not in midst of a system transition.
		// Do not set kPMActionsStatePowerClamped.
	} else if ((actions->state & kPMActionsStatePowerClamped) == 0) {
		bool enableClamp = false;

		// For most drivers, enable the clamp during ON->Dark transition
		// which has the kIOPMSynchronize flag set in changeFlags.
		if ((actionFlags & kPMActionsFlagIsDisplayWrangler) &&
		    ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0) &&
		    (changeFlags & kIOPMSynchronize)) {
			enableClamp = true;
		} else if ((actionFlags & kPMActionsFlagIsAudioDriver) &&
		    ((gDarkWakeFlags & kDarkWakeFlagAudioNotSuppressed) == 0) &&
		    ((_pendingCapability & kIOPMSystemCapabilityAudio) == 0) &&
		    (changeFlags & kIOPMSynchronize)) {
			enableClamp = true;
		} else if ((actionFlags & kPMActionsFlagHasDarkWakePowerState) &&
		    ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0) &&
		    (changeFlags & kIOPMSynchronize)) {
			enableClamp = true;
		} else if ((actionFlags & kPMActionsFlagIsGraphicsDriver) &&
		    (_systemTransitionType == kSystemTransitionSleep)) {
			// For graphics drivers, clamp power when entering
			// system sleep. Not when dropping to dark wake.
			enableClamp = true;
		}

		if (enableClamp) {
			actions->state |= kPMActionsStatePowerClamped;
			DLOG("power clamp enabled %s %qx, pendingCap 0x%x, ps %d, cflags 0x%x\n",
			    service->getName(), service->getRegistryEntryID(),
			    _pendingCapability, powerState, changeFlags);
		}
	} else if ((actions->state & kPMActionsStatePowerClamped) != 0) {
		bool disableClamp = false;

		if ((actionFlags & (
			    kPMActionsFlagIsDisplayWrangler |
			    kPMActionsFlagIsGraphicsDriver)) &&
		    (_pendingCapability & kIOPMSystemCapabilityGraphics)) {
			disableClamp = true;
		} else if ((actionFlags & kPMActionsFlagIsAudioDriver) &&
		    (_pendingCapability & kIOPMSystemCapabilityAudio)) {
			disableClamp = true;
		} else if ((actionFlags & kPMActionsFlagHasDarkWakePowerState) &&
		    (_pendingCapability & kIOPMSystemCapabilityGraphics)) {
			disableClamp = true;
		}

		if (disableClamp) {
			actions->state &= ~kPMActionsStatePowerClamped;
			DLOG("power clamp removed %s %qx, pendingCap 0x%x, ps %d, cflags 0x%x\n",
			    service->getName(), service->getRegistryEntryID(),
			    _pendingCapability, powerState, changeFlags);
		}
	}

	if (actions->state & kPMActionsStatePowerClamped) {
		uint32_t maxPowerState = 0;

		// Determine the max power state allowed when clamp is enabled
		if (changeFlags & (kIOPMDomainDidChange | kIOPMDomainWillChange)) {
			// Parent intiated power state changes
			if ((service->getPowerState() > maxPowerState) &&
			    (actionFlags & kPMActionsFlagIsDisplayWrangler)) {
				maxPowerState++;

				// Remove lingering effects of any tickle before entering
				// dark wake. It will take a new tickle to return to full
				// wake, so the existing tickle state is useless.

				if (changeFlags & kIOPMDomainDidChange) {
					*inOutChangeFlags |= kIOPMExpireIdleTimer;
				}
			} else if (actionFlags & kPMActionsFlagIsGraphicsDriver) {
				maxPowerState++;
			} else if (actionFlags & kPMActionsFlagHasDarkWakePowerState) {
				maxPowerState = actions->darkWakePowerState;
			}
		} else {
			// Deny all self-initiated changes when power is limited.
			// Wrangler tickle should never defeat the limiter.
			maxPowerState = service->getPowerState();
		}

		if (powerState > maxPowerState) {
			DLOG("power clamped %s %qx, ps %u->%u, cflags 0x%x)\n",
			    service->getName(), service->getRegistryEntryID(),
			    powerState, maxPowerState, changeFlags);
			*inOutPowerState = maxPowerState;

			if (darkWakePostTickle &&
			    (actionFlags & kPMActionsFlagIsDisplayWrangler) &&
			    (changeFlags & kIOPMDomainWillChange) &&
			    ((gDarkWakeFlags & kDarkWakeFlagPromotionMask) ==
			    kDarkWakeFlagPromotionEarly)) {
				darkWakePostTickle = false;
				reportUserInput();
			}
		}

		if (!darkWakePowerClamped && (changeFlags & kIOPMDomainDidChange)) {
			if (darkWakeLogClamp) {
				AbsoluteTime    now;
				uint64_t        nsec;

				clock_get_uptime(&now);
				SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
				absolutetime_to_nanoseconds(now, &nsec);
				DLOG("dark wake power clamped after %u ms\n",
				    ((int)((nsec) / NSEC_PER_MSEC)));
			}
			darkWakePowerClamped = true;
		}
	}
}

void
IOPMrootDomain::handleActivityTickleForDisplayWrangler(
	IOService *     service,
	IOPMActions *   actions )
{
#if DISPLAY_WRANGLER_PRESENT
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

	if (!darkWakeExit && ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0)) {
		DLOG("display wrangler tickled\n");
		if (kIOLogPMRootDomain & gIOKitDebug) {
			OSReportWithBacktrace("Dark wake display tickle");
		}
		if (pmPowerStateQueue) {
			pmPowerStateQueue->submitPowerEvent(
				kPowerEventPolicyStimulus,
				(void *) kStimulusDarkWakeActivityTickle,
				true /* set wake type */ );
		}
	}
#endif /* DISPLAY_WRANGLER_PRESENT */
}

void
IOPMrootDomain::handleUpdatePowerClientForDisplayWrangler(
	IOService *             service,
	IOPMActions *           actions,
	const OSSymbol *        powerClient,
	IOPMPowerStateIndex     oldPowerState,
	IOPMPowerStateIndex     newPowerState )
{
#if DISPLAY_WRANGLER_PRESENT
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

	if (powerClient == gIOPMPowerClientDevice) {
		if ((newPowerState > oldPowerState) &&
		    (newPowerState == kWranglerPowerStateMax) &&
		    (service->getPowerState() == kWranglerPowerStateMax)) {
			evaluatePolicy( kStimulusEnterUserActiveState );
		} else if ((newPowerState < oldPowerState) &&
		    (newPowerState <= kWranglerPowerStateSleep)) {
			evaluatePolicy( kStimulusLeaveUserActiveState );
		}
	}

	if (newPowerState <= kWranglerPowerStateSleep) {
		evaluatePolicy( kStimulusDisplayWranglerSleep );
	} else if (newPowerState == kWranglerPowerStateMax) {
		evaluatePolicy( kStimulusDisplayWranglerWake );
	}
#endif /* DISPLAY_WRANGLER_PRESENT */
}

//******************************************************************************
// User active state management
//******************************************************************************

void
IOPMrootDomain::preventTransitionToUserActive( bool prevent )
{
#if DISPLAY_WRANGLER_PRESENT
	_preventUserActive = prevent;
	if (wrangler && !_preventUserActive) {
		// Allowing transition to user active, but the wrangler may have
		// already powered ON in case of sleep cancel/revert. Poll the
		// same conditions checked for in displayWranglerNotification()
		// to bring the user active state up to date.

		if ((wrangler->getPowerState() == kWranglerPowerStateMax) &&
		    (wrangler->getPowerStateForClient(gIOPMPowerClientDevice) ==
		    kWranglerPowerStateMax)) {
			evaluatePolicy( kStimulusEnterUserActiveState );
		}
	}
#endif /* DISPLAY_WRANGLER_PRESENT */
}

//******************************************************************************
// Approve usage of delayed child notification by PM.
//******************************************************************************

bool
IOPMrootDomain::shouldDelayChildNotification(
	IOService * service )
{
	if ((kFullWakeReasonNone == fullWakeReason) &&
	    (kSystemTransitionWake == _systemTransitionType)) {
		DLOG("%s: delay child notify\n", service->getName());
		return true;
	}
	return false;
}

//******************************************************************************
// PM actions for PCI device.
//******************************************************************************

void
IOPMrootDomain::handlePowerChangeStartForPCIDevice(
	IOService *             service,
	IOPMActions *           actions,
	const IOPMRequest *     request,
	IOPMPowerStateIndex     powerState,
	IOPMPowerChangeFlags *  inOutChangeFlags )
{
	pmTracer->tracePCIPowerChange(
		PMTraceWorker::kPowerChangeStart,
		service, *inOutChangeFlags,
		(actions->flags & kPMActionsPCIBitNumberMask));
}

void
IOPMrootDomain::handlePowerChangeDoneForPCIDevice(
	IOService *             service,
	IOPMActions *           actions,
	const IOPMRequest *     request,
	IOPMPowerStateIndex     powerState,
	IOPMPowerChangeFlags    changeFlags )
{
	pmTracer->tracePCIPowerChange(
		PMTraceWorker::kPowerChangeCompleted,
		service, changeFlags,
		(actions->flags & kPMActionsPCIBitNumberMask));
}

//******************************************************************************
// registerInterest
//
// Override IOService::registerInterest() for root domain clients.
//******************************************************************************

class IOPMServiceInterestNotifier : public _IOServiceInterestNotifier
{
	friend class IOPMrootDomain;
	OSDeclareDefaultStructors(IOPMServiceInterestNotifier);

protected:
	uint32_t        ackTimeoutCnt;
	uint32_t        msgType;        // Message pending ack
	uint32_t        msgIndex;
	uint32_t        maxMsgDelayMS;
	uint32_t        maxAckDelayMS;
	uint64_t        msgAbsTime;
	uint64_t        uuid0;
	uint64_t        uuid1;
	OSSharedPtr<const OSSymbol> identifier;
	OSSharedPtr<const OSSymbol> clientName;
};

OSDefineMetaClassAndStructors(IOPMServiceInterestNotifier, _IOServiceInterestNotifier)

OSSharedPtr<IONotifier>
IOPMrootDomain::registerInterest(
	const OSSymbol * typeOfInterest,
	IOServiceInterestHandler handler,
	void * target, void * ref )
{
	IOPMServiceInterestNotifier* notifier;
	bool            isSystemCapabilityClient;
	bool            isKernelCapabilityClient;
	IOReturn        rc = kIOReturnError;

	isSystemCapabilityClient = typeOfInterest &&
	    typeOfInterest->isEqualTo(kIOPMSystemCapabilityInterest);

	isKernelCapabilityClient = typeOfInterest &&
	    typeOfInterest->isEqualTo(gIOPriorityPowerStateInterest);

	if (isSystemCapabilityClient) {
		typeOfInterest = gIOAppPowerStateInterest;
	}

	notifier = new IOPMServiceInterestNotifier;
	if (!notifier) {
		return NULL;
	}

	if (notifier->init()) {
		rc  = super::registerInterestForNotifier(notifier, typeOfInterest, handler, target, ref);
	}
	if (rc != kIOReturnSuccess) {
		return NULL;
	}

	notifier->ackTimeoutCnt = 0;

	if (pmPowerStateQueue) {
		if (isSystemCapabilityClient) {
			notifier->retain();
			if (pmPowerStateQueue->submitPowerEvent(
				    kPowerEventRegisterSystemCapabilityClient, notifier) == false) {
				notifier->release();
			}
		}

		if (isKernelCapabilityClient) {
			notifier->retain();
			if (pmPowerStateQueue->submitPowerEvent(
				    kPowerEventRegisterKernelCapabilityClient, notifier) == false) {
				notifier->release();
			}
		}
	}

	OSSharedPtr<OSData> data;
	uint8_t *uuid = NULL;
	OSSharedPtr<OSKext> kext = OSKext::lookupKextWithAddress((vm_address_t)handler);
	if (kext) {
		data = kext->copyUUID();
	}
	if (data && (data->getLength() == sizeof(uuid_t))) {
		uuid = (uint8_t *)(data->getBytesNoCopy());

		notifier->uuid0 = ((uint64_t)(uuid[0]) << 56) | ((uint64_t)(uuid[1]) << 48) | ((uint64_t)(uuid[2]) << 40) |
		    ((uint64_t)(uuid[3]) << 32) | ((uint64_t)(uuid[4]) << 24) | ((uint64_t)(uuid[5]) << 16) |
		    ((uint64_t)(uuid[6]) << 8) | (uuid[7]);
		notifier->uuid1 = ((uint64_t)(uuid[8]) << 56) | ((uint64_t)(uuid[9]) << 48) | ((uint64_t)(uuid[10]) << 40) |
		    ((uint64_t)(uuid[11]) << 32) | ((uint64_t)(uuid[12]) << 24) | ((uint64_t)(uuid[13]) << 16) |
		    ((uint64_t)(uuid[14]) << 8) | (uuid[15]);

		notifier->identifier = copyKextIdentifierWithAddress((vm_address_t) handler);
	}
	return OSSharedPtr<IOPMServiceInterestNotifier>(notifier, OSNoRetain);
}

//******************************************************************************
// systemMessageFilter
//
//******************************************************************************

bool
IOPMrootDomain::systemMessageFilter(
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
		    !_joinedCapabilityClients->containsObject((OSObject *) object))) {
			break;
		}

		// Capability change message for app and kernel clients.

		if (isCapMsg) {
			// Kernel clients
			if ((context->notifyType == kNotifyPriority) ||
			    (context->notifyType == kNotifyCapabilityChangePriority)) {
				isCapClient = true;
			}

			// powerd's systemCapabilityNotifier
			if ((context->notifyType == kNotifyCapabilityChangeApps) &&
			    (object == (void *) systemCapabilityNotifier.get())) {
				isCapClient = true;
			}
		}

		if (isCapClient) {
			IOPMSystemCapabilityChangeParameters * capArgs =
			    (IOPMSystemCapabilityChangeParameters *) arg2;

			if (kSystemTransitionNewCapClient == _systemTransitionType) {
				capArgs->fromCapabilities = 0;
				capArgs->toCapabilities = _currentCapability;
				capArgs->changeFlags = 0;
			} else {
				capArgs->fromCapabilities = _currentCapability;
				capArgs->toCapabilities = _pendingCapability;

				if (context->isPreChange) {
					capArgs->changeFlags = kIOPMSystemCapabilityWillChange;
				} else {
					capArgs->changeFlags = kIOPMSystemCapabilityDidChange;
				}

				if ((object == (void *) systemCapabilityNotifier.get()) &&
				    context->isPreChange) {
					toldPowerdCapWillChange = true;
				}
			}

			// Capability change messages only go to the PM configd plugin.
			// Wait for response post-change if capabilitiy is increasing.
			// Wait for response pre-change if capability is decreasing.

			if ((context->notifyType == kNotifyCapabilityChangeApps) && arg3 &&
			    ((capabilityLoss && context->isPreChange) ||
			    (!capabilityLoss && !context->isPreChange))) {
				// app has not replied yet, wait for it
				*((OSObject **) arg3) = kOSBooleanFalse;
			}

			allow = true;
			break;
		}

		// Capability client will always see kIOMessageCanSystemSleep,
		// even for demand sleep. It will also have a chance to veto
		// sleep one last time after all clients have responded to
		// kIOMessageSystemWillSleep

		if ((kIOMessageCanSystemSleep == context->messageType) ||
		    (kIOMessageSystemWillNotSleep == context->messageType)) {
			if (object == (OSObject *) systemCapabilityNotifier.get()) {
				allow = true;
				break;
			}

			// Not idle sleep, don't ask apps.
			if (context->changeFlags & kIOPMSkipAskPowerDown) {
				break;
			}
		}

		if (kIOPMMessageLastCallBeforeSleep == context->messageType) {
			if ((object == (OSObject *) systemCapabilityNotifier.get()) &&
			    CAP_HIGHEST(kIOPMSystemCapabilityGraphics) &&
			    (fullToDarkReason == kIOPMSleepReasonIdle)) {
				allow = true;
			}
			break;
		}

		// Reject capability change messages for legacy clients.
		// Reject legacy system sleep messages for capability client.

		if (isCapMsg || (object == (OSObject *) systemCapabilityNotifier.get())) {
			break;
		}

		// Filter system sleep messages.

		if ((context->notifyType == kNotifyApps) &&
		    (_systemMessageClientMask & kSystemMessageClientLegacyApp)) {
			allow = true;

			if (notifier) {
				if (arg3) {
					if (notifier->ackTimeoutCnt >= 3) {
						*((OSObject **) arg3) = kOSBooleanFalse;
					} else {
						*((OSObject **) arg3) = kOSBooleanTrue;
					}
				}
			}
		} else if ((context->notifyType == kNotifyPriority) &&
		    (_systemMessageClientMask & kSystemMessageClientKernel)) {
			allow = true;
		}
	}while (false);

	if (allow && isCapMsg && _joinedCapabilityClients) {
		_joinedCapabilityClients->removeObject((OSObject *) object);
		if (_joinedCapabilityClients->getCount() == 0) {
			DLOG("destroyed capability client set %p\n",
			    OBFUSCATE(_joinedCapabilityClients.get()));
			_joinedCapabilityClients.reset();
		}
	}
	if (notifier) {
		notifier->msgType = context->messageType;
	}

	return allow;
}

//******************************************************************************
// setMaintenanceWakeCalendar
//
//******************************************************************************

IOReturn
IOPMrootDomain::setMaintenanceWakeCalendar(
	const IOPMCalendarStruct * calendar )
{
	OSSharedPtr<OSData> data;
	IOReturn ret = 0;

	if (!calendar) {
		return kIOReturnBadArgument;
	}

	data = OSData::withBytes((void *) calendar, sizeof(*calendar));
	if (!data) {
		return kIOReturnNoMemory;
	}

	if (kPMCalendarTypeMaintenance == calendar->selector) {
		ret = setPMSetting(gIOPMSettingMaintenanceWakeCalendarKey.get(), data.get());
	} else if (kPMCalendarTypeSleepService == calendar->selector) {
		ret = setPMSetting(gIOPMSettingSleepServiceWakeCalendarKey.get(), data.get());
	}

	return ret;
}

// MARK: -
// MARK: Display Wrangler

//******************************************************************************
// displayWranglerNotification
//
// Handle the notification when the IODisplayWrangler changes power state.
//******************************************************************************

IOReturn
IOPMrootDomain::displayWranglerNotification(
	void * target, void * refCon,
	UInt32 messageType, IOService * service,
	void * messageArgument, vm_size_t argSize )
{
#if DISPLAY_WRANGLER_PRESENT
	IOPMPowerStateIndex                 displayPowerState;
	IOPowerStateChangeNotification *    params =
	    (IOPowerStateChangeNotification *) messageArgument;

	if ((messageType != kIOMessageDeviceWillPowerOff) &&
	    (messageType != kIOMessageDeviceHasPoweredOn)) {
		return kIOReturnUnsupported;
	}

	ASSERT_GATED();
	if (!gRootDomain) {
		return kIOReturnUnsupported;
	}

	displayPowerState = params->stateNumber;
	DLOG("wrangler %s ps %d\n",
	    getIOMessageString(messageType), (uint32_t) displayPowerState);

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

		if (displayPowerState <= kWranglerPowerStateSleep) {
			gRootDomain->evaluatePolicy( kStimulusDisplayWranglerSleep );
		}
		break;

	case kIOMessageDeviceHasPoweredOn:
		// Display wrangler has powered on due to user activity
		// or wake from sleep.

		if (kWranglerPowerStateMax == displayPowerState) {
			gRootDomain->evaluatePolicy( kStimulusDisplayWranglerWake );

			// See comment in handleUpdatePowerClientForDisplayWrangler
			if (service->getPowerStateForClient(gIOPMPowerClientDevice) ==
			    kWranglerPowerStateMax) {
				gRootDomain->evaluatePolicy( kStimulusEnterUserActiveState );
			}
		}
		break;
	}
#endif /* DISPLAY_WRANGLER_PRESENT */
	return kIOReturnUnsupported;
}

//******************************************************************************
// reportUserInput
//
//******************************************************************************

void
IOPMrootDomain::updateUserActivity( void )
{
#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
	clock_get_uptime(&userActivityTime);
	bool aborting =  ((lastSleepReason == kIOPMSleepReasonSoftware)
	    || (lastSleepReason == kIOPMSleepReasonIdle)
	    || (lastSleepReason == kIOPMSleepReasonMaintenance));
	if (aborting) {
		userActivityCount++;
		DLOG("user activity reported %d lastSleepReason %d\n", userActivityCount, lastSleepReason);
	}
#endif
}
void
IOPMrootDomain::reportUserInput( void )
{
	if (wrangler) {
		wrangler->activityTickle(0, 0);
	}
#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
	// Update user activity
	updateUserActivity();

	if (!darkWakeExit && ((_pendingCapability & kIOPMSystemCapabilityGraphics) == 0)) {
		// update user active abs time
		clock_get_uptime(&gUserActiveAbsTime);
		pmPowerStateQueue->submitPowerEvent(
			kPowerEventPolicyStimulus,
			(void *) kStimulusDarkWakeActivityTickle,
			true /* set wake type */ );
	}
#endif
}

void
IOPMrootDomain::requestUserActive(IOService *device, const char *reason)
{
#if DISPLAY_WRANGLER_PRESENT
	if (wrangler) {
		wrangler->activityTickle(0, 0);
	}
#else
	if (!device) {
		DLOG("requestUserActive: device is null\n");
		return;
	}
	OSSharedPtr<const OSSymbol> deviceName = device->copyName();
	uint64_t registryID = device->getRegistryEntryID();

	if (!deviceName || !registryID) {
		DLOG("requestUserActive: no device name or registry entry\n");
		return;
	}
	const char *name = deviceName->getCStringNoCopy();
	char payload[128];
	snprintf(payload, sizeof(payload), "%s:%s", name, reason);
	DLOG("requestUserActive from %s (0x%llx) for %s\n", name, registryID, reason);
	messageClient(kIOPMMessageRequestUserActive, systemCapabilityNotifier.get(), (void *)payload, sizeof(payload));
#endif
}

//******************************************************************************
// latchDisplayWranglerTickle
//******************************************************************************

bool
IOPMrootDomain::latchDisplayWranglerTickle( bool latch )
{
#if DISPLAY_WRANGLER_PRESENT
	if (latch) {
		if (!(_currentCapability & kIOPMSystemCapabilityGraphics) &&
		    !(_pendingCapability & kIOPMSystemCapabilityGraphics) &&
		    !checkSystemCanSustainFullWake()) {
			// Currently in dark wake, and not transitioning to full wake.
			// Full wake is unsustainable, so latch the tickle to prevent
			// the display from lighting up momentarily.
			wranglerTickled = true;
		} else {
			wranglerTickled = false;
		}
	} else if (wranglerTickled && checkSystemCanSustainFullWake()) {
		wranglerTickled = false;

		pmPowerStateQueue->submitPowerEvent(
			kPowerEventPolicyStimulus,
			(void *) kStimulusDarkWakeActivityTickle );
	}

	return wranglerTickled;
#else  /* ! DISPLAY_WRANGLER_PRESENT */
	return false;
#endif /* ! DISPLAY_WRANGLER_PRESENT */
}

//******************************************************************************
// setDisplayPowerOn
//
// For root domain user client
//******************************************************************************

void
IOPMrootDomain::setDisplayPowerOn( uint32_t options )
{
	pmPowerStateQueue->submitPowerEvent( kPowerEventSetDisplayPowerOn,
	    (void *) NULL, options );
}

// MARK: -
// MARK: System PM Policy

//******************************************************************************
// checkSystemSleepAllowed
//
//******************************************************************************

bool
IOPMrootDomain::checkSystemSleepAllowed( IOOptionBits options,
    uint32_t     sleepReason )
{
	uint32_t err = 0;

	// Conditions that prevent idle and demand system sleep.

	do {
		if (userDisabledAllSleep) {
			err = kPMUserDisabledAllSleep; // 1. user-space sleep kill switch
			break;
		}

		if (systemBooting || systemShutdown || gWillShutdown) {
			err = kPMSystemRestartBootingInProgress; // 2. restart or shutdown in progress
			break;
		}

		if (options == 0) {
			break;
		}

		// Conditions above pegs the system at full wake.
		// Conditions below prevent system sleep but does not prevent
		// dark wake, and must be called from gated context.

#if !CONFIG_SLEEP
		err = kPMConfigPreventSystemSleep;    // 3. config does not support sleep
		break;
#endif

		if (lowBatteryCondition || thermalWarningState || thermalEmergencyState) {
			break; // always sleep on low battery or when in thermal warning/emergency state
		}

		if (sleepReason == kIOPMSleepReasonDarkWakeThermalEmergency) {
			break; // always sleep on dark wake thermal emergencies
		}

		if (preventSystemSleepList->getCount() != 0) {
			err = kPMChildPreventSystemSleep; // 4. child prevent system sleep clamp
			break;
		}

		if (getPMAssertionLevel( kIOPMDriverAssertionCPUBit ) ==
		    kIOPMDriverAssertionLevelOn) {
			err = kPMCPUAssertion; // 5. CPU assertion
			break;
		}

		if (pciCantSleepValid) {
			if (pciCantSleepFlag) {
				err = kPMPCIUnsupported; // 6. PCI card does not support PM (cached)
			}
			break;
		} else if (sleepSupportedPEFunction &&
		    CAP_HIGHEST(kIOPMSystemCapabilityGraphics)) {
			IOReturn ret;
			OSBitAndAtomic(~kPCICantSleep, &platformSleepSupport);
			ret = getPlatform()->callPlatformFunction(
				sleepSupportedPEFunction.get(), false,
				NULL, NULL, NULL, NULL);
			pciCantSleepValid = true;
			pciCantSleepFlag  = false;
			if ((platformSleepSupport & kPCICantSleep) ||
			    ((ret != kIOReturnSuccess) && (ret != kIOReturnUnsupported))) {
				err = 6; // 6. PCI card does not support PM
				pciCantSleepFlag = true;
				break;
			}
		}
	}while (false);

	if (err) {
		DLOG("System sleep prevented by %s\n", getSystemSleepPreventerString(err));
		return false;
	}
	return true;
}

bool
IOPMrootDomain::checkSystemSleepEnabled( void )
{
	return checkSystemSleepAllowed(0, 0);
}

bool
IOPMrootDomain::checkSystemCanSleep( uint32_t sleepReason )
{
	ASSERT_GATED();
	return checkSystemSleepAllowed(1, sleepReason);
}

//******************************************************************************
// checkSystemCanSustainFullWake
//******************************************************************************

bool
IOPMrootDomain::checkSystemCanSustainFullWake( void )
{
	if (lowBatteryCondition || thermalWarningState || thermalEmergencyState) {
		// Low battery wake, or received a low battery notification
		// while system is awake. This condition will persist until
		// the following wake.
		return false;
	}

	if (clamshellExists && clamshellClosed && !clamshellSleepDisableMask) {
		// Graphics state is unknown and external display might not be probed.
		// Do not incorporate state that requires graphics to be in max power
		// such as desktopMode or clamshellDisabled.

		if (!acAdaptorConnected) {
			DLOG("full wake check: no AC\n");
			return false;
		}
	}
	return true;
}

//******************************************************************************
// mustHibernate
//******************************************************************************

#if HIBERNATION

bool
IOPMrootDomain::mustHibernate( void )
{
	return lowBatteryCondition || thermalWarningState;
}

#endif /* HIBERNATION */

//******************************************************************************
// AOT
//******************************************************************************

// Tables for accumulated days in year by month, latter used for leap years

static const unsigned int daysbymonth[] =
{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };

static const unsigned int lydaysbymonth[] =
{ 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 };

static int __unused
IOPMConvertSecondsToCalendar(clock_sec_t secs, IOPMCalendarStruct * dt)
{
	const unsigned int *    dbm = daysbymonth;
	clock_sec_t             n, x, y, z;

	// Calculate seconds, minutes and hours

	n = secs % (24 * 3600);
	dt->second = n % 60;
	n /= 60;
	dt->minute = n % 60;
	dt->hour = (typeof(dt->hour))(n / 60);

	// Calculate day of week

	n = secs / (24 * 3600);
//	dt->dayWeek = (n + 4) % 7;

	// Calculate year
	// Rebase from days since Unix epoch (1/1/1970) store in 'n',
	// to days since 1/1/1968 to start on 4 year cycle, beginning
	// on a leap year.

	n += (366 + 365);

	// Every 4 year cycle will be exactly (366 + 365 * 3) = 1461 days.
	// Valid before 2100, since 2100 is not a leap year.

	x = n / 1461;       // number of 4 year cycles
	y = n % 1461;       // days into current 4 year cycle
	z = 1968 + (4 * x);

	// Add in years in the current 4 year cycle

	if (y >= 366) {
		y -= 366;   // days after the leap year
		n = y % 365; // days into the current year
		z += (1 + y / 365); // years after the past 4-yr cycle
	} else {
		n = y;
		dbm = lydaysbymonth;
	}
	if (z > 2099) {
		return 0;
	}

	dt->year = (typeof(dt->year))z;

	// Adjust remaining days value to start at 1

	n += 1;

	// Calculate month

	for (x = 1; (n > dbm[x]) && (x < 12); x++) {
		continue;
	}
	dt->month = (typeof(dt->month))x;

	// Calculate day of month

	dt->day = (typeof(dt->day))(n - dbm[x - 1]);

	return 1;
}

static clock_sec_t
IOPMConvertCalendarToSeconds(const IOPMCalendarStruct * dt)
{
	const unsigned int *    dbm = daysbymonth;
	long                    y, secs, days;

	if (dt->year < 1970 || dt->month > 12) {
		return 0;
	}

	// Seconds elapsed in the current day

	secs = dt->second + 60 * dt->minute + 3600 * dt->hour;

	// Number of days from 1/1/70 to beginning of current year
	// Account for extra day every 4 years starting at 1973

	y = dt->year - 1970;
	days = (y * 365) + ((y + 1) / 4);

	// Change table if current year is a leap year

	if ((dt->year % 4) == 0) {
		dbm = lydaysbymonth;
	}

	// Add in days elapsed in the current year

	days += (dt->day - 1) + dbm[dt->month - 1];

	// Add accumulated days to accumulated seconds

	secs += 24 * 3600 * days;

	return secs;
}

unsigned long
IOPMrootDomain::getRUN_STATE(void)
{
	return _aotNow ? AOT_STATE : ON_STATE;
}

bool
IOPMrootDomain::isAOTMode()
{
	return _aotNow;
}

IOReturn
IOPMrootDomain::setWakeTime(uint64_t wakeContinuousTime)
{
	clock_sec_t     nowsecs, wakesecs;
	clock_usec_t    nowmicrosecs, wakemicrosecs;
	uint64_t        nowAbs, wakeAbs;

	clock_gettimeofday_and_absolute_time(&nowsecs, &nowmicrosecs, &nowAbs);
	wakeAbs = continuoustime_to_absolutetime(wakeContinuousTime);
	if (wakeAbs < nowAbs) {
		printf(LOG_PREFIX "wakeAbs %qd < nowAbs %qd\n", wakeAbs, nowAbs);
		wakeAbs = nowAbs;
	}
	wakeAbs -= nowAbs;
	absolutetime_to_microtime(wakeAbs, &wakesecs, &wakemicrosecs);

	wakesecs += nowsecs;
	wakemicrosecs += nowmicrosecs;
	if (wakemicrosecs >= USEC_PER_SEC) {
		wakesecs++;
		wakemicrosecs -= USEC_PER_SEC;
	}
	if (wakemicrosecs >= (USEC_PER_SEC / 10)) {
		wakesecs++;
	}

	IOPMConvertSecondsToCalendar(wakesecs, &_aotWakeTimeCalendar);

	if (_aotWakeTimeContinuous != wakeContinuousTime) {
		_aotWakeTimeContinuous = wakeContinuousTime;
		IOLog(LOG_PREFIX "setWakeTime: " YMDTF "\n", YMDT(&_aotWakeTimeCalendar));
	}
	_aotWakeTimeCalendar.selector = kPMCalendarTypeMaintenance;
	_aotWakeTimeUTC               = wakesecs;

	return kIOReturnSuccess;
}

// assumes WAKEEVENT_LOCK
bool
IOPMrootDomain::aotShouldExit(bool checkTimeSet, bool software)
{
	bool exitNow;
	const char * reason = "";

	if (software) {
		_aotExit = true;
		_aotMetrics->softwareRequestCount++;
		reason = "software request";
	} else if (kIOPMWakeEventAOTExitFlags & _aotPendingFlags) {
		_aotExit = true;
		reason = gWakeReasonString;
	} else if (checkTimeSet && (kPMCalendarTypeInvalid == _aotWakeTimeCalendar.selector)) {
		_aotExit = true;
		_aotMetrics->noTimeSetCount++;
		reason = "flipbook expired";
	} else if ((kIOPMAOTModeRespectTimers & _aotMode) && _calendarWakeAlarmUTC) {
		clock_sec_t     sec;
		clock_usec_t    usec;
		clock_get_calendar_microtime(&sec, &usec);
		if (_calendarWakeAlarmUTC <= sec) {
			_aotExit = true;
			_aotMetrics->rtcAlarmsCount++;
			reason = "user alarm";
		}
	}
	exitNow = (_aotNow && _aotExit);
	if (exitNow) {
		_aotNow = false;
		IOLog(LOG_PREFIX "AOT exit for %s, sc %d po %d, cp %d, rj %d, ex %d, nt %d, rt %d\n",
		    reason,
		    _aotMetrics->sleepCount,
		    _aotMetrics->possibleCount,
		    _aotMetrics->confirmedPossibleCount,
		    _aotMetrics->rejectedPossibleCount,
		    _aotMetrics->expiredPossibleCount,
		    _aotMetrics->noTimeSetCount,
		    _aotMetrics->rtcAlarmsCount);
	}
	return exitNow;
}

void
IOPMrootDomain::aotExit(bool cps)
{
	uint32_t savedMessageMask;

	ASSERT_GATED();
	_aotTasksSuspended  = false;
	_aotReadyToFullWake = false;
	if (_aotTimerScheduled) {
		_aotTimerES->cancelTimeout();
		_aotTimerScheduled = false;
	}
	updateTasksSuspend();

	_aotMetrics->totalTime += mach_absolute_time() - _aotLastWakeTime;
	_aotLastWakeTime = 0;
	if (_aotMetrics->sleepCount && (_aotMetrics->sleepCount <= kIOPMAOTMetricsKernelWakeCountMax)) {
		WAKEEVENT_LOCK();
		strlcpy(&_aotMetrics->kernelWakeReason[_aotMetrics->sleepCount - 1][0],
		    gWakeReasonString,
		    sizeof(_aotMetrics->kernelWakeReason[_aotMetrics->sleepCount]));
		WAKEEVENT_UNLOCK();
	}

	_aotWakeTimeCalendar.selector = kPMCalendarTypeInvalid;

	// Preserve the message mask since a system wake transition
	// may have already started and initialized the mask.
	savedMessageMask = _systemMessageClientMask;
	_systemMessageClientMask = kSystemMessageClientLegacyApp;
	tellClients(kIOMessageSystemWillPowerOn);
	_systemMessageClientMask = savedMessageMask | kSystemMessageClientLegacyApp;

	if (cps) {
		changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonAOTExit);
	}
}

void
IOPMrootDomain::aotEvaluate(IOTimerEventSource * timer)
{
	bool exitNow;

	IOLog("aotEvaluate(%d) 0x%x\n", (timer != NULL), _aotPendingFlags);

	WAKEEVENT_LOCK();
	exitNow = aotShouldExit(false, false);
	if (timer != NULL) {
		_aotTimerScheduled = false;
	}
	WAKEEVENT_UNLOCK();
	if (exitNow) {
		aotExit(true);
	} else {
#if 0
		if (_aotLingerTime) {
			uint64_t deadline;
			IOLog("aot linger before sleep\n");
			clock_absolutetime_interval_to_deadline(_aotLingerTime, &deadline);
			clock_delay_until(deadline);
		}
#endif
		privateSleepSystem(kIOPMSleepReasonSoftware);
	}
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

void
IOPMrootDomain::adjustPowerState( bool sleepASAP )
{
	DEBUG_LOG("adjustPowerState %s, asap %d, idleSleepEnabled %d\n",
	    getPowerStateString((uint32_t) getPowerState()), sleepASAP, idleSleepEnabled);

	ASSERT_GATED();

	if (_aotNow) {
		bool exitNow;

		if (AOT_STATE != getPowerState()) {
			return;
		}
		WAKEEVENT_LOCK();
		exitNow = aotShouldExit(true, false);
		if (!exitNow
		    && !_aotTimerScheduled
		    && (kIOPMWakeEventAOTPossibleExit == (kIOPMWakeEventAOTPossibleFlags & _aotPendingFlags))) {
			_aotTimerScheduled = true;
			if (_aotLingerTime) {
				_aotTimerES->setTimeout(_aotLingerTime);
			} else {
				_aotTimerES->setTimeout(800, kMillisecondScale);
			}
		}
		WAKEEVENT_UNLOCK();
		if (exitNow) {
			aotExit(true);
		} else {
			_aotReadyToFullWake = true;
			if (!_aotTimerScheduled) {
				privateSleepSystem(kIOPMSleepReasonSoftware);
			}
		}
		return;
	}

	if ((!idleSleepEnabled) || !checkSystemSleepEnabled()) {
		changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonAdjustPowerState);
	} else if (sleepASAP) {
		changePowerStateWithTagToPriv(SLEEP_STATE, kCPSReasonAdjustPowerState);
	}
}

void
IOPMrootDomain::handleSetDisplayPowerOn(bool powerOn)
{
	if (powerOn) {
		if (!checkSystemCanSustainFullWake()) {
			DLOG("System cannot sustain full wake\n");
			return;
		}

		// Force wrangler to max power state. If system is in dark wake
		// this alone won't raise the wrangler's power state.
		if (wrangler) {
			wrangler->changePowerStateForRootDomain(kWranglerPowerStateMax);
		}

		// System in dark wake, always requesting full wake should
		// not have any bad side-effects, even if the request fails.

		if (!CAP_CURRENT(kIOPMSystemCapabilityGraphics)) {
			setProperty(kIOPMRootDomainWakeTypeKey, kIOPMRootDomainWakeTypeNotification);
			requestFullWake( kFullWakeReasonDisplayOn );
		}
	} else {
		// Relenquish desire to power up display.
		// Must first transition to state 1 since wrangler doesn't
		// power off the displays at state 0. At state 0 the root
		// domain is removed from the wrangler's power client list.
		if (wrangler) {
			wrangler->changePowerStateForRootDomain(kWranglerPowerStateMin + 1);
			wrangler->changePowerStateForRootDomain(kWranglerPowerStateMin);
		}
	}
}

//******************************************************************************
// dispatchPowerEvent
//
// IOPMPowerStateQueue callback function. Running on PM work loop thread.
//******************************************************************************

void
IOPMrootDomain::dispatchPowerEvent(
	uint32_t event, void * arg0, uint64_t arg1 )
{
	ASSERT_GATED();

	switch (event) {
	case kPowerEventFeatureChanged:
		DMSG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		messageClients(kIOPMMessageFeatureChange, this);
		break;

	case kPowerEventReceivedPowerNotification:
		DMSG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		handlePowerNotification((UInt32)(uintptr_t) arg0 );
		break;

	case kPowerEventSystemBootCompleted:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (systemBooting) {
			systemBooting = false;

			// read noidle setting from Device Tree
			OSSharedPtr<IORegistryEntry> defaults = IORegistryEntry::fromPath("IODeviceTree:/defaults");
			if (defaults != NULL) {
				OSSharedPtr<OSObject> noIdleProp = defaults->copyProperty("no-idle");
				OSData *data = OSDynamicCast(OSData, noIdleProp.get());
				if ((data != NULL) && (data->getLength() == 4)) {
					gNoIdleFlag = *(uint32_t*)data->getBytesNoCopy();
					DLOG("Setting gNoIdleFlag to %u from device tree\n", gNoIdleFlag);
				}
			}
			if (lowBatteryCondition || thermalEmergencyState) {
				if (lowBatteryCondition) {
					privateSleepSystem(kIOPMSleepReasonLowPower);
				} else {
					privateSleepSystem(kIOPMSleepReasonThermalEmergency);
				}
				// The rest is unnecessary since the system is expected
				// to sleep immediately. The following wake will update
				// everything.
				break;
			}

			sleepWakeDebugMemAlloc();
			saveFailureData2File();

			// If lid is closed, re-send lid closed notification
			// now that booting is complete.
			if (clamshellClosed) {
				handlePowerNotification(kLocalEvalClamshellCommand);
			}
			evaluatePolicy( kStimulusAllowSystemSleepChanged );
		}
		break;

	case kPowerEventSystemShutdown:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (kOSBooleanTrue == (OSBoolean *) arg0) {
			/* We set systemShutdown = true during shutdown
			 *  to prevent sleep at unexpected times while loginwindow is trying
			 *  to shutdown apps and while the OS is trying to transition to
			 *  complete power of.
			 *
			 *  Set to true during shutdown, as soon as loginwindow shows
			 *  the "shutdown countdown dialog", through individual app
			 *  termination, and through black screen kernel shutdown.
			 */
			systemShutdown = true;
		} else {
			/*
			 *  A shutdown was initiated, but then the shutdown
			 *  was cancelled, clearing systemShutdown to false here.
			 */
			systemShutdown = false;
		}
		break;

	case kPowerEventUserDisabledSleep:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		userDisabledAllSleep = (kOSBooleanTrue == (OSBoolean *) arg0);
		break;

	case kPowerEventRegisterSystemCapabilityClient:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);

		// reset() handles the arg0 == nullptr case for us
		systemCapabilityNotifier.reset((IONotifier *) arg0, OSRetain);
		/* intentional fall-through */
		[[clang::fallthrough]];

	case kPowerEventRegisterKernelCapabilityClient:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (!_joinedCapabilityClients) {
			_joinedCapabilityClients = OSSet::withCapacity(8);
		}
		if (arg0) {
			OSSharedPtr<IONotifier> notify((IONotifier *) arg0, OSNoRetain);
			if (_joinedCapabilityClients) {
				_joinedCapabilityClients->setObject(notify.get());
				synchronizePowerTree( kIOPMSyncNoChildNotify );
			}
		}
		break;

	case kPowerEventPolicyStimulus:
		DMSG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (arg0) {
			int stimulus = (int)(uintptr_t) arg0;
			evaluatePolicy(stimulus, (uint32_t) arg1);
		}
		break;

	case kPowerEventAssertionCreate:
		DMSG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (pmAssertions) {
			pmAssertions->handleCreateAssertion((OSData *)arg0);
		}
		break;


	case kPowerEventAssertionRelease:
		DMSG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (pmAssertions) {
			pmAssertions->handleReleaseAssertion(arg1);
		}
		break;

	case kPowerEventAssertionSetLevel:
		DMSG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (pmAssertions) {
			pmAssertions->handleSetAssertionLevel(arg1, (IOPMDriverAssertionLevel)(uintptr_t)arg0);
		}
		break;

	case kPowerEventQueueSleepWakeUUID:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		handleQueueSleepWakeUUID((OSObject *)arg0);
		break;
	case kPowerEventPublishSleepWakeUUID:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		handlePublishSleepWakeUUID((bool)arg0);
		break;

	case kPowerEventSetDisplayPowerOn:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (arg1 != 0) {
			displayPowerOnRequested = true;
		} else {
			displayPowerOnRequested = false;
		}
		handleSetDisplayPowerOn(displayPowerOnRequested);
		break;

	case kPowerEventPublishWakeType:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);

		// Don't replace wake type property if already set
		if ((arg0 == gIOPMWakeTypeUserKey) ||
		    !propertyExists(kIOPMRootDomainWakeTypeKey)) {
			const char * wakeType = NULL;

			if (arg0 == gIOPMWakeTypeUserKey) {
				requestUserActive(this, "WakeTypeUser");
				wakeType = kIOPMRootDomainWakeTypeUser;
			} else if (arg0 == gIOPMSettingDebugWakeRelativeKey) {
				requestUserActive(this, "WakeTypeAlarm");
				wakeType = kIOPMRootDomainWakeTypeAlarm;
			} else if (arg0 == gIOPMSettingSleepServiceWakeCalendarKey) {
				darkWakeSleepService = true;
				wakeType = kIOPMRootDomainWakeTypeSleepService;
			} else if (arg0 == gIOPMSettingMaintenanceWakeCalendarKey) {
				wakeType = kIOPMRootDomainWakeTypeMaintenance;
			}

			if (wakeType) {
				setProperty(kIOPMRootDomainWakeTypeKey, wakeType);
			}
		}
		break;

	case kPowerEventAOTEvaluate:
		DLOG("power event %u args %p 0x%llx\n", event, OBFUSCATE(arg0), arg1);
		if (_aotReadyToFullWake) {
			aotEvaluate(NULL);
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

IOReturn
IOPMrootDomain::systemPowerEventOccurred(
	const OSSymbol *event,
	uint32_t intValue)
{
	IOReturn        attempt = kIOReturnSuccess;
	OSSharedPtr<OSNumber>        newNumber;

	if (!event) {
		return kIOReturnBadArgument;
	}

	newNumber = OSNumber::withNumber(intValue, 8 * sizeof(intValue));
	if (!newNumber) {
		return kIOReturnInternalError;
	}

	attempt = systemPowerEventOccurred(event, static_cast<OSObject *>(newNumber.get()));

	return attempt;
}

void
IOPMrootDomain::setThermalState(OSObject *value)
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

IOReturn
IOPMrootDomain::systemPowerEventOccurred(
	const OSSymbol *event,
	OSObject *value)
{
	OSSharedPtr<OSDictionary> thermalsDict;
	bool shouldUpdate = true;

	if (!event || !value) {
		return kIOReturnBadArgument;
	}

	// LOCK
	// We reuse featuresDict Lock because it already exists and guards
	// the very infrequently used publish/remove feature mechanism; so there's zero rsk
	// of stepping on that lock.
	if (featuresDictLock) {
		IOLockLock(featuresDictLock);
	}

	OSSharedPtr<OSObject> origThermalsProp = copyProperty(kIOPMRootDomainPowerStatusKey);
	OSDictionary * origThermalsDict = OSDynamicCast(OSDictionary, origThermalsProp.get());

	if (origThermalsDict) {
		thermalsDict = OSDictionary::withDictionary(origThermalsDict);
	} else {
		thermalsDict = OSDictionary::withCapacity(1);
	}

	if (!thermalsDict) {
		shouldUpdate = false;
		goto exit;
	}

	thermalsDict->setObject(event, value);

	setProperty(kIOPMRootDomainPowerStatusKey, thermalsDict.get());

exit:
	// UNLOCK
	if (featuresDictLock) {
		IOLockUnlock(featuresDictLock);
	}

	if (shouldUpdate) {
		if (event &&
		    event->isEqualTo(kIOPMThermalLevelWarningKey)) {
			setThermalState(value);
		}
		messageClients(kIOPMMessageSystemPowerEventOccurred, (void *)NULL);
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

IOReturn
IOPMrootDomain::receivePowerNotification( UInt32 msg )
{
	if (msg & kIOPMPowerButton) {
		uint32_t currentPhase = pmTracer->getTracePhase();
		if (currentPhase != kIOPMTracePointSystemUp && currentPhase > kIOPMTracePointSystemSleep) {
			DEBUG_LOG("power button pressed during wake. phase = %u\n", currentPhase);
			swd_flags |= SWD_PWR_BTN_STACKSHOT;
			thread_call_enter(powerButtonDown);
		} else {
			DEBUG_LOG("power button pressed when system is up\n");
		}
	} else if (msg & kIOPMPowerButtonUp) {
		if (swd_flags & SWD_PWR_BTN_STACKSHOT) {
			swd_flags &= ~SWD_PWR_BTN_STACKSHOT;
			thread_call_enter(powerButtonUp);
		}
	} else {
		pmPowerStateQueue->submitPowerEvent(
			kPowerEventReceivedPowerNotification, (void *)(uintptr_t) msg );
	}
	return kIOReturnSuccess;
}

void
IOPMrootDomain::handlePowerNotification( UInt32 msg )
{
	bool        eval_clamshell = false;
	bool        eval_clamshell_alarm = false;

	ASSERT_GATED();

	/*
	 * Local (IOPMrootDomain only) eval clamshell command
	 */
	if (msg & kLocalEvalClamshellCommand) {
		if ((gClamshellFlags & kClamshell_WAR_47715679) && isRTCAlarmWake) {
			eval_clamshell_alarm = true;

			// reset isRTCAlarmWake. This evaluation should happen only once
			// on RTC/Alarm wake. Any clamshell events after wake should follow
			// the regular evaluation
			isRTCAlarmWake = false;
		} else {
			eval_clamshell = true;
		}
	}

	/*
	 * Overtemp
	 */
	if (msg & kIOPMOverTemp) {
		DLOG("Thermal overtemp message received!\n");
		thermalEmergencyState = true;
		privateSleepSystem(kIOPMSleepReasonThermalEmergency);
	}

	/*
	 * Forward DW thermal notification to client, if system is not going to sleep
	 */
	if ((msg & kIOPMDWOverTemp) && (_systemTransitionType != kSystemTransitionSleep)) {
		DLOG("DarkWake thermal limits message received!\n");
		messageClients(kIOPMMessageDarkWakeThermalEmergency);
	}

	/*
	 * Sleep Now!
	 */
	if (msg & kIOPMSleepNow) {
		privateSleepSystem(kIOPMSleepReasonSoftware);
	}

	/*
	 * Power Emergency
	 */
	if (msg & kIOPMPowerEmergency) {
		DLOG("Low battery notification received\n");
#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
		// Wait for the next low battery notification if the system state is
		// in transition.
		if ((_systemTransitionType == kSystemTransitionNone) &&
		    CAP_CURRENT(kIOPMSystemCapabilityCPU) &&
		    !systemBooting && !systemShutdown && !gWillShutdown) {
			// Setting lowBatteryCondition will prevent system sleep
			lowBatteryCondition = true;

			// Notify userspace to initiate system shutdown
			messageClients(kIOPMMessageRequestSystemShutdown);
		}
#else
		lowBatteryCondition = true;
		privateSleepSystem(kIOPMSleepReasonLowPower);
#endif
	}

	/*
	 * Clamshell OPEN
	 */
	if (msg & kIOPMClamshellOpened) {
		DLOG("Clamshell opened\n");
		// Received clamshel open message from clamshell controlling driver
		// Update our internal state and tell general interest clients
		clamshellClosed = false;
		clamshellExists = true;

		// Don't issue a hid tickle when lid is open and polled on wake
		if (msg & kIOPMSetValue) {
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
		if (aborting) {
			userActivityCount++;
		}
		DLOG("clamshell tickled %d lastSleepReason %d\n", userActivityCount, lastSleepReason);
	}

	/*
	 * Clamshell CLOSED
	 * Send the clamshell interest notification since the lid is closing.
	 */
	if (msg & kIOPMClamshellClosed) {
		if ((clamshellIgnoreClose || (gClamshellFlags & kClamshell_WAR_38378787)) &&
		    clamshellClosed && clamshellExists) {
			DLOG("Ignoring redundant Clamshell close event\n");
		} else {
			DLOG("Clamshell closed\n");
			// Received clamshel open message from clamshell controlling driver
			// Update our internal state and tell general interest clients
			clamshellClosed = true;
			clamshellExists = true;

			// Ignore all following clamshell close events until the clamshell
			// is opened or the system sleeps. When a clamshell close triggers
			// a system wake, the lid driver may send us two clamshell close
			// events, one for the clamshell close event itself, and a second
			// close event when the driver polls the lid state on wake.
			clamshellIgnoreClose = true;

			// Tell PMCPU
			informCPUStateChange(kInformLid, 1);

			// Tell general interest clients
			sendClientClamshellNotification();

			// And set eval_clamshell = so we can attempt
			eval_clamshell = true;
		}
	}

	/*
	 * Set Desktop mode (sent from graphics)
	 *
	 *  -> reevaluate lid state
	 */
	if (msg & kIOPMSetDesktopMode) {
		desktopMode = (0 != (msg & kIOPMSetValue));
		msg &= ~(kIOPMSetDesktopMode | kIOPMSetValue);
		DLOG("Desktop mode %d\n", desktopMode);

		sendClientClamshellNotification();

		// Re-evaluate the lid state
		eval_clamshell = true;
	}

	/*
	 * AC Adaptor connected
	 *
	 *  -> reevaluate lid state
	 */
	if (msg & kIOPMSetACAdaptorConnected) {
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
	if (msg & kIOPMEnableClamshell) {
		DLOG("Clamshell enabled\n");

		// Re-evaluate the lid state
		// System should sleep on external display disappearance
		// in lid closed operation.
		if (true == clamshellDisabled) {
			eval_clamshell = true;

#if DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY
			// Also clear kClamshellSleepDisableInternal when graphics enables
			// the clamshell during a full wake. When graphics is behaving as
			// expected, this will allow clamshell close to be honored earlier
			// rather than waiting for the delayed evaluation.
			if ((clamshellSleepDisableMask & kClamshellSleepDisableInternal) &&
			    (CAP_PENDING(kIOPMSystemCapabilityGraphics) ||
			    CAP_CURRENT(kIOPMSystemCapabilityGraphics))) {
				setClamShellSleepDisable(false, kClamshellSleepDisableInternal);

				// Cancel the TC to avoid an extra kLocalEvalClamshellCommand
				// when timer expires which is harmless but useless.
				thread_call_cancel(fullWakeThreadCall);
			}
#endif
		}

		clamshellDisabled = false;
		sendClientClamshellNotification();
	}

	/*
	 * Disable Clamshell (external display appeared)
	 * We don't bother re-evaluating clamshell state. If the system is awake,
	 * the lid is probably open.
	 */
	if (msg & kIOPMDisableClamshell) {
		DLOG("Clamshell disabled\n");
		clamshellDisabled = true;
		sendClientClamshellNotification();
	}

	/*
	 * Evaluate clamshell and SLEEP if appropriate
	 */
	if (eval_clamshell_alarm && clamshellClosed) {
		if (shouldSleepOnRTCAlarmWake()) {
			privateSleepSystem(kIOPMSleepReasonClamshell);
		}
	} else if (eval_clamshell && clamshellClosed) {
		if (shouldSleepOnClamshellClosed()) {
			privateSleepSystem(kIOPMSleepReasonClamshell);
		} else {
			evaluatePolicy( kStimulusDarkWakeEvaluate );
		}
	}

	if (msg & kIOPMProModeEngaged) {
		int newState = 1;
		DLOG("ProModeEngaged\n");
		messageClient(kIOPMMessageProModeStateChange, systemCapabilityNotifier.get(), &newState, sizeof(newState));
	}

	if (msg & kIOPMProModeDisengaged) {
		int newState = 0;
		DLOG("ProModeDisengaged\n");
		messageClient(kIOPMMessageProModeStateChange, systemCapabilityNotifier.get(), &newState, sizeof(newState));
	}
}

//******************************************************************************
// evaluatePolicy
//
// Evaluate root-domain policy in response to external changes.
//******************************************************************************

void
IOPMrootDomain::evaluatePolicy( int stimulus, uint32_t arg )
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
			int displaySleepEntry   : 1;
		} bit;
		uint32_t u32;
	} flags;


	ASSERT_GATED();
	flags.u32 = 0;

	switch (stimulus) {
	case kStimulusDisplayWranglerSleep:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		if (!wranglerPowerOff) {
			// wrangler is in sleep state or lower
			flags.bit.displaySleep = true;
		}
		if (!wranglerAsleep) {
			// transition from wrangler wake to wrangler sleep
			flags.bit.displaySleepEntry = true;
			wranglerAsleep = true;
		}
		break;

	case kStimulusDisplayWranglerWake:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		displayIdleForDemandSleep = false;
		wranglerPowerOff = false;
		wranglerAsleep = false;
		break;

	case kStimulusEnterUserActiveState:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		if (_preventUserActive) {
			DLOG("user active dropped\n");
			break;
		}
		if (!userIsActive) {
			userIsActive = true;
			userWasActive = true;
			clock_get_uptime(&gUserActiveAbsTime);

			// Stay awake after dropping demand for display power on
			if (kFullWakeReasonDisplayOn == fullWakeReason) {
				fullWakeReason = fFullWakeReasonDisplayOnAndLocalUser;
				DLOG("User activity while in notification wake\n");
				changePowerStateWithOverrideTo( getRUN_STATE(), 0);
			}

			kdebugTrace(kPMLogUserActiveState, 0, 1, 0);
			setProperty(gIOPMUserIsActiveKey.get(), kOSBooleanTrue);
			messageClients(kIOPMMessageUserIsActiveChanged);
		}
		flags.bit.idleSleepDisabled = true;
		break;

	case kStimulusLeaveUserActiveState:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		if (userIsActive) {
			clock_get_uptime(&gUserInactiveAbsTime);
			userIsActive = false;
			clock_get_uptime(&userBecameInactiveTime);
			flags.bit.userBecameInactive = true;

			kdebugTrace(kPMLogUserActiveState, 0, 0, 0);
			setProperty(gIOPMUserIsActiveKey.get(), kOSBooleanFalse);
			messageClients(kIOPMMessageUserIsActiveChanged);
		}
		break;

	case kStimulusAggressivenessChanged:
	{
		DMSG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		unsigned long   aggressiveValue;
		uint32_t        minutesToIdleSleep  = 0;
		uint32_t        minutesToDisplayDim = 0;
		uint32_t        minutesDelta        = 0;

		// Fetch latest display and system sleep slider values.
		aggressiveValue = 0;
		getAggressiveness(kPMMinutesToSleep, &aggressiveValue);
		minutesToIdleSleep = (uint32_t) aggressiveValue;

		aggressiveValue = 0;
		getAggressiveness(kPMMinutesToDim, &aggressiveValue);
		minutesToDisplayDim = (uint32_t) aggressiveValue;
		DLOG("aggressiveness changed: system %u->%u, display %u\n",
		    sleepSlider, minutesToIdleSleep, minutesToDisplayDim);

		DLOG("idle time -> %d secs (ena %d)\n",
		    idleSeconds, (minutesToIdleSleep != 0));

		// How long to wait before sleeping the system once
		// the displays turns off is indicated by 'extraSleepDelay'.

		if (minutesToIdleSleep > minutesToDisplayDim) {
			minutesDelta = minutesToIdleSleep - minutesToDisplayDim;
		} else if (minutesToIdleSleep == minutesToDisplayDim) {
			minutesDelta = 1;
		}

		if ((!idleSleepEnabled) && (minutesToIdleSleep != 0)) {
			idleSleepEnabled = flags.bit.idleSleepEnabled = true;
		}

		if ((idleSleepEnabled) && (minutesToIdleSleep == 0)) {
			flags.bit.idleSleepDisabled = true;
			idleSleepEnabled = false;
		}
#if !defined(XNU_TARGET_OS_OSX)
		if (0x7fffffff == minutesToIdleSleep) {
			minutesToIdleSleep = idleSeconds;
		}
#endif /* !defined(XNU_TARGET_OS_OSX) */

		if (((minutesDelta != extraSleepDelay) ||
		    (userActivityTime != userActivityTime_prev)) &&
		    !flags.bit.idleSleepEnabled && !flags.bit.idleSleepDisabled) {
			flags.bit.sleepDelayChanged = true;
		}

		if (systemDarkWake && !darkWakeToSleepASAP &&
		    (flags.bit.idleSleepEnabled || flags.bit.idleSleepDisabled)) {
			// Reconsider decision to remain in dark wake
			flags.bit.evaluateDarkWake = true;
		}

		sleepSlider = minutesToIdleSleep;
		extraSleepDelay = minutesDelta;
		userActivityTime_prev = userActivityTime;
	}   break;

	case kStimulusDemandSystemSleep:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		displayIdleForDemandSleep = true;
		if (wrangler && wranglerIdleSettings) {
			// Request wrangler idle only when demand sleep is triggered
			// from full wake.
			if (CAP_CURRENT(kIOPMSystemCapabilityGraphics)) {
				wrangler->setProperties(wranglerIdleSettings.get());
				DLOG("Requested wrangler idle\n");
			}
		}
		// arg = sleepReason
		changePowerStateWithOverrideTo( SLEEP_STATE, arg );
		break;

	case kStimulusAllowSystemSleepChanged:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		flags.bit.adjustPowerState = true;
		break;

	case kStimulusDarkWakeActivityTickle:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		// arg == true implies real and not self generated wrangler tickle.
		// Update wake type on PM work loop instead of the tickle thread to
		// eliminate the possibility of an early tickle clobbering the wake
		// type set by the platform driver.
		if (arg == true) {
			setProperty(kIOPMRootDomainWakeTypeKey, kIOPMRootDomainWakeTypeHIDActivity);
		}

		if (!darkWakeExit) {
			if (latchDisplayWranglerTickle(true)) {
				DLOG("latched tickle\n");
				break;
			}

			darkWakeExit = true;
			DLOG("Requesting full wake due to dark wake activity tickle\n");
			requestFullWake( kFullWakeReasonLocalUser );
		}
		break;

	case kStimulusDarkWakeEntry:
	case kStimulusDarkWakeReentry:
		DLOG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		// Any system transitions since the last dark wake transition
		// will invalid the stimulus.

		if (arg == _systemStateGeneration) {
			DLOG("dark wake entry\n");
			systemDarkWake = true;

			// Keep wranglerPowerOff an invariant when wrangler is absent
			if (wrangler) {
				wranglerPowerOff = true;
			}

			if (kStimulusDarkWakeEntry == stimulus) {
				clock_get_uptime(&userBecameInactiveTime);
				flags.bit.evaluateDarkWake = true;
				if (activitySinceSleep()) {
					DLOG("User activity recorded while going to darkwake\n");
					reportUserInput();
				}
			}

			// Always accelerate disk spindown while in dark wake,
			// even if system does not support/allow sleep.

			cancelIdleSleepTimer();
			setQuickSpinDownTimeout();
		}
		break;

	case kStimulusDarkWakeEvaluate:
		DMSG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		if (systemDarkWake) {
			flags.bit.evaluateDarkWake = true;
		}
		break;

	case kStimulusNoIdleSleepPreventers:
		DMSG("evaluatePolicy( %d, 0x%x )\n", stimulus, arg);
		flags.bit.adjustPowerState = true;
		break;
	} /* switch(stimulus) */

	if (flags.bit.evaluateDarkWake && (kFullWakeReasonNone == fullWakeReason)) {
		DLOG("DarkWake: sleepASAP %d, clamshell closed %d, disabled %d/%x, desktopMode %d, ac %d\n",
		    darkWakeToSleepASAP, clamshellClosed, clamshellDisabled, clamshellSleepDisableMask, desktopMode, acAdaptorConnected);
		if (darkWakeToSleepASAP ||
		    (clamshellClosed && !(desktopMode && acAdaptorConnected))) {
			uint32_t newSleepReason;

			if (CAP_HIGHEST(kIOPMSystemCapabilityGraphics)) {
				// System was previously in full wake. Sleep reason from
				// full to dark already recorded in fullToDarkReason.

				if (lowBatteryCondition) {
					newSleepReason = kIOPMSleepReasonLowPower;
				} else if (thermalEmergencyState) {
					newSleepReason = kIOPMSleepReasonThermalEmergency;
				} else {
					newSleepReason = fullToDarkReason;
				}
			} else {
				// In dark wake from system sleep.

				if (darkWakeSleepService) {
					newSleepReason = kIOPMSleepReasonSleepServiceExit;
				} else {
					newSleepReason = kIOPMSleepReasonMaintenance;
				}
			}

			if (checkSystemCanSleep(newSleepReason)) {
				privateSleepSystem(newSleepReason);
			}
		} else { // non-maintenance (network) dark wake
			if (checkSystemCanSleep(kIOPMSleepReasonIdle)) {
				// Release power clamp, and wait for children idle.
				adjustPowerState(true);
			} else {
				changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonDarkWakeCannotSleep);
			}
		}
	}

	if (systemDarkWake) {
		// The rest are irrelevant while system is in dark wake.
		flags.u32 = 0;
	}

	if ((flags.bit.displaySleepEntry) &&
	    (kFullWakeReasonDisplayOn == fullWakeReason)) {
		// kIOPMSleepReasonNotificationWakeExit
		DLOG("Display sleep while in notification wake\n");
		changePowerStateWithOverrideTo(SLEEP_STATE, kIOPMSleepReasonNotificationWakeExit);
	}

	if (flags.bit.userBecameInactive || flags.bit.sleepDelayChanged) {
		bool cancelQuickSpindown = false;

		if (flags.bit.sleepDelayChanged) {
			// Cancel existing idle sleep timer and quick disk spindown.
			// New settings will be applied by the idleSleepEnabled flag
			// handler below if idle sleep is enabled.

			DLOG("extra sleep timer changed\n");
			cancelIdleSleepTimer();
			cancelQuickSpindown = true;
		} else {
			DLOG("user inactive\n");
		}

		if (!userIsActive && idleSleepEnabled) {
			startIdleSleepTimer(getTimeToIdleSleep());
		}

		if (cancelQuickSpindown) {
			restoreUserSpinDownTimeout();
		}
	}

	if (flags.bit.idleSleepEnabled) {
		DLOG("idle sleep timer enabled\n");
		if (!wrangler) {
#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
			startIdleSleepTimer(getTimeToIdleSleep());
#else
			changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonIdleSleepEnabled);
			startIdleSleepTimer( idleSeconds );
#endif
		} else {
			// Start idle timer if prefs now allow system sleep
			// and user is already inactive. Disk spindown is
			// accelerated upon timer expiration.

			if (!userIsActive) {
				startIdleSleepTimer(getTimeToIdleSleep());
			}
		}
	}

	if (flags.bit.idleSleepDisabled) {
		DLOG("idle sleep timer disabled\n");
		cancelIdleSleepTimer();
		restoreUserSpinDownTimeout();
		adjustPowerState();
	}

	if (flags.bit.adjustPowerState) {
		bool sleepASAP = false;

		if (!systemBooting && (0 == idleSleepPreventersCount())) {
			if (!wrangler) {
				changePowerStateWithTagToPriv(getRUN_STATE(), kCPSReasonEvaluatePolicy);
				if (idleSleepEnabled) {
#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
					if (!extraSleepDelay && !idleSleepTimerPending) {
						sleepASAP = true;
					}
#else
					// stay awake for at least idleSeconds
					startIdleSleepTimer(idleSeconds);
#endif
				}
			} else if (!extraSleepDelay && !idleSleepTimerPending && !systemDarkWake) {
				sleepASAP = true;
			}
		}

		adjustPowerState(sleepASAP);
	}
}

//******************************************************************************

unsigned int
IOPMrootDomain::idleSleepPreventersCount()
{
	if (_aotMode) {
		unsigned int count __block;
		count = 0;
		preventIdleSleepList->iterateObjects(^bool (OSObject * obj)
		{
			count += (NULL == obj->metaCast("AppleARMBacklight"));
			return false;
		});
		return count;
	}

	return preventIdleSleepList->getCount();
}


//******************************************************************************
// requestFullWake
//
// Request transition from dark wake to full wake
//******************************************************************************

void
IOPMrootDomain::requestFullWake( FullWakeReason reason )
{
	uint32_t        options = 0;
	IOService *     pciRoot = NULL;
	bool            promotion = false;

	// System must be in dark wake and a valid reason for entering full wake
	if ((kFullWakeReasonNone == reason) ||
	    (kFullWakeReasonNone != fullWakeReason) ||
	    (CAP_CURRENT(kIOPMSystemCapabilityGraphics))) {
		return;
	}

	// Will clear reason upon exit from full wake
	fullWakeReason = reason;

	_desiredCapability |= (kIOPMSystemCapabilityGraphics |
	    kIOPMSystemCapabilityAudio);

	if ((kSystemTransitionWake == _systemTransitionType) &&
	    !(_pendingCapability & kIOPMSystemCapabilityGraphics) &&
	    !darkWakePowerClamped) {
		// Promote to full wake while waking up to dark wake due to tickle.
		// PM will hold off notifying the graphics subsystem about system wake
		// as late as possible, so if a HID tickle does arrive, graphics can
		// power up from this same wake transition. Otherwise, the latency to
		// power up graphics on the following transition can be huge on certain
		// systems. However, once any power clamping has taken effect, it is
		// too late to promote the current dark wake transition to a full wake.
		_pendingCapability |= (kIOPMSystemCapabilityGraphics |
		    kIOPMSystemCapabilityAudio);

		// Tell the PCI parent of audio and graphics drivers to stop
		// delaying the child notifications. Same for root domain.
		pciRoot = pciHostBridgeDriver.get();
		willEnterFullWake();
		promotion = true;
	}

	// Unsafe to cancel once graphics was powered.
	// If system woke from dark wake, the return to sleep can
	// be cancelled. "awake -> dark -> sleep" transition
	// can be cancelled also, during the "dark -> sleep" phase
	// *prior* to driver power down.
	if (!CAP_HIGHEST(kIOPMSystemCapabilityGraphics) ||
	    _pendingCapability == 0) {
		options |= kIOPMSyncCancelPowerDown;
	}

	synchronizePowerTree(options, pciRoot);

	if (kFullWakeReasonLocalUser == fullWakeReason) {
		// IOGraphics doesn't light the display even though graphics is
		// enabled in kIOMessageSystemCapabilityChange message(radar 9502104)
		// So, do an explicit activity tickle
		if (wrangler) {
			wrangler->activityTickle(0, 0);
		}
	}

	// Log a timestamp for the initial full wake request.
	// System may not always honor this full wake request.
	if (!CAP_HIGHEST(kIOPMSystemCapabilityGraphics)) {
		AbsoluteTime    now;
		uint64_t        nsec;

		clock_get_uptime(&now);
		SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
		absolutetime_to_nanoseconds(now, &nsec);
		MSG("full wake %s (reason %u) %u ms\n",
		    promotion ? "promotion" : "request",
		    fullWakeReason, ((int)((nsec) / NSEC_PER_MSEC)));
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

void
IOPMrootDomain::willEnterFullWake( void )
{
	hibernateRetry = false;
	sleepToStandby = false;
	standbyNixed   = false;
	resetTimers    = false;
	sleepTimerMaintenance = false;

	assert(!CAP_CURRENT(kIOPMSystemCapabilityGraphics));

	_systemMessageClientMask = kSystemMessageClientPowerd |
	    kSystemMessageClientLegacyApp;

	if ((_highestCapability & kIOPMSystemCapabilityGraphics) == 0) {
		// First time to attain full wake capability since the last wake
		_systemMessageClientMask |= kSystemMessageClientKernel;

		// Set kIOPMUserTriggeredFullWakeKey before full wake for IOGraphics
		setProperty(gIOPMUserTriggeredFullWakeKey.get(),
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

void
IOPMrootDomain::fullWakeDelayedWork( void )
{
#if DARK_TO_FULL_EVALUATE_CLAMSHELL_DELAY
	if (!gIOPMWorkLoop->inGate()) {
		gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(IOWorkLoop::Action, this,
			&IOPMrootDomain::fullWakeDelayedWork), this);
		return;
	}

	DLOG("fullWakeDelayedWork cap cur %x pend %x high %x, clamshell disable %x/%x\n",
	    _currentCapability, _pendingCapability, _highestCapability,
	    clamshellDisabled, clamshellSleepDisableMask);

	if (clamshellExists &&
	    CAP_CURRENT(kIOPMSystemCapabilityGraphics) &&
	    !CAP_CHANGE(kIOPMSystemCapabilityGraphics)) {
		if (clamshellSleepDisableMask & kClamshellSleepDisableInternal) {
			setClamShellSleepDisable(false, kClamshellSleepDisableInternal);
		} else {
			// Not the initial full wake after waking from sleep.
			// Evaluate the clamshell for rdar://problem/9157444.
			receivePowerNotification(kLocalEvalClamshellCommand);
		}
	}
#endif
}

//******************************************************************************
// evaluateAssertions
//
//******************************************************************************

// Bitmask of all kernel assertions that prevent system idle sleep.
// kIOPMDriverAssertionReservedBit7 is reserved for IOMediaBSDClient.
#define NO_IDLE_SLEEP_ASSERTIONS_MASK \
	(kIOPMDriverAssertionReservedBit7 | \
	 kIOPMDriverAssertionPreventSystemIdleSleepBit)

void
IOPMrootDomain::evaluateAssertions(IOPMDriverAssertionType newAssertions, IOPMDriverAssertionType oldAssertions)
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
		if (_aotNow) {
			IOLog("CPU assertions %d\n", (0 != (kIOPMDriverAssertionCPUBit & newAssertions)));
		}
		evaluatePolicy(_aotNow ? kStimulusNoIdleSleepPreventers : kStimulusDarkWakeEvaluate);
		if (!assertOnWakeSecs && gIOLastWakeAbsTime) {
			AbsoluteTime    now;
			clock_usec_t    microsecs;
			clock_get_uptime(&now);
			SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
			absolutetime_to_microtime(now, &assertOnWakeSecs, &microsecs);
			if (assertOnWakeReport) {
				HISTREPORT_TALLYVALUE(assertOnWakeReport, (int64_t)assertOnWakeSecs);
				DLOG("Updated assertOnWake %lu\n", (unsigned long)assertOnWakeSecs);
			}
		}
	}

	if (changedBits & NO_IDLE_SLEEP_ASSERTIONS_MASK) {
		if ((newAssertions & NO_IDLE_SLEEP_ASSERTIONS_MASK) != 0) {
			if ((oldAssertions & NO_IDLE_SLEEP_ASSERTIONS_MASK) == 0) {
				DLOG("PreventIdleSleep driver assertion raised\n");
				bool ok = updatePreventIdleSleepList(this, true);
				if (ok && (changedBits & kIOPMDriverAssertionPreventSystemIdleSleepBit)) {
					// Cancel idle sleep if there is one in progress
					cancelIdlePowerDown(this);
				}
			}
		} else {
			DLOG("PreventIdleSleep driver assertion dropped\n");
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

void
IOPMrootDomain::pmStatsRecordEvent(
	int                 eventIndex,
	AbsoluteTime        timestamp)
{
	bool        starting = eventIndex & kIOPMStatsEventStartFlag ? true:false;
	bool        stopping = eventIndex & kIOPMStatsEventStopFlag ? true:false;
	uint64_t    delta;
	uint64_t    nsec;
	OSSharedPtr<OSData> publishPMStats;

	eventIndex &= ~(kIOPMStatsEventStartFlag | kIOPMStatsEventStopFlag);

	absolutetime_to_nanoseconds(timestamp, &nsec);

	switch (eventIndex) {
	case kIOPMStatsHibernateImageWrite:
		if (starting) {
			gPMStats.hibWrite.start = nsec;
		} else if (stopping) {
			gPMStats.hibWrite.stop = nsec;
		}

		if (stopping) {
			delta = gPMStats.hibWrite.stop - gPMStats.hibWrite.start;
			IOLog("PMStats: Hibernate write took %qd ms\n", delta / NSEC_PER_MSEC);
		}
		break;
	case kIOPMStatsHibernateImageRead:
		if (starting) {
			gPMStats.hibRead.start = nsec;
		} else if (stopping) {
			gPMStats.hibRead.stop = nsec;
		}

		if (stopping) {
			delta = gPMStats.hibRead.stop - gPMStats.hibRead.start;
			IOLog("PMStats: Hibernate read took %qd ms\n", delta / NSEC_PER_MSEC);

			publishPMStats = OSData::withBytes(&gPMStats, sizeof(gPMStats));
			setProperty(kIOPMSleepStatisticsKey, publishPMStats.get());
			bzero(&gPMStats, sizeof(gPMStats));
		}
		break;
	}
}

/*
 * Appends a record of the application response to
 * IOPMrootDomain::pmStatsAppResponses
 */
void
IOPMrootDomain::pmStatsRecordApplicationResponse(
	const OSSymbol      *response,
	const char          *name,
	int                 messageType,
	uint32_t            delay_ms,
	uint64_t            id,
	OSObject            *object,
	IOPMPowerStateIndex powerState,
	bool                async)
{
	OSSharedPtr<OSDictionary>    responseDescription;
	OSSharedPtr<OSNumber>        delayNum;
	OSSharedPtr<OSNumber>        powerCaps;
	OSSharedPtr<OSNumber>        pidNum;
	OSSharedPtr<OSNumber>        msgNum;
	OSSharedPtr<const OSSymbol>  appname;
	OSSharedPtr<const OSSymbol>  sleep;
	OSSharedPtr<const OSSymbol>  wake;
	IOPMServiceInterestNotifier *notify = NULL;

	if (object && (notify = OSDynamicCast(IOPMServiceInterestNotifier, object))) {
		if (response->isEqualTo(gIOPMStatsResponseTimedOut.get())) {
			notify->ackTimeoutCnt++;
		} else {
			notify->ackTimeoutCnt = 0;
		}
	}

	if (response->isEqualTo(gIOPMStatsResponsePrompt.get()) ||
	    (_systemTransitionType == kSystemTransitionNone) || (_systemTransitionType == kSystemTransitionNewCapClient)) {
		return;
	}


	if (response->isEqualTo(gIOPMStatsDriverPSChangeSlow.get())) {
		kdebugTrace(kPMLogDrvPSChangeDelay, id, messageType, delay_ms);
	} else if (notify) {
		// User space app or kernel capability client
		if (id) {
			kdebugTrace(kPMLogAppResponseDelay, id, notify->msgType, delay_ms);
		} else {
			kdebugTrace(kPMLogDrvResponseDelay, notify->uuid0, messageType, delay_ms);
		}
		notify->msgType = 0;
	}

	responseDescription = OSDictionary::withCapacity(5);
	if (responseDescription) {
		if (response) {
			responseDescription->setObject(_statsResponseTypeKey.get(), response);
		}

		msgNum = OSNumber::withNumber(messageType, 32);
		if (msgNum) {
			responseDescription->setObject(_statsMessageTypeKey.get(), msgNum.get());
		}

		if (!name && notify && notify->identifier) {
			name = notify->identifier->getCStringNoCopy();
		}

		if (name && (strlen(name) > 0)) {
			appname = OSSymbol::withCString(name);
			if (appname) {
				responseDescription->setObject(_statsNameKey.get(), appname.get());
			}
		}

		if (!id && notify) {
			id = notify->uuid0;
		}
		if (id != 0) {
			pidNum = OSNumber::withNumber(id, 64);
			if (pidNum) {
				responseDescription->setObject(_statsPIDKey.get(), pidNum.get());
			}
		}

		delayNum = OSNumber::withNumber(delay_ms, 32);
		if (delayNum) {
			responseDescription->setObject(_statsTimeMSKey.get(), delayNum.get());
		}

		if (response->isEqualTo(gIOPMStatsDriverPSChangeSlow.get())) {
			powerCaps = OSNumber::withNumber(powerState, 32);

#if !defined(__i386__) && !defined(__x86_64__) && (DEVELOPMENT || DEBUG)
			static const char * driverCallTypes[] = {
				[kDriverCallInformPreChange]  = "powerStateWillChangeTo",
				[kDriverCallInformPostChange] = "powerStateDidChangeTo",
				[kDriverCallSetPowerState]    = "setPowerState"
			};

			if (messageType < (sizeof(driverCallTypes) / sizeof(driverCallTypes[0]))) {
				DLOG("%s[0x%qx]::%s(%u) %stook %d ms\n",
				    name, id, driverCallTypes[messageType], (uint32_t) powerState,
				    async ? "async " : "", delay_ms);
			}
#endif
		} else {
			powerCaps = OSNumber::withNumber(_pendingCapability, 32);
		}
		if (powerCaps) {
			responseDescription->setObject(_statsPowerCapsKey.get(), powerCaps.get());
		}

		sleep = OSSymbol::withCString("Sleep");
		wake = OSSymbol::withCString("Wake");
		if (_systemTransitionType == kSystemTransitionSleep) {
			responseDescription->setObject(kIOPMStatsSystemTransitionKey, sleep.get());
		} else if (_systemTransitionType == kSystemTransitionWake) {
			responseDescription->setObject(kIOPMStatsSystemTransitionKey, wake.get());
		} else if (_systemTransitionType == kSystemTransitionCapability) {
			if (CAP_LOSS(kIOPMSystemCapabilityGraphics)) {
				responseDescription->setObject(kIOPMStatsSystemTransitionKey, sleep.get());
			} else if (CAP_GAIN(kIOPMSystemCapabilityGraphics)) {
				responseDescription->setObject(kIOPMStatsSystemTransitionKey, wake.get());
			}
		}

		IOLockLock(pmStatsLock);
		if (pmStatsAppResponses && pmStatsAppResponses->getCount() < 50) {
			pmStatsAppResponses->setObject(responseDescription.get());
		}
		IOLockUnlock(pmStatsLock);
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

IOReturn
IOPMrootDomain::callPlatformFunction(
	const OSSymbol * functionName,
	bool waitForFunction,
	void * param1, void * param2,
	void * param3, void * param4 )
{
	if (pmTracer && functionName &&
	    functionName->isEqualTo(kIOPMRegisterNVRAMTracePointHandlerKey) &&
	    !pmTracer->tracePointHandler && !pmTracer->tracePointTarget) {
		uint32_t    tracePointPhases, tracePointPCI;
		uint64_t    statusCode;

		pmTracer->tracePointHandler = (IOPMTracePointHandler) param1;
		pmTracer->tracePointTarget  = (void *) param2;
		tracePointPCI               = (uint32_t)(uintptr_t) param3;
		tracePointPhases            = (uint32_t)(uintptr_t) param4;
		if ((tracePointPhases & 0xff) == kIOPMTracePointSystemSleep) {
			OSSharedPtr<IORegistryEntry> node = IORegistryEntry::fromPath( "/chosen", gIODTPlane );
			if (node) {
				OSSharedPtr<OSObject> bootRomFailureProp;
				bootRomFailureProp = node->copyProperty(kIOEFIBootRomFailureKey);
				OSData *data = OSDynamicCast(OSData, bootRomFailureProp.get());
				uint32_t bootFailureCode;
				if (data && data->getLength() == sizeof(bootFailureCode)) {
					// Failure code from EFI/BootRom is a four byte structure
					memcpy(&bootFailureCode, data->getBytesNoCopy(), sizeof(bootFailureCode));
					tracePointPCI = OSSwapBigToHostInt32(bootFailureCode);
				}
			}
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
	    functionName->isEqualTo(kIOPMInstallSystemSleepPolicyHandlerKey)) {
		if (gSleepPolicyHandler) {
			return kIOReturnExclusiveAccess;
		}
		if (!param1) {
			return kIOReturnBadArgument;
		}
		gSleepPolicyHandler = (IOPMSystemSleepPolicyHandler) param1;
		gSleepPolicyTarget  = (void *) param2;
		setProperty("IOPMSystemSleepPolicyHandler", kOSBooleanTrue);
		return kIOReturnSuccess;
	}
#endif

	return super::callPlatformFunction(
		functionName, waitForFunction, param1, param2, param3, param4);
}

void
IOPMrootDomain::kdebugTrace(uint32_t event, uint64_t id,
    uintptr_t param1, uintptr_t param2, uintptr_t param3)
{
	uint32_t code   = IODBG_POWER(event);
	uint64_t regId  = id;
	if (regId == 0) {
		regId  = getRegistryEntryID();
	}
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, code, (uintptr_t) regId, param1, param2, param3, 0);
}

void
IOPMrootDomain::tracePoint( uint8_t point )
{
	if (systemBooting) {
		return;
	}

	if (kIOPMTracePointWakeCapabilityClients == point) {
		acceptSystemWakeEvents(kAcceptSystemWakeEvents_Disable);
	}

	kdebugTrace(kPMLogSleepWakeTracePoint, 0, point, 0);
	pmTracer->tracePoint(point);
}

static void
kext_log_putc(char c)
{
	if (gKextNameEnd || gKextNamePos >= (sizeof(gKextNameBuf) - 1)) {
		return;
	}
	if (c == '(' || c == '[' || c == ' ') {
		c = 0;
		gKextNameEnd = true;
	}

	gKextNameBuf[gKextNamePos++] = c;
}

static int
kext_log(const char *fmt, ...)
{
	va_list listp;

	va_start(listp, fmt);
	_doprnt(fmt, &listp, &kext_log_putc, 16);
	va_end(listp);

	return 0;
}

static OSPtr<const OSSymbol>
copyKextIdentifierWithAddress(vm_address_t address)
{
	OSSharedPtr<const OSSymbol> identifer;

	IOLockLock(gHaltLogLock);

	gKextNameEnd = false;
	gKextNamePos = 0;
	gKextNameBuf[0] = 0;

	OSKext::printKextsInBacktrace(&address, 1, kext_log, OSKext::kPrintKextsLock | OSKext::kPrintKextsTerse);
	gKextNameBuf[sizeof(gKextNameBuf) - 1] = 0;
	identifer = OSSymbol::withCString((gKextNameBuf[0] != 0) ? gKextNameBuf : kOSKextKernelIdentifier);

	IOLockUnlock(gHaltLogLock);

	return identifer;
}

// Caller serialized using PM workloop
const char *
IOPMrootDomain::getNotificationClientName(OSObject *object)
{
	IOPMServiceInterestNotifier *notifier = (typeof(notifier))object;
	const char *clientName = "UNKNOWN";

	if (!notifier->clientName) {
		// Check for user client
		if (systemCapabilityNotifier && (((IOPMServiceInterestNotifier *) systemCapabilityNotifier.get())->handler == notifier->handler)) {
			OSNumber *clientID = NULL;
			messageClient(kIOMessageCopyClientID, object, &clientID);
			if (clientID) {
				OSSharedPtr<OSString> string(IOCopyLogNameForPID(clientID->unsigned32BitValue()), OSNoRetain);
				if (string) {
					notifier->clientName = OSSymbol::withString(string.get());
				}
				clientID->release();
			}
		} else if (notifier->identifier) {
			notifier->clientName.reset(notifier->identifier.get(), OSRetain);
		}
	}

	if (notifier->clientName) {
		clientName = notifier->clientName->getCStringNoCopy();
	}

	return clientName;
}

void
IOPMrootDomain::traceNotification(OSObject *object, bool start, uint64_t timestamp, uint32_t msgIndex)
{
	IOPMServiceInterestNotifier *notifier;

	if (systemBooting) {
		return;
	}
	notifier = OSDynamicCast(IOPMServiceInterestNotifier, object);
	if (!notifier) {
		return;
	}

	if (start) {
		pmTracer->traceDetail(notifier->uuid0 >> 32);
		kdebugTrace(kPMLogSleepWakeMessage, pmTracer->getTracePhase(),
		    (uintptr_t) notifier->msgType, (uintptr_t) notifier->uuid0, (uintptr_t) notifier->uuid1);

		// Update notifier state used for response/ack logging
		notifier->msgIndex = msgIndex;
		notifier->msgAbsTime = timestamp;

		if (msgIndex != UINT_MAX) {
			DLOG("%s[%u] to %s\n", getIOMessageString(notifier->msgType), msgIndex, getNotificationClientName(notifier));
		} else {
			DLOG("%s to %s\n", getIOMessageString(notifier->msgType), getNotificationClientName(notifier));
		}

		assert(notifierObject == NULL);
		notifierThread = current_thread();
		notifierObject.reset(notifier, OSRetain);
	} else {
		uint64_t nsec;
		uint32_t delayMS;

		SUB_ABSOLUTETIME(&timestamp, &notifier->msgAbsTime);
		absolutetime_to_nanoseconds(timestamp, &nsec);
		delayMS = (uint32_t)(nsec / 1000000ULL);
		if (delayMS > notifier->maxMsgDelayMS) {
			notifier->maxMsgDelayMS = delayMS;
		}

		assert(notifierObject == notifier);
		notifierObject.reset();
		notifierThread = NULL;
	}
}

void
IOPMrootDomain::traceNotificationAck(OSObject *object, uint32_t delay_ms)
{
	if (systemBooting) {
		return;
	}
	IOPMServiceInterestNotifier *notifier = OSDynamicCast(IOPMServiceInterestNotifier, object);
	if (!notifier) {
		return;
	}

	kdebugTrace(kPMLogDrvResponseDelay, notifier->uuid0,
	    (uintptr_t) notifier->uuid1, (uintptr_t) 0, (uintptr_t) delay_ms);

	DLOG("%s[%u] ack from %s took %d ms\n",
	    getIOMessageString(notifier->msgType), notifier->msgIndex, getNotificationClientName(notifier), delay_ms);
	if (delay_ms > notifier->maxAckDelayMS) {
		notifier->maxAckDelayMS = delay_ms;
	}
}

void
IOPMrootDomain::traceNotificationResponse(OSObject *object, uint32_t delay_ms, uint32_t ack_time_us)
{
	if (systemBooting) {
		return;
	}
	IOPMServiceInterestNotifier *notifier = OSDynamicCast(IOPMServiceInterestNotifier, object);
	if (!notifier) {
		return;
	}

	kdebugTrace(kPMLogDrvResponseDelay, notifier->uuid0,
	    (uintptr_t) notifier->uuid1, (uintptr_t)(ack_time_us / 1000), (uintptr_t) delay_ms);

	if (ack_time_us == 0) {
		// Client work is done and ack will not be forthcoming
		DLOG("%s[%u] response from %s took %d ms\n",
		    getIOMessageString(notifier->msgType), notifier->msgIndex, getNotificationClientName(notifier), delay_ms);
	} else {
		// Client needs more time and it must ack within ack_time_us
		DLOG("%s[%u] response from %s took %d ms (ack in %d us)\n",
		    getIOMessageString(notifier->msgType), notifier->msgIndex, getNotificationClientName(notifier), delay_ms, ack_time_us);
	}
}

void
IOPMrootDomain::traceFilteredNotification(OSObject *object)
{
	if ((kIOLogDebugPower & gIOKitDebug) == 0) {
		return;
	}
	if (systemBooting) {
		return;
	}
	IOPMServiceInterestNotifier *notifier = OSDynamicCast(IOPMServiceInterestNotifier, object);
	if (!notifier) {
		return;
	}

	DLOG("%s to %s dropped\n", getIOMessageString(notifier->msgType), getNotificationClientName(notifier));
}

void
IOPMrootDomain::traceDetail(uint32_t msgType, uint32_t msgIndex, uint32_t delay)
{
	if (!systemBooting) {
		uint32_t detail = ((msgType & 0xffff) << 16) | (delay & 0xffff);
		pmTracer->traceDetail( detail );
		kdebugTrace(kPMLogSleepWakeTracePoint, pmTracer->getTracePhase(), msgType, delay);
		DLOG("trace point 0x%02x msgType 0x%x detail 0x%08x\n", pmTracer->getTracePhase(), msgType, delay);
	}
}

void
IOPMrootDomain::configureReportGated(uint64_t channel_id, uint64_t action, void *result)
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
	} else if (channel_id == kSleepDelaysChID) {
		report = &sleepDelaysReport;
		bktCnt = kSleepDelaysBcktCnt;
		bktSize = kSleepDelaysBcktSize;
		clientCnt = &sleepDelaysClientCnt;
	} else {
		assert(false);
		return;
	}

	switch (action) {
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
		HISTREPORT_INIT((uint16_t)bktCnt, bktSize, *report, reportSize,
		    getRegistryEntryID(), channel_id, kIOReportCategoryPower);

		if (channel_id == kAssertDelayChID) {
			assertOnWakeSecs = 0;
		}

		break;

	case kIOReportDisable:
		if (*clientCnt == 0) {
			break;
		}
		if (*clientCnt == 1) {
			IOFree(*report, HISTREPORT_BUFSIZE(bktCnt));
			*report = NULL;
		}
		(*clientCnt)--;

		if (channel_id == kAssertDelayChID) {
			assertOnWakeSecs = -1; // Invalid value to prevent updates
		}
		break;

	case kIOReportGetDimensions:
		if (*report) {
			HISTREPORT_UPDATERES(*report, kIOReportGetDimensions, result);
		}
		break;
	}

	return;
}

IOReturn
IOPMrootDomain::configureReport(IOReportChannelList    *channelList,
    IOReportConfigureAction action,
    void                   *result,
    void                   *destination)
{
	unsigned cnt;
	uint64_t configAction = (uint64_t)action;

	for (cnt = 0; cnt < channelList->nchannels; cnt++) {
		if ((channelList->channels[cnt].channel_id == kSleepCntChID) ||
		    (channelList->channels[cnt].channel_id == kDarkWkCntChID) ||
		    (channelList->channels[cnt].channel_id == kUserWkCntChID)) {
			if (action != kIOReportGetDimensions) {
				continue;
			}
			SIMPLEREPORT_UPDATERES(kIOReportGetDimensions, result);
		} else if ((channelList->channels[cnt].channel_id == kAssertDelayChID) ||
		    (channelList->channels[cnt].channel_id == kSleepDelaysChID)) {
			gIOPMWorkLoop->runAction(
				OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::configureReportGated),
				(OSObject *)this, (void *)channelList->channels[cnt].channel_id,
				(void *)configAction, (void *)result);
		}
	}

	return super::configureReport(channelList, action, result, destination);
}

IOReturn
IOPMrootDomain::updateReportGated(uint64_t ch_id, void *result, IOBufferMemoryDescriptor *dest)
{
	uint32_t    size2cpy;
	void        *data2cpy;
	void        **report;

	ASSERT_GATED();

	report = NULL;
	if (ch_id == kAssertDelayChID) {
		report = &assertOnWakeReport;
	} else if (ch_id == kSleepDelaysChID) {
		report = &sleepDelaysReport;
	} else {
		assert(false);
		return kIOReturnBadArgument;
	}

	if (*report == NULL) {
		return kIOReturnNotOpen;
	}

	HISTREPORT_UPDATEPREP(*report, data2cpy, size2cpy);
	if (size2cpy > (dest->getCapacity() - dest->getLength())) {
		return kIOReturnOverrun;
	}

	HISTREPORT_UPDATERES(*report, kIOReportCopyChannelData, result);
	dest->appendBytes(data2cpy, size2cpy);

	return kIOReturnSuccess;
}

IOReturn
IOPMrootDomain::updateReport(IOReportChannelList      *channelList,
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

	if (action != kIOReportCopyChannelData) {
		goto exit;
	}

	for (cnt = 0; cnt < channelList->nchannels; cnt++) {
		ch_id = channelList->channels[cnt].channel_id;

		if ((ch_id == kAssertDelayChID) || (ch_id == kSleepDelaysChID)) {
			gIOPMWorkLoop->runAction(
				OSMemberFunctionCast(IOWorkLoop::Action, this, &IOPMrootDomain::updateReportGated),
				(OSObject *)this, (void *)ch_id,
				(void *)result, (void *)dest);
			continue;
		} else if ((ch_id == kSleepCntChID) ||
		    (ch_id == kDarkWkCntChID) || (ch_id == kUserWkCntChID)) {
			SIMPLEREPORT_INIT(buf, sizeof(buf), getRegistryEntryID(), ch_id, kIOReportCategoryPower);
		} else {
			continue;
		}

		if (ch_id == kSleepCntChID) {
			SIMPLEREPORT_SETVALUE(buf, sleepCnt);
		} else if (ch_id == kDarkWkCntChID) {
			SIMPLEREPORT_SETVALUE(buf, darkWakeCnt);
		} else if (ch_id == kUserWkCntChID) {
			SIMPLEREPORT_SETVALUE(buf, displayWakeCnt);
		}

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

OSPtr<PMTraceWorker>
PMTraceWorker::tracer(IOPMrootDomain * owner)
{
	OSSharedPtr<PMTraceWorker> me = OSMakeShared<PMTraceWorker>();
	if (!me || !me->init()) {
		return NULL;
	}

	DLOG("PMTraceWorker %p\n", OBFUSCATE(me.get()));

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

void
PMTraceWorker::RTC_TRACE(void)
{
	if (tracePointHandler && tracePointTarget) {
		uint32_t    wordA;

		IOLockLock(pmTraceWorkerLock);
		wordA = (loginWindowData << 24) | (coreDisplayData << 16) |
		    (coreGraphicsData << 8) | tracePhase;
		IOLockUnlock(pmTraceWorkerLock);

		tracePointHandler( tracePointTarget, traceData32, wordA );
		_LOG("RTC_TRACE wrote 0x%08x 0x%08x\n", traceData32, wordA);
	}
#if DEVELOPMENT || DEBUG
	if ((swd_panic_phase != 0) && (swd_panic_phase == tracePhase)) {
		DEBUG_LOG("Causing sleep wake failure in phase 0x%08x\n", tracePhase);
		IOLock *l = IOLockAlloc();
		IOLockLock(l);
		IOLockLock(l);
	}
#endif
}

int
PMTraceWorker::recordTopLevelPCIDevice(IOService * pciDevice)
{
	OSSharedPtr<const OSSymbol>    deviceName;
	int                 index = -1;

	IOLockLock(pmTraceWorkerLock);

	if (!pciDeviceBitMappings) {
		pciDeviceBitMappings = OSArray::withCapacity(kPMBestGuessPCIDevicesCount);
		if (!pciDeviceBitMappings) {
			goto exit;
		}
	}

	// Check for bitmask overflow.
	if (pciDeviceBitMappings->getCount() >= kPMMaxRTCBitfieldSize) {
		goto exit;
	}

	if ((deviceName = pciDevice->copyName()) &&
	    (pciDeviceBitMappings->getNextIndexOfObject(deviceName.get(), 0) == (unsigned int)-1) &&
	    pciDeviceBitMappings->setObject(deviceName.get())) {
		index = pciDeviceBitMappings->getCount() - 1;
		_LOG("PMTrace PCI array: set object %s => %d\n",
		    deviceName->getCStringNoCopy(), index);
	}

	if (!addedToRegistry && (index >= 0)) {
		addedToRegistry = owner->setProperty("PCITopLevel", this);
	}

exit:
	IOLockUnlock(pmTraceWorkerLock);
	return index;
}

bool
PMTraceWorker::serialize(OSSerialize *s) const
{
	bool ok = false;
	if (pciDeviceBitMappings) {
		IOLockLock(pmTraceWorkerLock);
		ok = pciDeviceBitMappings->serialize(s);
		IOLockUnlock(pmTraceWorkerLock);
	}
	return ok;
}

void
PMTraceWorker::tracePoint(uint8_t phase)
{
	// clear trace detail when phase begins
	if (tracePhase != phase) {
		traceData32 = 0;
	}

	tracePhase = phase;

	DLOG("trace point 0x%02x\n", tracePhase);
	RTC_TRACE();
}

void
PMTraceWorker::traceDetail(uint32_t detail)
{
	if (detail == traceData32) {
		return;
	}
	traceData32 = detail;
	RTC_TRACE();
}

void
PMTraceWorker::traceComponentWakeProgress(uint32_t component, uint32_t data)
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

void
PMTraceWorker::tracePCIPowerChange(
	change_t type, IOService *service, uint32_t changeFlags, uint32_t bitNum)
{
	uint32_t    bitMask;
	uint32_t    expectedFlag;

	// Ignore PCI changes outside of system sleep/wake.
	if ((kIOPMTracePointSleepPowerPlaneDrivers != tracePhase) &&
	    (kIOPMTracePointWakePowerPlaneDrivers != tracePhase)) {
		return;
	}

	// Only record the WillChange transition when going to sleep,
	// and the DidChange on the way up.
	changeFlags &= (kIOPMDomainWillChange | kIOPMDomainDidChange);
	expectedFlag = (kIOPMTracePointSleepPowerPlaneDrivers == tracePhase) ?
	    kIOPMDomainWillChange : kIOPMDomainDidChange;
	if (changeFlags != expectedFlag) {
		return;
	}

	// Mark this device off in our bitfield
	if (bitNum < kPMMaxRTCBitfieldSize) {
		bitMask = (1 << bitNum);

		if (kPowerChangeStart == type) {
			traceData32 |= bitMask;
			_LOG("PMTrace: Device %s started  - bit %2d mask 0x%08x => 0x%08x\n",
			    service->getName(), bitNum, bitMask, traceData32);
			owner->kdebugTrace(kPMLogPCIDevChangeStart, service->getRegistryEntryID(), traceData32, 0);
		} else {
			traceData32 &= ~bitMask;
			_LOG("PMTrace: Device %s finished - bit %2d mask 0x%08x => 0x%08x\n",
			    service->getName(), bitNum, bitMask, traceData32);
			owner->kdebugTrace(kPMLogPCIDevChangeDone, service->getRegistryEntryID(), traceData32, 0);
		}

		DLOG("trace point 0x%02x detail 0x%08x\n", tracePhase, traceData32);
		RTC_TRACE();
	}
}

uint64_t
PMTraceWorker::getPMStatusCode()
{
	return ((uint64_t)traceData32 << 32) | ((uint64_t)tracePhase);
}

uint8_t
PMTraceWorker::getTracePhase()
{
	return tracePhase;
}

uint32_t
PMTraceWorker::getTraceData()
{
	return traceData32;
}

// MARK: -
// MARK: PMHaltWorker

//******************************************************************************
// PMHaltWorker Class
//
//******************************************************************************

PMHaltWorker *
PMHaltWorker::worker( void )
{
	PMHaltWorker *  me;
	IOThread        thread;

	do {
		me = OSTypeAlloc( PMHaltWorker );
		if (!me || !me->init()) {
			break;
		}

		me->lock = IOLockAlloc();
		if (!me->lock) {
			break;
		}

		DLOG("PMHaltWorker %p\n", OBFUSCATE(me));
		me->retain(); // thread holds extra retain
		if (KERN_SUCCESS != kernel_thread_start(&PMHaltWorker::main, (void *) me, &thread)) {
			me->release();
			break;
		}
		thread_deallocate(thread);
		return me;
	} while (false);

	if (me) {
		me->release();
	}
	return NULL;
}

void
PMHaltWorker::free( void )
{
	DLOG("PMHaltWorker free %p\n", OBFUSCATE(this));
	if (lock) {
		IOLockFree(lock);
		lock = NULL;
	}
	return OSObject::free();
}

void
PMHaltWorker::main( void * arg, wait_result_t waitResult )
{
	PMHaltWorker * me = (PMHaltWorker *) arg;

	IOLockLock( gPMHaltLock );
	gPMHaltBusyCount++;
	me->depth = gPMHaltDepth;
	IOLockUnlock( gPMHaltLock );

	while (me->depth >= 0) {
		PMHaltWorker::work( me );

		IOLockLock( gPMHaltLock );
		if (++gPMHaltIdleCount >= gPMHaltBusyCount) {
			// This is the last thread to finish work on this level,
			// inform everyone to start working on next lower level.
			gPMHaltDepth--;
			me->depth = gPMHaltDepth;
			gPMHaltIdleCount = 0;
			thread_wakeup((event_t) &gPMHaltIdleCount);
		} else {
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

void
PMHaltWorker::work( PMHaltWorker * me )
{
	OSSharedPtr<IOService>     service;
	OSSet *         inner;
	AbsoluteTime    startTime, elapsedTime;
	UInt32          deltaTime;
	bool            timeout;

	while (true) {
		timeout = false;

		// Claim an unit of work from the shared pool
		IOLockLock( gPMHaltLock );
		inner = (OSSet *)gPMHaltArray->getObject(me->depth);
		if (inner) {
			service.reset(OSDynamicCast(IOService, inner->getAnyObject()), OSRetain);
			if (service) {
				inner->removeObject(service.get());
			}
		}
		IOLockUnlock( gPMHaltLock );
		if (!service) {
			break; // no more work at this depth
		}
		clock_get_uptime(&startTime);

		if (!service->isInactive() &&
		    service->setProperty(gPMHaltClientAcknowledgeKey.get(), me)) {
			IOLockLock(me->lock);
			me->startTime = startTime;
			me->service   = service.get();
			me->timeout   = false;
			IOLockUnlock(me->lock);

			service->systemWillShutdown( gPMHaltMessageType);

			// Wait for driver acknowledgement
			IOLockLock(me->lock);
			while (service->propertyExists(gPMHaltClientAcknowledgeKey.get())) {
				IOLockSleep(me->lock, me, THREAD_UNINT);
			}
			me->service = NULL;
			timeout = me->timeout;
			IOLockUnlock(me->lock);
		}

		deltaTime = computeDeltaTimeMS(&startTime, &elapsedTime);
		if ((deltaTime > kPMHaltTimeoutMS) || timeout) {
			LOG("%s driver %s (0x%llx) took %u ms\n",
			    (gPMHaltMessageType == kIOMessageSystemWillPowerOff) ?
			    "PowerOff" : "Restart",
			    service->getName(), service->getRegistryEntryID(),
			    (uint32_t) deltaTime );
			halt_log_enter("PowerOff/Restart handler completed",
			    OSMemberFunctionCast(const void *, service.get(), &IOService::systemWillShutdown),
			    elapsedTime);
		}

		me->visits++;
	}
}

void
PMHaltWorker::checkTimeout( PMHaltWorker * me, AbsoluteTime * now )
{
	UInt64          nano;
	AbsoluteTime    startTime;
	AbsoluteTime    endTime;

	endTime = *now;

	IOLockLock(me->lock);
	if (me->service && !me->timeout) {
		startTime = me->startTime;
		nano = 0;
		if (CMP_ABSOLUTETIME(&endTime, &startTime) > 0) {
			SUB_ABSOLUTETIME(&endTime, &startTime);
			absolutetime_to_nanoseconds(endTime, &nano);
		}
		if (nano > 3000000000ULL) {
			me->timeout = true;

			halt_log_enter("PowerOff/Restart still waiting on handler",
			    OSMemberFunctionCast(const void *, me->service, &IOService::systemWillShutdown),
			    endTime);
			MSG("%s still waiting on %s\n",
			    (gPMHaltMessageType == kIOMessageSystemWillPowerOff) ?  "PowerOff" : "Restart",
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

void
IOPMrootDomain::acknowledgeSystemWillShutdown( IOService * from )
{
	PMHaltWorker            * worker;
	OSSharedPtr<OSObject>     prop;

	if (!from) {
		return;
	}

	//DLOG("%s acknowledged\n", from->getName());
	prop = from->copyProperty( gPMHaltClientAcknowledgeKey.get());
	if (prop) {
		worker = (PMHaltWorker *) prop.get();
		IOLockLock(worker->lock);
		from->removeProperty( gPMHaltClientAcknowledgeKey.get());
		thread_wakeup((event_t) worker);
		IOLockUnlock(worker->lock);
	} else {
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
#define PLACEHOLDER ((OSSet *)gPMHaltArray.get())
	OSSharedPtr<IORegistryIterator>  iter;
	IORegistryEntry *                entry;
	IOService *                      node;
	OSSet *                          inner;
	OSSharedPtr<OSSet>               newInner;
	PMHaltWorker *                   workers[kPMHaltMaxWorkers];
	AbsoluteTime                     deadline;
	unsigned int                     totalNodes = 0;
	unsigned int                     depth;
	unsigned int                     rootDepth;
	unsigned int                     numWorkers;
	unsigned int                     count;
	int                              waitResult;
	void *                           baseFunc;
	bool                             ok;

	DLOG("%s msgType = 0x%x\n", __FUNCTION__, messageType);

	baseFunc = OSMemberFunctionCast(void *, root, &IOService::systemWillShutdown);

	// Iterate the entire PM tree starting from root

	rootDepth = root->getDepth( gIOPowerPlane );
	if (!rootDepth) {
		goto done;
	}

	// debug - for repeated test runs
	while (PMHaltWorker::metaClass->getInstanceCount()) {
		IOSleep(1);
	}

	if (!gPMHaltArray) {
		gPMHaltArray = OSArray::withCapacity(40);
		if (!gPMHaltArray) {
			goto done;
		}
	} else { // debug
		gPMHaltArray->flushCollection();
	}

	if (!gPMHaltLock) {
		gPMHaltLock = IOLockAlloc();
		if (!gPMHaltLock) {
			goto done;
		}
	}

	if (!gPMHaltClientAcknowledgeKey) {
		gPMHaltClientAcknowledgeKey =
		    OSSymbol::withCStringNoCopy("PMShutdown");
		if (!gPMHaltClientAcknowledgeKey) {
			goto done;
		}
	}

	gPMHaltMessageType = messageType;

	// Depth-first walk of PM plane

	iter = IORegistryIterator::iterateOver(
		root, gIOPowerPlane, kIORegistryIterateRecursively);

	if (iter) {
		while ((entry = iter->getNextObject())) {
			node = OSDynamicCast(IOService, entry);
			if (!node) {
				continue;
			}

			if (baseFunc ==
			    OSMemberFunctionCast(void *, node, &IOService::systemWillShutdown)) {
				continue;
			}

			depth = node->getDepth( gIOPowerPlane );
			if (depth <= rootDepth) {
				continue;
			}

			ok = false;

			// adjust to zero based depth
			depth -= (rootDepth + 1);

			// gPMHaltArray is an array of containers, each container
			// refers to nodes with the same depth.

			count = gPMHaltArray->getCount();
			while (depth >= count) {
				// expand array and insert placeholders
				gPMHaltArray->setObject(PLACEHOLDER);
				count++;
			}
			count = gPMHaltArray->getCount();
			if (depth < count) {
				inner = (OSSet *)gPMHaltArray->getObject(depth);
				if (inner == PLACEHOLDER) {
					newInner = OSSet::withCapacity(40);
					if (newInner) {
						gPMHaltArray->replaceObject(depth, newInner.get());
						inner = newInner.get();
					}
				}

				// PM nodes that appear more than once in the tree will have
				// the same depth, OSSet will refuse to add the node twice.
				if (inner) {
					ok = inner->setObject(node);
				}
			}
			if (!ok) {
				DLOG("Skipped PM node %s\n", node->getName());
			}
		}
	}

	// debug only
	for (int i = 0; (inner = (OSSet *)gPMHaltArray->getObject(i)); i++) {
		count = 0;
		if (inner != PLACEHOLDER) {
			count = inner->getCount();
		}
		DLOG("Nodes at depth %u = %u\n", i, count);
	}

	// strip placeholders (not all depths are populated)
	numWorkers = 0;
	for (int i = 0; (inner = (OSSet *)gPMHaltArray->getObject(i));) {
		if (inner == PLACEHOLDER) {
			gPMHaltArray->removeObject(i);
			continue;
		}
		count = inner->getCount();
		if (count > numWorkers) {
			numWorkers = count;
		}
		totalNodes += count;
		i++;
	}

	if (gPMHaltArray->getCount() == 0 || !numWorkers) {
		goto done;
	}

	gPMHaltBusyCount = 0;
	gPMHaltIdleCount = 0;
	gPMHaltDepth = gPMHaltArray->getCount() - 1;

	// Create multiple workers (and threads)

	if (numWorkers > kPMHaltMaxWorkers) {
		numWorkers = kPMHaltMaxWorkers;
	}

	DLOG("PM nodes %u, maxDepth %u, workers %u\n",
	    totalNodes, gPMHaltArray->getCount(), numWorkers);

	for (unsigned int i = 0; i < numWorkers; i++) {
		workers[i] = PMHaltWorker::worker();
	}

	// Wait for workers to exhaust all available work

	IOLockLock(gPMHaltLock);
	while (gPMHaltDepth >= 0) {
		clock_interval_to_deadline(1000, kMillisecondScale, &deadline);

		waitResult = IOLockSleepDeadline(
			gPMHaltLock, &gPMHaltDepth, deadline, THREAD_UNINT);
		if (THREAD_TIMED_OUT == waitResult) {
			AbsoluteTime now;
			clock_get_uptime(&now);

			IOLockUnlock(gPMHaltLock);
			for (unsigned int i = 0; i < numWorkers; i++) {
				if (workers[i]) {
					PMHaltWorker::checkTimeout(workers[i], &now);
				}
			}
			IOLockLock(gPMHaltLock);
		}
	}
	IOLockUnlock(gPMHaltLock);

	// Release all workers

	for (unsigned int i = 0; i < numWorkers; i++) {
		if (workers[i]) {
			workers[i]->release();
		}
		// worker also retained by it's own thread
	}

done:
	DLOG("%s done\n", __FUNCTION__);
	return;
}

// MARK: -
// MARK: Kernel Assertion

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOPMDriverAssertionID
IOPMrootDomain::createPMAssertion(
	IOPMDriverAssertionType whichAssertionBits,
	IOPMDriverAssertionLevel assertionLevel,
	IOService *ownerService,
	const char *ownerDescription)
{
	IOReturn            ret;
	IOPMDriverAssertionID     newAssertion;

	if (!pmAssertions) {
		return 0;
	}

	ret = pmAssertions->createAssertion(whichAssertionBits, assertionLevel, ownerService, ownerDescription, &newAssertion);

	if (kIOReturnSuccess == ret) {
		return newAssertion;
	} else {
		return 0;
	}
}

IOReturn
IOPMrootDomain::releasePMAssertion(IOPMDriverAssertionID releaseAssertion)
{
	if (!pmAssertions) {
		return kIOReturnInternalError;
	}

	return pmAssertions->releaseAssertion(releaseAssertion);
}


IOReturn
IOPMrootDomain::setPMAssertionLevel(
	IOPMDriverAssertionID assertionID,
	IOPMDriverAssertionLevel assertionLevel)
{
	return pmAssertions->setAssertionLevel(assertionID, assertionLevel);
}

IOPMDriverAssertionLevel
IOPMrootDomain::getPMAssertionLevel(IOPMDriverAssertionType whichAssertion)
{
	IOPMDriverAssertionType       sysLevels;

	if (!pmAssertions || whichAssertion == 0) {
		return kIOPMDriverAssertionLevelOff;
	}

	sysLevels = pmAssertions->getActivatedAssertions();

	// Check that every bit set in argument 'whichAssertion' is asserted
	// in the aggregate bits.
	if ((sysLevels & whichAssertion) == whichAssertion) {
		return kIOPMDriverAssertionLevelOn;
	} else {
		return kIOPMDriverAssertionLevelOff;
	}
}

IOReturn
IOPMrootDomain::setPMAssertionUserLevels(IOPMDriverAssertionType inLevels)
{
	if (!pmAssertions) {
		return kIOReturnNotFound;
	}

	return pmAssertions->setUserAssertionLevels(inLevels);
}

bool
IOPMrootDomain::serializeProperties( OSSerialize * s ) const
{
	if (pmAssertions) {
		pmAssertions->publishProperties();
	}
	return IOService::serializeProperties(s);
}

OSSharedPtr<OSObject>
IOPMrootDomain::copyProperty( const char * aKey) const
{
	OSSharedPtr<OSObject> obj;
	obj = IOService::copyProperty(aKey);

	if (obj) {
		return obj;
	}

	if (!strncmp(aKey, kIOPMSleepWakeWdogRebootKey,
	    sizeof(kIOPMSleepWakeWdogRebootKey))) {
		if (swd_flags & SWD_BOOT_BY_SW_WDOG) {
			return OSSharedPtr<OSBoolean>(kOSBooleanTrue, OSNoRetain);
		} else {
			return OSSharedPtr<OSBoolean>(kOSBooleanFalse, OSNoRetain);
		}
	}

	if (!strncmp(aKey, kIOPMSleepWakeWdogLogsValidKey,
	    sizeof(kIOPMSleepWakeWdogLogsValidKey))) {
		if (swd_flags & SWD_VALID_LOGS) {
			return OSSharedPtr<OSBoolean>(kOSBooleanTrue, OSNoRetain);
		} else {
			return OSSharedPtr<OSBoolean>(kOSBooleanFalse, OSNoRetain);
		}
	}

	/*
	 * XXX: We should get rid of "DesktopMode" property  when 'kAppleClamshellCausesSleepKey'
	 * is set properly in darwake from sleep. For that, kIOPMEnableClamshell msg has to be
	 * issued by DisplayWrangler on darkwake.
	 */
	if (!strcmp(aKey, "DesktopMode")) {
		if (desktopMode) {
			return OSSharedPtr<OSBoolean>(kOSBooleanTrue, OSNoRetain);
		} else {
			return OSSharedPtr<OSBoolean>(kOSBooleanFalse, OSNoRetain);
		}
	}
	if (!strcmp(aKey, "DisplayIdleForDemandSleep")) {
		if (displayIdleForDemandSleep) {
			return OSSharedPtr<OSBoolean>(kOSBooleanTrue, OSNoRetain);
		} else {
			return OSSharedPtr<OSBoolean>(kOSBooleanFalse, OSNoRetain);
		}
	}

	if (!strcmp(aKey, kIOPMDriverWakeEventsKey)) {
		OSSharedPtr<OSArray> array;
		WAKEEVENT_LOCK();
		if (_systemWakeEventsArray && _systemWakeEventsArray->getCount()) {
			OSSharedPtr<OSCollection> collection = _systemWakeEventsArray->copyCollection();
			if (collection) {
				array = OSDynamicPtrCast<OSArray>(collection);
			}
		}
		WAKEEVENT_UNLOCK();
		return os::move(array);
	}

	if (!strcmp(aKey, kIOPMSleepStatisticsAppsKey)) {
		OSSharedPtr<OSArray> array;
		IOLockLock(pmStatsLock);
		if (pmStatsAppResponses && pmStatsAppResponses->getCount()) {
			OSSharedPtr<OSCollection> collection = pmStatsAppResponses->copyCollection();
			if (collection) {
				array = OSDynamicPtrCast<OSArray>(collection);
			}
		}
		IOLockUnlock(pmStatsLock);
		return os::move(array);
	}

	if (!strcmp(aKey, kIOPMIdleSleepPreventersKey)) {
		OSArray *idleSleepList = NULL;
		gRootDomain->copySleepPreventersList(&idleSleepList, NULL);
		return OSSharedPtr<OSArray>(idleSleepList, OSNoRetain);
	}

	if (!strcmp(aKey, kIOPMSystemSleepPreventersKey)) {
		OSArray *systemSleepList = NULL;
		gRootDomain->copySleepPreventersList(NULL, &systemSleepList);
		return OSSharedPtr<OSArray>(systemSleepList, OSNoRetain);
	}

	if (!strcmp(aKey, kIOPMIdleSleepPreventersWithIDKey)) {
		OSArray *idleSleepList = NULL;
		gRootDomain->copySleepPreventersListWithID(&idleSleepList, NULL);
		return OSSharedPtr<OSArray>(idleSleepList, OSNoRetain);
	}

	if (!strcmp(aKey, kIOPMSystemSleepPreventersWithIDKey)) {
		OSArray *systemSleepList = NULL;
		gRootDomain->copySleepPreventersListWithID(NULL, &systemSleepList);
		return OSSharedPtr<OSArray>(systemSleepList, OSNoRetain);
	}
	return NULL;
}

// MARK: -
// MARK: Wake Event Reporting

void
IOPMrootDomain::copyWakeReasonString( char * outBuf, size_t bufSize )
{
	WAKEEVENT_LOCK();
	strlcpy(outBuf, gWakeReasonString, bufSize);
	WAKEEVENT_UNLOCK();
}

void
IOPMrootDomain::copyShutdownReasonString( char * outBuf, size_t bufSize )
{
	WAKEEVENT_LOCK();
	strlcpy(outBuf, gShutdownReasonString, bufSize);
	WAKEEVENT_UNLOCK();
}

//******************************************************************************
// acceptSystemWakeEvents
//
// Private control for the acceptance of driver wake event claims.
//******************************************************************************

void
IOPMrootDomain::acceptSystemWakeEvents( uint32_t control )
{
	bool logWakeReason = false;

	WAKEEVENT_LOCK();
	switch (control) {
	case kAcceptSystemWakeEvents_Enable:
		assert(_acceptSystemWakeEvents == false);
		if (!_systemWakeEventsArray) {
			_systemWakeEventsArray = OSArray::withCapacity(4);
		}
		_acceptSystemWakeEvents = (_systemWakeEventsArray != NULL);
		if (!(_aotNow && (kIOPMWakeEventAOTExitFlags & _aotPendingFlags))) {
			gWakeReasonString[0] = '\0';
			if (_systemWakeEventsArray) {
				_systemWakeEventsArray->flushCollection();
			}
		}

		// Remove stale WakeType property before system sleep
		removeProperty(kIOPMRootDomainWakeTypeKey);
		removeProperty(kIOPMRootDomainWakeReasonKey);
		break;

	case kAcceptSystemWakeEvents_Disable:
		_acceptSystemWakeEvents = false;
#if defined(XNU_TARGET_OS_OSX)
		logWakeReason = (gWakeReasonString[0] != '\0');
#else /* !defined(XNU_TARGET_OS_OSX) */
		logWakeReason = gWakeReasonSysctlRegistered;
#if DEVELOPMENT
		static int panic_allowed = -1;

		if ((panic_allowed == -1) &&
		    (PE_parse_boot_argn("swd_wakereason_panic", &panic_allowed, sizeof(panic_allowed)) == false)) {
			panic_allowed = 0;
		}

		if (panic_allowed) {
			size_t i = 0;
			// Panic if wake reason is null or empty
			for (i = 0; (i < strlen(gWakeReasonString)); i++) {
				if ((gWakeReasonString[i] != ' ') && (gWakeReasonString[i] != '\t')) {
					break;
				}
			}
			if (i >= strlen(gWakeReasonString)) {
				panic("Wake reason is empty\n");
			}
		}
#endif /* DEVELOPMENT */
#endif /* !defined(XNU_TARGET_OS_OSX) */

		// publish kIOPMRootDomainWakeReasonKey if not already set
		if (!propertyExists(kIOPMRootDomainWakeReasonKey)) {
			setProperty(kIOPMRootDomainWakeReasonKey, gWakeReasonString);
		}
		break;

	case kAcceptSystemWakeEvents_Reenable:
		assert(_acceptSystemWakeEvents == false);
		_acceptSystemWakeEvents = (_systemWakeEventsArray != NULL);
		removeProperty(kIOPMRootDomainWakeReasonKey);
		break;
	}
	WAKEEVENT_UNLOCK();

	if (logWakeReason) {
		MSG("system wake events: %s\n", gWakeReasonString);
	}
}

//******************************************************************************
// claimSystemWakeEvent
//
// For a driver to claim a device is the source/conduit of a system wake event.
//******************************************************************************

void
IOPMrootDomain::claimSystemWakeEvent(
	IOService *     device,
	IOOptionBits    flags,
	const char *    reason,
	OSObject *      details )
{
	OSSharedPtr<const OSSymbol>     deviceName;
	OSSharedPtr<OSNumber>           deviceRegId;
	OSSharedPtr<OSNumber>           claimTime;
	OSSharedPtr<OSData>             flagsData;
	OSSharedPtr<OSString>           reasonString;
	OSSharedPtr<OSDictionary>       dict;
	uint64_t                        timestamp;
	bool                            addWakeReason;

	if (!device || !reason) {
		return;
	}

	pmEventTimeStamp(&timestamp);

	IOOptionBits        aotFlags = 0;
	bool                needAOTEvaluate = FALSE;

	if (kIOPMAOTModeAddEventFlags & _aotMode) {
		if (!strcmp("hold", reason)
		    || !strcmp("help", reason)
		    || !strcmp("menu", reason)
		    || !strcmp("stockholm", reason)
		    || !strcmp("ringer", reason)
		    || !strcmp("ringerab", reason)
		    || !strcmp("smc0", reason)
		    || !strcmp("AOP.RTPWakeupAP", reason)
		    || !strcmp("BT.OutboxNotEmpty", reason)
		    || !strcmp("WL.OutboxNotEmpty", reason)) {
			flags |= kIOPMWakeEventAOTExit;
		}
	}

#if DEVELOPMENT || DEBUG
	if (_aotLingerTime && !strcmp("rtc", reason)) {
		flags |= kIOPMWakeEventAOTPossibleExit;
	}
#endif /* DEVELOPMENT || DEBUG */

#if defined(XNU_TARGET_OS_OSX) && !DISPLAY_WRANGLER_PRESENT
	// Publishing the WakeType is serialized by the PM work loop
	if (!strcmp("rtc", reason) && (_nextScheduledAlarmType != NULL)) {
		pmPowerStateQueue->submitPowerEvent(kPowerEventPublishWakeType,
		    (void *) _nextScheduledAlarmType.get());
	}

	// Workaround for the missing wake HID event
	if (gDarkWakeFlags & kDarkWakeFlagUserWakeWorkaround) {
		if (!strcmp("trackpadkeyboard", reason)) {
			pmPowerStateQueue->submitPowerEvent(kPowerEventPublishWakeType,
			    (void *) gIOPMWakeTypeUserKey.get());
		}
	}
#endif

	deviceName   = device->copyName(gIOServicePlane);
	deviceRegId  = OSNumber::withNumber(device->getRegistryEntryID(), 64);
	claimTime    = OSNumber::withNumber(timestamp, 64);
	flagsData    = OSData::withBytes(&flags, sizeof(flags));
	reasonString = OSString::withCString(reason);
	dict = OSDictionary::withCapacity(5 + (details ? 1 : 0));
	if (!dict || !deviceName || !deviceRegId || !claimTime || !flagsData || !reasonString) {
		goto done;
	}

	dict->setObject(gIONameKey, deviceName.get());
	dict->setObject(gIORegistryEntryIDKey, deviceRegId.get());
	dict->setObject(kIOPMWakeEventTimeKey, claimTime.get());
	dict->setObject(kIOPMWakeEventFlagsKey, flagsData.get());
	dict->setObject(kIOPMWakeEventReasonKey, reasonString.get());
	if (details) {
		dict->setObject(kIOPMWakeEventDetailsKey, details);
	}

	WAKEEVENT_LOCK();
	addWakeReason = _acceptSystemWakeEvents;
	if (_aotMode) {
		IOLog("claimSystemWakeEvent(%s, %s, 0x%x) 0x%x %d\n", reason, deviceName->getCStringNoCopy(), (int)flags, _aotPendingFlags, _aotReadyToFullWake);
	}
	aotFlags        = (kIOPMWakeEventAOTFlags & flags);
	aotFlags        = (aotFlags & ~_aotPendingFlags);
	needAOTEvaluate = false;
	if (_aotNow && aotFlags) {
		if (kIOPMWakeEventAOTPossibleExit & flags) {
			_aotMetrics->possibleCount++;
		}
		if (kIOPMWakeEventAOTConfirmedPossibleExit & flags) {
			_aotMetrics->confirmedPossibleCount++;
		}
		if (kIOPMWakeEventAOTRejectedPossibleExit & flags) {
			_aotMetrics->rejectedPossibleCount++;
		}
		if (kIOPMWakeEventAOTExpiredPossibleExit & flags) {
			_aotMetrics->expiredPossibleCount++;
		}

		_aotPendingFlags |= aotFlags;
		addWakeReason     = _aotNow && _systemWakeEventsArray && ((kIOPMWakeEventAOTExitFlags & aotFlags));
		needAOTEvaluate   = _aotReadyToFullWake;
	}
	DMSG("claimSystemWakeEvent(%s, 0x%x, %s, 0x%llx) aot %d phase 0x%x add %d\n",
	    reason, (int)flags, deviceName->getCStringNoCopy(), device->getRegistryEntryID(),
	    _aotNow, pmTracer->getTracePhase(), addWakeReason);

	if (!gWakeReasonSysctlRegistered) {
		// Lazy registration until the platform driver stops registering
		// the same name.
		gWakeReasonSysctlRegistered = true;
#if !defined(XNU_TARGET_OS_OSX)
		sysctl_register_oid(&sysctl__kern_wakereason);
#endif /* !defined(XNU_TARGET_OS_OSX) */
	}
	if (addWakeReason) {
		_systemWakeEventsArray->setObject(dict.get());
		if (gWakeReasonString[0] != '\0') {
			strlcat(gWakeReasonString, " ", sizeof(gWakeReasonString));
		}
		strlcat(gWakeReasonString, reason, sizeof(gWakeReasonString));
	}

	WAKEEVENT_UNLOCK();
	if (needAOTEvaluate) {
		// Call aotEvaluate() on PM work loop since it may call
		// aotExit() which accesses PM state.
		pmPowerStateQueue->submitPowerEvent(kPowerEventAOTEvaluate);
	}

done:
	return;
}

//******************************************************************************
// claimSystemBootEvent
//
// For a driver to claim a device is the source/conduit of a system boot event.
//******************************************************************************

void
IOPMrootDomain::claimSystemBootEvent(
	IOService *              device,
	IOOptionBits             flags,
	const char *             reason,
	__unused OSObject *      details )
{
	if (!device || !reason) {
		return;
	}

	DEBUG_LOG("claimSystemBootEvent(%s, %s, 0x%x)\n", reason, device->getName(), (uint32_t) flags);
	WAKEEVENT_LOCK();
	if (!gBootReasonSysctlRegistered) {
		// Lazy sysctl registration after setting gBootReasonString
		strlcat(gBootReasonString, reason, sizeof(gBootReasonString));
		sysctl_register_oid(&sysctl__kern_bootreason);
		gBootReasonSysctlRegistered = true;
	}
	WAKEEVENT_UNLOCK();
}

//******************************************************************************
// claimSystemShutdownEvent
//
// For drivers to claim a system shutdown event on the ensuing boot.
//******************************************************************************

void
IOPMrootDomain::claimSystemShutdownEvent(
	IOService *              device,
	IOOptionBits             flags,
	const char *             reason,
	__unused OSObject *      details )
{
	if (!device || !reason) {
		return;
	}

	DEBUG_LOG("claimSystemShutdownEvent(%s, %s, 0x%x)\n", reason, device->getName(), (uint32_t) flags);
	WAKEEVENT_LOCK();
	if (gShutdownReasonString[0] != '\0') {
		strlcat(gShutdownReasonString, " ", sizeof(gShutdownReasonString));
	}
	strlcat(gShutdownReasonString, reason, sizeof(gShutdownReasonString));

	if (!gShutdownReasonSysctlRegistered) {
		sysctl_register_oid(&sysctl__kern_shutdownreason);
		gShutdownReasonSysctlRegistered = true;
	}
	WAKEEVENT_UNLOCK();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// MARK: -
// MARK: PMSettingHandle

OSDefineMetaClassAndStructors( PMSettingHandle, OSObject )

void
PMSettingHandle::free( void )
{
	if (pmso) {
		pmso->clientHandleFreed();
		pmso->release();
		pmso = NULL;
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
	IOPMrootDomain                      * parent_arg,
	IOPMSettingControllerCallback       handler_arg,
	OSObject                            * target_arg,
	uintptr_t                           refcon_arg,
	uint32_t                            supportedPowerSources,
	const OSSymbol *                    settings[],
	OSObject                            * *handle_obj)
{
	uint32_t                            settingCount = 0;
	PMSettingObject                     *pmso = NULL;
	PMSettingHandle                     *pmsh = NULL;

	if (!parent_arg || !handler_arg || !settings || !handle_obj) {
		return NULL;
	}

	// count OSSymbol entries in NULL terminated settings array
	while (settings[settingCount]) {
		settingCount++;
	}
	if (0 == settingCount) {
		return NULL;
	}

	pmso = new PMSettingObject;
	if (!pmso || !pmso->init()) {
		goto fail;
	}

	pmsh = new PMSettingHandle;
	if (!pmsh || !pmsh->init()) {
		goto fail;
	}

	queue_init(&pmso->calloutQueue);
	pmso->parent       = parent_arg;
	pmso->func         = handler_arg;
	pmso->target       = target_arg;
	pmso->refcon       = refcon_arg;
	pmso->settingCount = settingCount;

	pmso->retain(); // handle holds a retain on pmso
	pmsh->pmso = pmso;
	pmso->pmsh = pmsh;

	pmso->publishedFeatureID = (uint32_t *)IOMalloc(sizeof(uint32_t) * settingCount);
	if (pmso->publishedFeatureID) {
		for (unsigned int i = 0; i < settingCount; i++) {
			// Since there is now at least one listener to this setting, publish
			// PM root domain support for it.
			parent_arg->publishPMSetting( settings[i],
			    supportedPowerSources, &pmso->publishedFeatureID[i] );
		}
	}

	*handle_obj = pmsh;
	return pmso;

fail:
	if (pmso) {
		pmso->release();
	}
	if (pmsh) {
		pmsh->release();
	}
	return NULL;
}

void
PMSettingObject::free( void )
{
	if (publishedFeatureID) {
		for (uint32_t i = 0; i < settingCount; i++) {
			if (publishedFeatureID[i]) {
				parent->removePublishedFeature( publishedFeatureID[i] );
			}
		}

		IOFree(publishedFeatureID, sizeof(uint32_t) * settingCount);
	}

	super::free();
}

IOReturn
PMSettingObject::dispatchPMSetting( const OSSymbol * type, OSObject * object )
{
	return (*func)(target, type, object, refcon);
}

void
PMSettingObject::clientHandleFreed( void )
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

PMAssertionsTracker *
PMAssertionsTracker::pmAssertionsTracker( IOPMrootDomain *rootDomain )
{
	PMAssertionsTracker    *me;

	me = new PMAssertionsTracker;
	if (!me || !me->init()) {
		if (me) {
			me->release();
		}
		return NULL;
	}

	me->owner = rootDomain;
	me->issuingUniqueID = kAssertUniqueIDStart;
	me->assertionsArray = OSArray::withCapacity(5);
	me->assertionsKernel = 0;
	me->assertionsUser = 0;
	me->assertionsCombined = 0;
	me->assertionsArrayLock = IOLockAlloc();
	me->tabulateProducerCount = me->tabulateConsumerCount = 0;

	assert(me->assertionsArray);
	assert(me->assertionsArrayLock);

	return me;
}

/* tabulate
 * - Update assertionsKernel to reflect the state of all
 * assertions in the kernel.
 * - Update assertionsCombined to reflect both kernel & user space.
 */
void
PMAssertionsTracker::tabulate(void)
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

	if (!assertionsArray) {
		return;
	}

	if ((count = assertionsArray->getCount())) {
		for (i = 0; i < count; i++) {
			_d = OSDynamicCast(OSData, assertionsArray->getObject(i));
			if (_d) {
				_a = (PMAssertStruct *)_d->getBytesNoCopy();
				if (_a && (kIOPMDriverAssertionLevelOn == _a->level)) {
					assertionsKernel |= _a->assertionBits;
				}
			}
		}
	}

	tabulateProducerCount++;
	assertionsCombined = assertionsKernel | assertionsUser;

	if ((assertionsKernel != oldKernel) ||
	    (assertionsCombined != oldCombined)) {
		owner->evaluateAssertions(assertionsCombined, oldCombined);
	}
}

void
PMAssertionsTracker::updateCPUBitAccounting( PMAssertStruct *assertStruct )
{
	AbsoluteTime now;
	uint64_t     nsec;

	if (((assertStruct->assertionBits & kIOPMDriverAssertionCPUBit) == 0) ||
	    (assertStruct->assertCPUStartTime == 0)) {
		return;
	}

	now = mach_absolute_time();
	SUB_ABSOLUTETIME(&now, &assertStruct->assertCPUStartTime);
	absolutetime_to_nanoseconds(now, &nsec);
	assertStruct->assertCPUDuration += nsec;
	assertStruct->assertCPUStartTime = 0;

	if (assertStruct->assertCPUDuration > maxAssertCPUDuration) {
		maxAssertCPUDuration = assertStruct->assertCPUDuration;
		maxAssertCPUEntryId = assertStruct->registryEntryID;
	}
}

void
PMAssertionsTracker::reportCPUBitAccounting( void )
{
	PMAssertStruct *_a;
	OSData         *_d;
	int            i, count;
	AbsoluteTime   now;
	uint64_t       nsec;

	ASSERT_GATED();

	// Account for drivers that are still holding the CPU assertion
	if (assertionsKernel & kIOPMDriverAssertionCPUBit) {
		now = mach_absolute_time();
		if ((count = assertionsArray->getCount())) {
			for (i = 0; i < count; i++) {
				_d = OSDynamicCast(OSData, assertionsArray->getObject(i));
				if (_d) {
					_a = (PMAssertStruct *)_d->getBytesNoCopy();
					if ((_a->assertionBits & kIOPMDriverAssertionCPUBit) &&
					    (_a->level == kIOPMDriverAssertionLevelOn) &&
					    (_a->assertCPUStartTime != 0)) {
						// Don't modify PMAssertStruct, leave that
						// for updateCPUBitAccounting()
						SUB_ABSOLUTETIME(&now, &_a->assertCPUStartTime);
						absolutetime_to_nanoseconds(now, &nsec);
						nsec += _a->assertCPUDuration;
						if (nsec > maxAssertCPUDuration) {
							maxAssertCPUDuration = nsec;
							maxAssertCPUEntryId = _a->registryEntryID;
						}
					}
				}
			}
		}
	}

	if (maxAssertCPUDuration) {
		DLOG("cpu assertion held for %llu ms by 0x%llx\n",
		    (maxAssertCPUDuration / NSEC_PER_MSEC), maxAssertCPUEntryId);
	}

	maxAssertCPUDuration = 0;
	maxAssertCPUEntryId = 0;
}

void
PMAssertionsTracker::publishProperties( void )
{
	OSSharedPtr<OSArray>             assertionsSummary;

	if (tabulateConsumerCount != tabulateProducerCount) {
		IOLockLock(assertionsArrayLock);

		tabulateConsumerCount = tabulateProducerCount;

		/* Publish the IOPMrootDomain property "DriverPMAssertionsDetailed"
		 */
		assertionsSummary = copyAssertionsArray();
		if (assertionsSummary) {
			owner->setProperty(kIOPMAssertionsDriverDetailedKey, assertionsSummary.get());
		} else {
			owner->removeProperty(kIOPMAssertionsDriverDetailedKey);
		}

		/* Publish the IOPMrootDomain property "DriverPMAssertions"
		 */
		owner->setProperty(kIOPMAssertionsDriverKey, assertionsKernel, 64);

		IOLockUnlock(assertionsArrayLock);
	}
}

PMAssertionsTracker::PMAssertStruct *
PMAssertionsTracker::detailsForID(IOPMDriverAssertionID _id, int *index)
{
	PMAssertStruct      *_a = NULL;
	OSData              *_d = NULL;
	int                 found = -1;
	int                 count = 0;
	int                 i = 0;

	if (assertionsArray
	    && (count = assertionsArray->getCount())) {
		for (i = 0; i < count; i++) {
			_d = OSDynamicCast(OSData, assertionsArray->getObject(i));
			if (_d) {
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
		if (index) {
			*index = found;
		}
		return _a;
	}
}

/* PMAssertionsTracker::handleCreateAssertion
 * Perform assertion work on the PM workloop. Do not call directly.
 */
IOReturn
PMAssertionsTracker::handleCreateAssertion(OSData *newAssertion)
{
	PMAssertStruct *assertStruct;

	ASSERT_GATED();

	if (newAssertion) {
		IOLockLock(assertionsArrayLock);
		assertStruct = (PMAssertStruct *) newAssertion->getBytesNoCopy();
		if ((assertStruct->assertionBits & kIOPMDriverAssertionCPUBit) &&
		    (assertStruct->level == kIOPMDriverAssertionLevelOn)) {
			assertStruct->assertCPUStartTime = mach_absolute_time();
		}
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
IOReturn
PMAssertionsTracker::createAssertion(
	IOPMDriverAssertionType which,
	IOPMDriverAssertionLevel level,
	IOService *serviceID,
	const char *whoItIs,
	IOPMDriverAssertionID *outID)
{
	OSSharedPtr<OSData>         dataStore;
	PMAssertStruct  track;

	// Warning: trillions and trillions of created assertions may overflow the unique ID.
	track.id = OSIncrementAtomic64((SInt64*) &issuingUniqueID);
	track.level = level;
	track.assertionBits = which;

	// NB: ownerString is explicitly managed by PMAssertStruct
	// it will be released in `handleReleaseAssertion' below
	track.ownerString = whoItIs ? OSSymbol::withCString(whoItIs).detach():nullptr;
	track.ownerService = serviceID;
	track.registryEntryID = serviceID ? serviceID->getRegistryEntryID():0;
	track.modifiedTime = 0;
	pmEventTimeStamp(&track.createdTime);
	track.assertCPUStartTime = 0;
	track.assertCPUDuration = 0;

	dataStore = OSData::withBytes(&track, sizeof(PMAssertStruct));
	if (!dataStore) {
		if (track.ownerString) {
			track.ownerString->release();
			track.ownerString = NULL;
		}
		return kIOReturnNoMemory;
	}

	*outID = track.id;

	if (owner && owner->pmPowerStateQueue) {
		// queue action is responsible for releasing dataStore
		owner->pmPowerStateQueue->submitPowerEvent(kPowerEventAssertionCreate, (void *)dataStore.detach());
	}

	return kIOReturnSuccess;
}

/* PMAssertionsTracker::handleReleaseAssertion
 * Runs in PM workloop. Do not call directly.
 */
IOReturn
PMAssertionsTracker::handleReleaseAssertion(
	IOPMDriverAssertionID _id)
{
	ASSERT_GATED();

	int             index;
	PMAssertStruct  *assertStruct = detailsForID(_id, &index);

	if (!assertStruct) {
		return kIOReturnNotFound;
	}

	IOLockLock(assertionsArrayLock);

	if ((assertStruct->assertionBits & kIOPMDriverAssertionCPUBit) &&
	    (assertStruct->level == kIOPMDriverAssertionLevelOn)) {
		updateCPUBitAccounting(assertStruct);
	}

	if (assertStruct->ownerString) {
		assertStruct->ownerString->release();
		assertStruct->ownerString = NULL;
	}

	assertionsArray->removeObject(index);
	IOLockUnlock(assertionsArrayLock);

	tabulate();
	return kIOReturnSuccess;
}

/* PMAssertionsTracker::releaseAssertion
 * Releases an assertion and affects system behavior if appropiate.
 * Actual work happens on PM workloop.
 */
IOReturn
PMAssertionsTracker::releaseAssertion(
	IOPMDriverAssertionID _id)
{
	if (owner && owner->pmPowerStateQueue) {
		owner->pmPowerStateQueue->submitPowerEvent(kPowerEventAssertionRelease, NULL, _id);
	}
	return kIOReturnSuccess;
}

/* PMAssertionsTracker::handleSetAssertionLevel
 * Runs in PM workloop. Do not call directly.
 */
IOReturn
PMAssertionsTracker::handleSetAssertionLevel(
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
	if ((assertStruct->assertionBits & kIOPMDriverAssertionCPUBit) &&
	    (assertStruct->level != _level)) {
		if (_level == kIOPMDriverAssertionLevelOn) {
			assertStruct->assertCPUStartTime = mach_absolute_time();
		} else {
			updateCPUBitAccounting(assertStruct);
		}
	}
	assertStruct->level = _level;
	IOLockUnlock(assertionsArrayLock);

	tabulate();
	return kIOReturnSuccess;
}

/* PMAssertionsTracker::setAssertionLevel
 */
IOReturn
PMAssertionsTracker::setAssertionLevel(
	IOPMDriverAssertionID    _id,
	IOPMDriverAssertionLevel _level)
{
	if (owner && owner->pmPowerStateQueue) {
		owner->pmPowerStateQueue->submitPowerEvent(kPowerEventAssertionSetLevel,
		    (void *)(uintptr_t)_level, _id);
	}

	return kIOReturnSuccess;
}

IOReturn
PMAssertionsTracker::handleSetUserAssertionLevels(void * arg0)
{
	IOPMDriverAssertionType new_user_levels = *(IOPMDriverAssertionType *) arg0;

	ASSERT_GATED();

	if (new_user_levels != assertionsUser) {
		DLOG("assertionsUser 0x%llx->0x%llx\n", assertionsUser, new_user_levels);
		assertionsUser = new_user_levels;
	}

	tabulate();
	return kIOReturnSuccess;
}

IOReturn
PMAssertionsTracker::setUserAssertionLevels(
	IOPMDriverAssertionType new_user_levels)
{
	if (gIOPMWorkLoop) {
		gIOPMWorkLoop->runAction(
			OSMemberFunctionCast(
				IOWorkLoop::Action,
				this,
				&PMAssertionsTracker::handleSetUserAssertionLevels),
			this,
			(void *) &new_user_levels, NULL, NULL, NULL);
	}

	return kIOReturnSuccess;
}


OSSharedPtr<OSArray>
PMAssertionsTracker::copyAssertionsArray(void)
{
	int count;
	int i;
	OSSharedPtr<OSArray>     outArray = NULL;

	if (!assertionsArray || (0 == (count = assertionsArray->getCount()))) {
		goto exit;
	}
	outArray = OSArray::withCapacity(count);
	if (!outArray) {
		goto exit;
	}

	for (i = 0; i < count; i++) {
		PMAssertStruct  *_a = NULL;
		OSData          *_d = NULL;
		OSSharedPtr<OSDictionary>    details;

		_d = OSDynamicCast(OSData, assertionsArray->getObject(i));
		if (_d && (_a = (PMAssertStruct *)_d->getBytesNoCopy())) {
			OSSharedPtr<OSNumber>        _n;

			details = OSDictionary::withCapacity(7);
			if (!details) {
				continue;
			}

			outArray->setObject(details.get());

			_n = OSNumber::withNumber(_a->id, 64);
			if (_n) {
				details->setObject(kIOPMDriverAssertionIDKey, _n.get());
			}
			_n = OSNumber::withNumber(_a->createdTime, 64);
			if (_n) {
				details->setObject(kIOPMDriverAssertionCreatedTimeKey, _n.get());
			}
			_n = OSNumber::withNumber(_a->modifiedTime, 64);
			if (_n) {
				details->setObject(kIOPMDriverAssertionModifiedTimeKey, _n.get());
			}
			_n = OSNumber::withNumber((uintptr_t)_a->registryEntryID, 64);
			if (_n) {
				details->setObject(kIOPMDriverAssertionRegistryEntryIDKey, _n.get());
			}
			_n = OSNumber::withNumber(_a->level, 64);
			if (_n) {
				details->setObject(kIOPMDriverAssertionLevelKey, _n.get());
			}
			_n = OSNumber::withNumber(_a->assertionBits, 64);
			if (_n) {
				details->setObject(kIOPMDriverAssertionAssertedKey, _n.get());
			}

			if (_a->ownerString) {
				details->setObject(kIOPMDriverAssertionOwnerStringKey, _a->ownerString);
			}
		}
	}

exit:
	return os::move(outArray);
}

IOPMDriverAssertionType
PMAssertionsTracker::getActivatedAssertions(void)
{
	return assertionsCombined;
}

IOPMDriverAssertionLevel
PMAssertionsTracker::getAssertionLevel(
	IOPMDriverAssertionType type)
{
	// FIXME: unused and also wrong
	if (type && ((type & assertionsKernel) == assertionsKernel)) {
		return kIOPMDriverAssertionLevelOn;
	} else {
		return kIOPMDriverAssertionLevelOff;
	}
}

//*********************************************************************************
//*********************************************************************************
//*********************************************************************************


static void
pmEventTimeStamp(uint64_t *recordTS)
{
	clock_sec_t     tsec;
	clock_usec_t    tusec;

	if (!recordTS) {
		return;
	}

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
	{1, 0, ON_POWER, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1, 0, ON_POWER, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

void
IORootParent::initialize( void )
{

	gIOPMPSExternalConnectedKey = OSSymbol::withCStringNoCopy(kIOPMPSExternalConnectedKey);
	gIOPMPSExternalChargeCapableKey = OSSymbol::withCStringNoCopy(kIOPMPSExternalChargeCapableKey);
	gIOPMPSBatteryInstalledKey = OSSymbol::withCStringNoCopy(kIOPMPSBatteryInstalledKey);
	gIOPMPSIsChargingKey = OSSymbol::withCStringNoCopy(kIOPMPSIsChargingKey);
	gIOPMPSAtWarnLevelKey = OSSymbol::withCStringNoCopy(kIOPMPSAtWarnLevelKey);
	gIOPMPSAtCriticalLevelKey = OSSymbol::withCStringNoCopy(kIOPMPSAtCriticalLevelKey);
	gIOPMPSCurrentCapacityKey = OSSymbol::withCStringNoCopy(kIOPMPSCurrentCapacityKey);
	gIOPMPSMaxCapacityKey = OSSymbol::withCStringNoCopy(kIOPMPSMaxCapacityKey);
	gIOPMPSDesignCapacityKey = OSSymbol::withCStringNoCopy(kIOPMPSDesignCapacityKey);
	gIOPMPSTimeRemainingKey = OSSymbol::withCStringNoCopy(kIOPMPSTimeRemainingKey);
	gIOPMPSAmperageKey = OSSymbol::withCStringNoCopy(kIOPMPSAmperageKey);
	gIOPMPSVoltageKey = OSSymbol::withCStringNoCopy(kIOPMPSVoltageKey);
	gIOPMPSCycleCountKey = OSSymbol::withCStringNoCopy(kIOPMPSCycleCountKey);
	gIOPMPSMaxErrKey = OSSymbol::withCStringNoCopy(kIOPMPSMaxErrKey);
	gIOPMPSAdapterInfoKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterInfoKey);
	gIOPMPSLocationKey = OSSymbol::withCStringNoCopy(kIOPMPSLocationKey);
	gIOPMPSErrorConditionKey = OSSymbol::withCStringNoCopy(kIOPMPSErrorConditionKey);
	gIOPMPSManufacturerKey = OSSymbol::withCStringNoCopy(kIOPMPSManufacturerKey);
	gIOPMPSManufactureDateKey = OSSymbol::withCStringNoCopy(kIOPMPSManufactureDateKey);
	gIOPMPSModelKey = OSSymbol::withCStringNoCopy(kIOPMPSModelKey);
	gIOPMPSSerialKey = OSSymbol::withCStringNoCopy(kIOPMPSSerialKey);
	gIOPMPSLegacyBatteryInfoKey = OSSymbol::withCStringNoCopy(kIOPMPSLegacyBatteryInfoKey);
	gIOPMPSBatteryHealthKey = OSSymbol::withCStringNoCopy(kIOPMPSBatteryHealthKey);
	gIOPMPSHealthConfidenceKey = OSSymbol::withCStringNoCopy(kIOPMPSHealthConfidenceKey);
	gIOPMPSCapacityEstimatedKey = OSSymbol::withCStringNoCopy(kIOPMPSCapacityEstimatedKey);
	gIOPMPSBatteryChargeStatusKey = OSSymbol::withCStringNoCopy(kIOPMPSBatteryChargeStatusKey);
	gIOPMPSBatteryTemperatureKey = OSSymbol::withCStringNoCopy(kIOPMPSBatteryTemperatureKey);
	gIOPMPSAdapterDetailsKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsKey);
	gIOPMPSChargerConfigurationKey = OSSymbol::withCStringNoCopy(kIOPMPSChargerConfigurationKey);
	gIOPMPSAdapterDetailsIDKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsIDKey);
	gIOPMPSAdapterDetailsWattsKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsWattsKey);
	gIOPMPSAdapterDetailsRevisionKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsRevisionKey);
	gIOPMPSAdapterDetailsSerialNumberKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsSerialNumberKey);
	gIOPMPSAdapterDetailsFamilyKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsFamilyKey);
	gIOPMPSAdapterDetailsAmperageKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsAmperageKey);
	gIOPMPSAdapterDetailsDescriptionKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsDescriptionKey);
	gIOPMPSAdapterDetailsPMUConfigurationKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsPMUConfigurationKey);
	gIOPMPSAdapterDetailsSourceIDKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsSourceIDKey);
	gIOPMPSAdapterDetailsErrorFlagsKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsErrorFlagsKey);
	gIOPMPSAdapterDetailsSharedSourceKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsSharedSourceKey);
	gIOPMPSAdapterDetailsCloakedKey = OSSymbol::withCStringNoCopy(kIOPMPSAdapterDetailsCloakedKey);
	gIOPMPSInvalidWakeSecondsKey = OSSymbol::withCStringNoCopy(kIOPMPSInvalidWakeSecondsKey);
	gIOPMPSPostChargeWaitSecondsKey = OSSymbol::withCStringNoCopy(kIOPMPSPostChargeWaitSecondsKey);
	gIOPMPSPostDishargeWaitSecondsKey = OSSymbol::withCStringNoCopy(kIOPMPSPostDishargeWaitSecondsKey);
}

bool
IORootParent::start( IOService * nub )
{
	IOService::start(nub);
	attachToParent( getRegistryRoot(), gIOPowerPlane );
	PMinit();
	registerPowerDriver(this, patriarchPowerStates, 2);
	makeUsable();
	return true;
}

void
IORootParent::shutDownSystem( void )
{
}

void
IORootParent::restartSystem( void )
{
}

void
IORootParent::sleepSystem( void )
{
}

void
IORootParent::dozeSystem( void )
{
}

void
IORootParent::sleepToDoze( void )
{
}

void
IORootParent::wakeSystem( void )
{
}

OSSharedPtr<OSObject>
IORootParent::copyProperty( const char * aKey) const
{
	return IOService::copyProperty(aKey);
}

uint32_t
IOPMrootDomain::getWatchdogTimeout()
{
	if (gSwdSleepWakeTimeout) {
		gSwdSleepTimeout = gSwdWakeTimeout = gSwdSleepWakeTimeout;
	}
	if ((pmTracer->getTracePhase() < kIOPMTracePointSystemSleep) ||
	    (pmTracer->getTracePhase() == kIOPMTracePointDarkWakeEntry)) {
		return gSwdSleepTimeout ? gSwdSleepTimeout : WATCHDOG_SLEEP_TIMEOUT;
	} else {
		return gSwdWakeTimeout ? gSwdWakeTimeout : WATCHDOG_WAKE_TIMEOUT;
	}
}


#if defined(__i386__) || defined(__x86_64__) || (defined(__arm64__) && HIBERNATION)
IOReturn
IOPMrootDomain::restartWithStackshot()
{
	takeStackshot(true);

	return kIOReturnSuccess;
}

void
IOPMrootDomain::sleepWakeDebugTrig(bool wdogTrigger)
{
	takeStackshot(wdogTrigger);
}

void
IOPMrootDomain::tracePhase2String(uint32_t tracePhase, const char **phaseString, const char **description)
{
	switch (tracePhase) {
	case kIOPMTracePointSleepStarted:
		*phaseString = "kIOPMTracePointSleepStarted";
		*description = "starting sleep";
		break;

	case kIOPMTracePointSleepApplications:
		*phaseString = "kIOPMTracePointSleepApplications";
		*description = "notifying applications";
		break;

	case kIOPMTracePointSleepPriorityClients:
		*phaseString = "kIOPMTracePointSleepPriorityClients";
		*description = "notifying clients about upcoming system capability changes";
		break;

	case kIOPMTracePointSleepWillChangeInterests:
		*phaseString = "kIOPMTracePointSleepWillChangeInterests";
		*description = "creating hibernation file or while calling rootDomain's clients about upcoming rootDomain's state changes";
		break;

	case kIOPMTracePointSleepPowerPlaneDrivers:
		*phaseString = "kIOPMTracePointSleepPowerPlaneDrivers";
		*description = "calling power state change callbacks";
		break;

	case kIOPMTracePointSleepDidChangeInterests:
		*phaseString = "kIOPMTracePointSleepDidChangeInterests";
		*description = "calling rootDomain's clients about rootDomain's state changes";
		break;

	case kIOPMTracePointSleepCapabilityClients:
		*phaseString = "kIOPMTracePointSleepCapabilityClients";
		*description = "notifying clients about current system capabilities";
		break;

	case kIOPMTracePointSleepPlatformActions:
		*phaseString = "kIOPMTracePointSleepPlatformActions";
		*description = "calling Quiesce/Sleep action callbacks";
		break;

	case kIOPMTracePointSleepCPUs:
	{
		*phaseString = "kIOPMTracePointSleepCPUs";
#if defined(__i386__) || defined(__x86_64__)
		/*
		 * We cannot use the getCPUNumber() method to get the cpu number, since
		 * that cpu number is unrelated to the cpu number we need (we need the cpu
		 * number as enumerated by the scheduler, NOT the CPU number enumerated
		 * by ACPIPlatform as the CPUs are enumerated in MADT order).
		 * Instead, pass the Mach processor pointer associated with the current
		 * shutdown target so its associated cpu_id can be used in
		 * processor_to_datastring.
		 */
		if (currentShutdownTarget != NULL &&
		    currentShutdownTarget->getMachProcessor() != NULL) {
			const char *sbuf = processor_to_datastring("halting all non-boot CPUs",
			    currentShutdownTarget->getMachProcessor());
			*description = sbuf;
		} else {
			*description = "halting all non-boot CPUs";
		}
#else
		*description = "halting all non-boot CPUs";
#endif
		break;
	}
	case kIOPMTracePointSleepPlatformDriver:
		*phaseString = "kIOPMTracePointSleepPlatformDriver";
		*description = "executing platform specific code";
		break;

	case kIOPMTracePointHibernate:
		*phaseString = "kIOPMTracePointHibernate";
		*description = "writing the hibernation image";
		break;

	case kIOPMTracePointSystemSleep:
		*phaseString = "kIOPMTracePointSystemSleep";
		*description = "in EFI/Bootrom after last point of entry to sleep";
		break;

	case kIOPMTracePointWakePlatformDriver:
		*phaseString = "kIOPMTracePointWakePlatformDriver";
		*description = "executing platform specific code";
		break;


	case kIOPMTracePointWakePlatformActions:
		*phaseString = "kIOPMTracePointWakePlatformActions";
		*description = "calling Wake action callbacks";
		break;

	case kIOPMTracePointWakeCPUs:
		*phaseString = "kIOPMTracePointWakeCPUs";
		*description = "starting non-boot CPUs";
		break;

	case kIOPMTracePointWakeWillPowerOnClients:
		*phaseString = "kIOPMTracePointWakeWillPowerOnClients";
		*description = "sending kIOMessageSystemWillPowerOn message to kernel and userspace clients";
		break;

	case kIOPMTracePointWakeWillChangeInterests:
		*phaseString = "kIOPMTracePointWakeWillChangeInterests";
		*description = "calling rootDomain's clients about upcoming rootDomain's state changes";
		break;

	case kIOPMTracePointWakeDidChangeInterests:
		*phaseString = "kIOPMTracePointWakeDidChangeInterests";
		*description = "calling rootDomain's clients about completed rootDomain's state changes";
		break;

	case kIOPMTracePointWakePowerPlaneDrivers:
		*phaseString = "kIOPMTracePointWakePowerPlaneDrivers";
		*description = "calling power state change callbacks";
		break;

	case kIOPMTracePointWakeCapabilityClients:
		*phaseString = "kIOPMTracePointWakeCapabilityClients";
		*description = "informing clients about current system capabilities";
		break;

	case kIOPMTracePointWakeApplications:
		*phaseString = "kIOPMTracePointWakeApplications";
		*description = "sending asynchronous kIOMessageSystemHasPoweredOn message to userspace clients";
		break;

	case kIOPMTracePointDarkWakeEntry:
		*phaseString = "kIOPMTracePointDarkWakeEntry";
		*description = "entering darkwake on way to sleep";
		break;

	case kIOPMTracePointDarkWakeExit:
		*phaseString = "kIOPMTracePointDarkWakeExit";
		*description = "entering fullwake from darkwake";
		break;

	default:
		*phaseString = NULL;
		*description = NULL;
	}
}

void
IOPMrootDomain::saveFailureData2File()
{
	unsigned int len = 0;
	char  failureStr[512];
	errno_t error;
	char *outbuf;
	OSNumber *statusCode;
	uint64_t pmStatusCode = 0;
	uint32_t phaseData = 0;
	uint32_t phaseDetail = 0;
	bool efiFailure = false;

	OSSharedPtr<OSObject> statusCodeProp = copyProperty(kIOPMSleepWakeFailureCodeKey);
	statusCode = OSDynamicCast(OSNumber, statusCodeProp.get());
	if (statusCode) {
		pmStatusCode = statusCode->unsigned64BitValue();
		phaseData = pmStatusCode & 0xFFFFFFFF;
		phaseDetail = (pmStatusCode >> 32) & 0xFFFFFFFF;
		if ((phaseData & 0xFF) == kIOPMTracePointSystemSleep) {
			LOG("Sleep Wake failure in EFI\n");
			efiFailure = true;
			failureStr[0] = 0;
			snprintf(failureStr, sizeof(failureStr), "Sleep Wake failure in EFI\n\nFailure code:: 0x%08x 0x%08x\n\nPlease IGNORE the below stackshot\n", phaseDetail, phaseData);
			len = (typeof(len))strnlen(failureStr, sizeof(failureStr));
		}
	}

	if (!efiFailure) {
		if (PEReadNVRAMProperty(kIOSleepWakeFailurePanic, NULL, &len)) {
			swd_flags |= SWD_BOOT_BY_SW_WDOG;
			PERemoveNVRAMProperty(kIOSleepWakeFailurePanic);
			// dump panic will handle saving nvram data
			return;
		}

		/* Keeping this around for capturing data during power
		 * button press */

		if (!PEReadNVRAMProperty(kIOSleepWakeFailureString, NULL, &len)) {
			DLOG("No sleep wake failure string\n");
			return;
		}
		if (len == 0) {
			DLOG("Ignoring zero byte SleepWake failure string\n");
			goto exit;
		}

		// if PMStatus code is zero, delete stackshot and return
		if (statusCode) {
			if (((pmStatusCode & 0xFFFFFFFF) & 0xFF) == 0) {
				// there was no sleep wake failure
				// this can happen if delete stackshot was called
				// before take stackshot completed. Let us delete any
				// sleep wake failure data in nvram
				DLOG("Deleting stackshot on successful wake\n");
				deleteStackshot();
				return;
			}
		}

		if (len > sizeof(failureStr)) {
			len = sizeof(failureStr);
		}
		failureStr[0] = 0;
		PEReadNVRAMProperty(kIOSleepWakeFailureString, failureStr, &len);
	}
	if (failureStr[0] != 0) {
		error = sleepWakeDebugSaveFile(kSleepWakeFailureStringFile, failureStr, len);
		if (error) {
			DLOG("Failed to save SleepWake failure string to file. error:%d\n", error);
		} else {
			DLOG("Saved SleepWake failure string to file.\n");
		}
	}

	if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock)) {
		goto exit;
	}

	if (swd_buffer) {
		unsigned int len = 0;
		errno_t error;
		char nvram_var_name_buffer[20];
		unsigned int concat_len = 0;
		swd_hdr      *hdr = NULL;


		hdr = (swd_hdr *)swd_buffer;
		outbuf = (char *)hdr + hdr->spindump_offset;
		OSBoundedArrayRef<char> boundedOutBuf(outbuf, hdr->alloc_size - hdr->spindump_offset);

		for (int i = 0; i < 8; i++) {
			snprintf(nvram_var_name_buffer, sizeof(nvram_var_name_buffer), "%s%02d", SWD_STACKSHOT_VAR_PREFIX, i + 1);
			if (!PEReadNVRAMProperty(nvram_var_name_buffer, NULL, &len)) {
				LOG("No SleepWake blob to read beyond chunk %d\n", i);
				break;
			}
			if (PEReadNVRAMProperty(nvram_var_name_buffer, boundedOutBuf.slice(concat_len, len).data(), &len) == FALSE) {
				PERemoveNVRAMProperty(nvram_var_name_buffer);
				LOG("Could not read the property :-(\n");
				break;
			}
			PERemoveNVRAMProperty(nvram_var_name_buffer);
			concat_len += len;
		}
		LOG("Concatenated length for the SWD blob %d\n", concat_len);

		if (concat_len) {
			error = sleepWakeDebugSaveFile(kSleepWakeStacksFilename, outbuf, concat_len);
			if (error) {
				LOG("Failed to save SleepWake zipped data to file. error:%d\n", error);
			} else {
				LOG("Saved SleepWake zipped data to file.\n");
			}
		} else {
			// There is a sleep wake failure string but no stackshot
			// Write a placeholder stacks file so that swd runs
			snprintf(outbuf, 20, "%s", "No stackshot data\n");
			error = sleepWakeDebugSaveFile(kSleepWakeStacksFilename, outbuf, 20);
			if (error) {
				LOG("Failed to save SleepWake zipped data to file. error:%d\n", error);
			} else {
				LOG("Saved SleepWake zipped data to file.\n");
			}
		}
	} else {
		LOG("No buffer allocated to save failure stackshot\n");
	}


	gRootDomain->swd_lock = 0;
exit:
	PERemoveNVRAMProperty(kIOSleepWakeFailureString);
	return;
}


void
IOPMrootDomain::getFailureData(thread_t *thread, char *failureStr, size_t strLen)
{
	OSSharedPtr<IORegistryIterator>    iter;
	OSSharedPtr<const OSSymbol>        kextName = NULL;
	IORegistryEntry *       entry;
	IOService *             node;
	bool                    nodeFound = false;

	const void *            callMethod = NULL;
	const char *            objectName = NULL;
	uint32_t                timeout = getWatchdogTimeout();
	const char *            phaseString = NULL;
	const char *            phaseDescription = NULL;

	IOPMServiceInterestNotifier *notifier = OSDynamicCast(IOPMServiceInterestNotifier, notifierObject.get());
	uint32_t tracePhase = pmTracer->getTracePhase();

	*thread = NULL;
	if ((tracePhase < kIOPMTracePointSystemSleep) || (tracePhase == kIOPMTracePointDarkWakeEntry)) {
		snprintf(failureStr, strLen, "Sleep transition timed out after %d seconds", timeout);
	} else {
		snprintf(failureStr, strLen, "Wake transition timed out after %d seconds", timeout);
	}
	tracePhase2String(tracePhase, &phaseString, &phaseDescription);

	if (notifierThread) {
		if (notifier && (notifier->identifier)) {
			objectName = notifier->identifier->getCStringNoCopy();
		}
		*thread = notifierThread;
	} else {
		iter = IORegistryIterator::iterateOver(
			getPMRootDomain(), gIOPowerPlane, kIORegistryIterateRecursively);

		if (iter) {
			while ((entry = iter->getNextObject())) {
				node = OSDynamicCast(IOService, entry);
				if (!node) {
					continue;
				}
				if (OSDynamicCast(IOPowerConnection, node)) {
					continue;
				}

				if (node->getBlockingDriverCall(thread, &callMethod)) {
					nodeFound = true;
					break;
				}
			}
		}
		if (nodeFound) {
			kextName = copyKextIdentifierWithAddress((vm_address_t) callMethod);
			if (kextName) {
				objectName = kextName->getCStringNoCopy();
			}
		}
	}
	if (phaseDescription) {
		strlcat(failureStr, " while ", strLen);
		strlcat(failureStr, phaseDescription, strLen);
		strlcat(failureStr, ".", strLen);
	}
	if (objectName) {
		strlcat(failureStr, " Suspected bundle: ", strLen);
		strlcat(failureStr, objectName, strLen);
		strlcat(failureStr, ".", strLen);
	}
	if (*thread) {
		char threadName[40];
		snprintf(threadName, sizeof(threadName), " Thread 0x%llx.", thread_tid(*thread));
		strlcat(failureStr, threadName, strLen);
	}

	DLOG("%s\n", failureStr);
}

struct swd_stackshot_compressed_data {
	z_output_func   zoutput;
	size_t                  zipped;
	uint64_t                totalbytes;
	uint64_t                lastpercent;
	IOReturn                error;
	unsigned                outremain;
	unsigned                outlen;
	unsigned                writes;
	Bytef *                 outbuf;
};
struct swd_stackshot_compressed_data swd_zip_var = { };

static void *
swd_zs_alloc(void *__unused ref, u_int items, u_int size)
{
	void *result;
	LOG("Alloc in zipping %d items of size %d\n", items, size);

	result = (void *)(swd_zs_zmem + swd_zs_zoffset);
	swd_zs_zoffset += ~31L & (31 + (items * size)); // 32b align for vector crc
	LOG("Offset %zu\n", swd_zs_zoffset);
	return result;
}

static int
swd_zinput(z_streamp strm, Bytef *buf, unsigned size)
{
	unsigned len;

	len = strm->avail_in;

	if (len > size) {
		len = size;
	}
	if (len == 0) {
		return 0;
	}

	if (strm->next_in != (Bytef *) strm) {
		memcpy(buf, strm->next_in, len);
	} else {
		bzero(buf, len);
	}

	strm->adler = z_crc32(strm->adler, buf, len);

	strm->avail_in -= len;
	strm->next_in  += len;
	strm->total_in += len;

	return (int)len;
}

static int
swd_zoutput(z_streamp strm, Bytef *buf, unsigned len)
{
	unsigned int i = 0;
	// if outlen > max size don't add to the buffer
	assert(buf != NULL);
	if (strm && buf) {
		if (swd_zip_var.outlen + len > SWD_COMPRESSED_BUFSIZE) {
			LOG("No space to GZIP... not writing to NVRAM\n");
			return len;
		}
	}
	for (i = 0; i < len; i++) {
		*(swd_zip_var.outbuf + swd_zip_var.outlen + i) = *(buf + i);
	}
	swd_zip_var.outlen += len;
	return len;
}

static void
swd_zs_free(void * __unused ref, void * __unused ptr)
{
}

static int
swd_compress(char *inPtr, char *outPtr, size_t numBytes)
{
	int wbits = 12;
	int memlevel = 3;

	if (((unsigned int) numBytes) != numBytes) {
		return 0;
	}

	if (!swd_zs.zalloc) {
		swd_zs.zalloc = swd_zs_alloc;
		swd_zs.zfree = swd_zs_free;
		if (deflateInit2(&swd_zs, Z_BEST_SPEED, Z_DEFLATED, wbits + 16, memlevel, Z_DEFAULT_STRATEGY)) {
			// allocation failed
			bzero(&swd_zs, sizeof(swd_zs));
			// swd_zs_zoffset = 0;
		} else {
			LOG("PMRD inited the zlib allocation routines\n");
		}
	}

	swd_zip_var.zipped = 0;
	swd_zip_var.totalbytes = 0; // should this be the max that we have?
	swd_zip_var.lastpercent = 0;
	swd_zip_var.error = kIOReturnSuccess;
	swd_zip_var.outremain = 0;
	swd_zip_var.outlen = 0;
	swd_zip_var.writes = 0;
	swd_zip_var.outbuf = (Bytef *)outPtr;

	swd_zip_var.totalbytes = numBytes;

	swd_zs.avail_in = 0;
	swd_zs.next_in = NULL;
	swd_zs.avail_out = 0;
	swd_zs.next_out = NULL;

	deflateResetWithIO(&swd_zs, swd_zinput, swd_zoutput);

	z_stream *zs;
	int zr;
	zs = &swd_zs;

	while (swd_zip_var.error >= 0) {
		if (!zs->avail_in) {
			zs->next_in = (unsigned char *)inPtr ? (Bytef *)inPtr : (Bytef *)zs; /* zero marker? */
			zs->avail_in = (unsigned int) numBytes;
		}
		if (!zs->avail_out) {
			zs->next_out = (Bytef *)zs;
			zs->avail_out = UINT32_MAX;
		}
		zr = deflate(zs, Z_NO_FLUSH);
		if (Z_STREAM_END == zr) {
			break;
		}
		if (zr != Z_OK) {
			LOG("ZERR %d\n", zr);
			swd_zip_var.error = zr;
		} else {
			if (zs->total_in == numBytes) {
				break;
			}
		}
	}

	//now flush the stream
	while (swd_zip_var.error >= 0) {
		if (!zs->avail_out) {
			zs->next_out = (Bytef *)zs;
			zs->avail_out = UINT32_MAX;
		}
		zr = deflate(zs, Z_FINISH);
		if (Z_STREAM_END == zr) {
			break;
		}
		if (zr != Z_OK) {
			LOG("ZERR %d\n", zr);
			swd_zip_var.error = zr;
		} else {
			if (zs->total_in == numBytes) {
				LOG("Total output size %d\n", swd_zip_var.outlen);
				break;
			}
		}
	}

	return swd_zip_var.outlen;
}

void
IOPMrootDomain::deleteStackshot()
{
	if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock)) {
		// takeStackshot hasn't completed
		return;
	}
	LOG("Deleting any sleepwake failure data in nvram\n");

	PERemoveNVRAMProperty(kIOSleepWakeFailureString);
	char nvram_var_name_buf[20];
	for (int i = 0; i < 8; i++) {
		snprintf(nvram_var_name_buf, sizeof(nvram_var_name_buf), "%s%02d", SWD_STACKSHOT_VAR_PREFIX, i + 1);
		if (PERemoveNVRAMProperty(nvram_var_name_buf) == false) {
			LOG("Removing %s returned false\n", nvram_var_name_buf);
		}
	}
	// force NVRAM sync
	if (PEWriteNVRAMProperty(kIONVRAMSyncNowPropertyKey, kIONVRAMSyncNowPropertyKey, (unsigned int) strlen(kIONVRAMSyncNowPropertyKey)) == false) {
		DLOG("Failed to force nvram sync\n");
	}
	gRootDomain->swd_lock = 0;
}

void
IOPMrootDomain::takeStackshot(bool wdogTrigger)
{
	swd_hdr *                hdr = NULL;
	int                      cnt = 0;
	int                      max_cnt = 2;
	pid_t                    pid = 0;
	kern_return_t            kr = KERN_SUCCESS;
	uint64_t                 flags;

	char *                   dstAddr;
	uint32_t                 size;
	uint32_t                 bytesRemaining;
	unsigned                 bytesWritten = 0;

	char                     failureStr[512];
	thread_t                 thread = NULL;
	const char *             swfPanic = "swfPanic";

	uint32_t                 bufSize;
	int                      success = 0;

#if defined(__i386__) || defined(__x86_64__)
	const bool               concise = false;
#else
	const bool               concise = true;
#endif

	if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock)) {
		return;
	}

	failureStr[0] = 0;
	if ((kIOSleepWakeWdogOff & gIOKitDebug) || systemBooting || systemShutdown || gWillShutdown) {
		return;
	}

	if (wdogTrigger) {
		getFailureData(&thread, failureStr, sizeof(failureStr));

		if (concise || (PEGetCoprocessorVersion() >= kCoprocessorVersion2)) {
			goto skip_stackshot;
		}
	} else {
		AbsoluteTime now;
		uint64_t nsec;
		clock_get_uptime(&now);
		SUB_ABSOLUTETIME(&now, &gIOLastWakeAbsTime);
		absolutetime_to_nanoseconds(now, &nsec);
		snprintf(failureStr, sizeof(failureStr), "Power button pressed during wake transition after %u ms.\n", ((int)((nsec) / NSEC_PER_MSEC)));
	}

	if (swd_buffer == NULL) {
		sleepWakeDebugMemAlloc();
		if (swd_buffer == NULL) {
			return;
		}
	}
	hdr = (swd_hdr *)swd_buffer;
	bufSize = hdr->alloc_size;

	dstAddr = (char*)hdr + hdr->spindump_offset;
	flags = STACKSHOT_KCDATA_FORMAT | STACKSHOT_NO_IO_STATS | STACKSHOT_SAVE_KEXT_LOADINFO | STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY | STACKSHOT_THREAD_WAITINFO;
	/* If not wdogTrigger only take kernel tasks stackshot
	 */
	if (wdogTrigger) {
		pid = -1;
	} else {
		pid = 0;
	}

	/* Attempt to take stackshot with all ACTIVE_KERNEL_THREADS
	 * If we run out of space, take stackshot with only kernel task
	 */
	while (success == 0 && cnt < max_cnt) {
		bytesRemaining = bufSize - hdr->spindump_offset;
		cnt++;
		DLOG("Taking snapshot. bytesRemaining: %d\n", bytesRemaining);

		size = bytesRemaining;
		kr = stack_snapshot_from_kernel(pid, dstAddr, size, flags, 0, 0, &bytesWritten);
		DLOG("stack_snapshot_from_kernel returned 0x%x. pid: %d bufsize:0x%x flags:0x%llx bytesWritten: %d\n",
		    kr, pid, size, flags, bytesWritten);
		if (kr == KERN_INSUFFICIENT_BUFFER_SIZE) {
			if (pid == -1) {
				pid = 0;
			} else {
				LOG("Insufficient buffer size for only kernel task\n");
				break;
			}
		}
		if (kr == KERN_SUCCESS) {
			if (bytesWritten == 0) {
				MSG("Failed to get stackshot(0x%x) bufsize:0x%x flags:0x%llx\n", kr, size, flags);
				continue;
			}
			bytesRemaining -= bytesWritten;
			hdr->spindump_size = (bufSize - bytesRemaining - hdr->spindump_offset);

			memset(hdr->reason, 0x20, sizeof(hdr->reason));

			// Compress stackshot and save to NVRAM
			{
				char *outbuf = (char *)swd_compressed_buffer;
				int outlen = 0;
				int num_chunks = 0;
				int max_chunks = 0;
				int leftover = 0;
				char nvram_var_name_buffer[20];

				outlen = swd_compress((char*)hdr + hdr->spindump_offset, outbuf, bytesWritten);

				if (outlen) {
					max_chunks = outlen / (2096 - 200);
					leftover = outlen % (2096 - 200);

					if (max_chunks < 8) {
						for (num_chunks = 0; num_chunks < max_chunks; num_chunks++) {
							snprintf(nvram_var_name_buffer, sizeof(nvram_var_name_buffer), "%s%02d", SWD_STACKSHOT_VAR_PREFIX, num_chunks + 1);
							if (PEWriteNVRAMPropertyWithCopy(nvram_var_name_buffer, (outbuf + (num_chunks * (2096 - 200))), (2096 - 200)) == FALSE) {
								LOG("Failed to update NVRAM %d\n", num_chunks);
								break;
							}
						}
						if (leftover) {
							snprintf(nvram_var_name_buffer, sizeof(nvram_var_name_buffer), "%s%02d", SWD_STACKSHOT_VAR_PREFIX, num_chunks + 1);
							if (PEWriteNVRAMPropertyWithCopy(nvram_var_name_buffer, (outbuf + (num_chunks * (2096 - 200))), leftover) == FALSE) {
								LOG("Failed to update NVRAM with leftovers\n");
							}
						}
						success = 1;
						LOG("Successfully saved stackshot to NVRAM\n");
					} else {
						LOG("Compressed failure stackshot is too large. size=%d bytes\n", outlen);
						if (pid == -1) {
							pid = 0;
						} else {
							LOG("Compressed failure stackshot of only kernel is too large size=%d bytes\n", outlen);
							break;
						}
					}
				}
			}
		}
	}

	if (failureStr[0]) {
		// append sleep-wake failure code
		char traceCode[80];
		snprintf(traceCode, sizeof(traceCode), "\nFailure code:: 0x%08x %08x\n",
		    pmTracer->getTraceData(), pmTracer->getTracePhase());
		strlcat(failureStr, traceCode, sizeof(failureStr));
		if (PEWriteNVRAMProperty(kIOSleepWakeFailureString, failureStr, (unsigned int) strnlen(failureStr, sizeof(failureStr))) == false) {
			DLOG("Failed to write SleepWake failure string\n");
		}
	}

	// force NVRAM sync
	if (PEWriteNVRAMProperty(kIONVRAMSyncNowPropertyKey, kIONVRAMSyncNowPropertyKey, (unsigned int) strlen(kIONVRAMSyncNowPropertyKey)) == false) {
		DLOG("Failed to force nvram sync\n");
	}

skip_stackshot:
	if (wdogTrigger) {
		if (PEGetCoprocessorVersion() < kCoprocessorVersion2) {
			if (swd_flags & SWD_BOOT_BY_SW_WDOG) {
				// If current boot is due to this watch dog trigger restart in previous boot,
				// then don't trigger again until at least 1 successful sleep & wake.
				if (!(sleepCnt && (displayWakeCnt || darkWakeCnt))) {
					LOG("Shutting down due to repeated Sleep/Wake failures\n");
					if (!tasksSuspended) {
						tasksSuspended = TRUE;
						updateTasksSuspend();
					}
					PEHaltRestart(kPEHaltCPU);
					return;
				}
			}
			if (gSwdPanic == 0) {
				LOG("Calling panic prevented by swd_panic boot-args. Calling restart");
				if (!tasksSuspended) {
					tasksSuspended = TRUE;
					updateTasksSuspend();
				}
				PEHaltRestart(kPERestartCPU);
			}
		}
		if (!concise && (PEWriteNVRAMProperty(kIOSleepWakeFailurePanic, swfPanic, (unsigned int) strlen(swfPanic)) == false)) {
			DLOG("Failed to write SleepWake failure panic key\n");
		}
#if defined(__x86_64__)
		if (thread) {
			panic_with_thread_context(0, NULL, DEBUGGER_OPTION_ATTEMPTCOREDUMPANDREBOOT, thread, "%s", failureStr);
		} else
#endif /* defined(__x86_64__) */
		{
			panic_with_options(0, NULL, DEBUGGER_OPTION_ATTEMPTCOREDUMPANDREBOOT, "%s", failureStr);
		}
	} else {
		gRootDomain->swd_lock = 0;
		return;
	}
}

void
IOPMrootDomain::sleepWakeDebugMemAlloc()
{
	vm_size_t    size = SWD_STACKSHOT_SIZE + SWD_COMPRESSED_BUFSIZE + SWD_ZLIB_BUFSIZE;

	swd_hdr      *hdr = NULL;
	void         *bufPtr = NULL;

	OSSharedPtr<IOBufferMemoryDescriptor>  memDesc;


	if (kIOSleepWakeWdogOff & gIOKitDebug) {
		return;
	}

	if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock)) {
		return;
	}

	memDesc = IOBufferMemoryDescriptor::inTaskWithOptions(
		kernel_task, kIODirectionIn | kIOMemoryMapperNone,
		size);
	if (memDesc == NULL) {
		DLOG("Failed to allocate Memory descriptor for sleepWake debug\n");
		goto exit;
	}

	bufPtr = memDesc->getBytesNoCopy();

	// Carve out memory for zlib routines
	swd_zs_zmem = (vm_offset_t)bufPtr;
	bufPtr = (char *)bufPtr + SWD_ZLIB_BUFSIZE;

	// Carve out memory for compressed stackshots
	swd_compressed_buffer = bufPtr;
	bufPtr = (char *)bufPtr + SWD_COMPRESSED_BUFSIZE;

	// Remaining is used for holding stackshot
	hdr = (swd_hdr *)bufPtr;
	memset(hdr, 0, sizeof(swd_hdr));

	hdr->signature = SWD_HDR_SIGNATURE;
	hdr->alloc_size = SWD_STACKSHOT_SIZE;

	hdr->spindump_offset = sizeof(swd_hdr);
	swd_buffer = (void *)hdr;
	swd_memDesc = os::move(memDesc);
	DLOG("SleepWake debug buffer size:0x%x spindump offset:0x%x\n", hdr->alloc_size, hdr->spindump_offset);

exit:
	gRootDomain->swd_lock = 0;
}

void
IOPMrootDomain::sleepWakeDebugSpinDumpMemAlloc()
{
#if UNUSED
	vm_size_t    size = SWD_SPINDUMP_SIZE;

	swd_hdr      *hdr = NULL;

	OSSharedPtr<IOBufferMemoryDescriptor>  memDesc;

	if (!OSCompareAndSwap(0, 1, &gRootDomain->swd_lock)) {
		return;
	}

	memDesc = IOBufferMemoryDescriptor::inTaskWithOptions(
		kernel_task, kIODirectionIn | kIOMemoryMapperNone,
		SWD_SPINDUMP_SIZE);

	if (memDesc == NULL) {
		DLOG("Failed to allocate Memory descriptor for sleepWake debug spindump\n");
		goto exit;
	}


	hdr = (swd_hdr *)memDesc->getBytesNoCopy();
	memset(hdr, 0, sizeof(swd_hdr));

	hdr->signature = SWD_HDR_SIGNATURE;
	hdr->alloc_size = size;

	hdr->spindump_offset = sizeof(swd_hdr);
	swd_spindump_buffer = (void *)hdr;
	swd_spindump_memDesc = os::move(memDesc);

exit:
	gRootDomain->swd_lock = 0;
#endif /* UNUSED */
}

void
IOPMrootDomain::sleepWakeDebugEnableWdog()
{
}

bool
IOPMrootDomain::sleepWakeDebugIsWdogEnabled()
{
	return !systemBooting && !systemShutdown && !gWillShutdown;
}

void
IOPMrootDomain::sleepWakeDebugSaveSpinDumpFile()
{
	swd_hdr *hdr = NULL;
	errno_t error = EIO;

	if (swd_spindump_buffer && gSpinDumpBufferFull) {
		hdr = (swd_hdr *)swd_spindump_buffer;

		error = sleepWakeDebugSaveFile("/var/tmp/SleepWakeDelayStacks.dump",
		    (char*)hdr + hdr->spindump_offset, hdr->spindump_size);

		if (error) {
			return;
		}

		sleepWakeDebugSaveFile("/var/tmp/SleepWakeDelayLog.dump",
		    (char*)hdr + offsetof(swd_hdr, UUID),
		    sizeof(swd_hdr) - offsetof(swd_hdr, UUID));

		gSpinDumpBufferFull = false;
	}
}

errno_t
IOPMrootDomain::sleepWakeDebugSaveFile(const char *name, char *buf, int len)
{
	struct vnode         *vp = NULL;
	vfs_context_t        ctx = vfs_context_create(vfs_context_current());
	kauth_cred_t         cred = vfs_context_ucred(ctx);
	struct vnode_attr    va;
	errno_t      error = EIO;

	if (vnode_open(name, (O_CREAT | FWRITE | O_NOFOLLOW),
	    S_IRUSR | S_IRGRP | S_IROTH, VNODE_LOOKUP_NOFOLLOW, &vp, ctx) != 0) {
		LOG("Failed to open the file %s\n", name);
		swd_flags |= SWD_FILEOP_ERROR;
		goto exit;
	}
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_nlink);
	/* Don't dump to non-regular files or files with links. */
	if (vp->v_type != VREG ||
	    vnode_getattr(vp, &va, ctx) || va.va_nlink != 1) {
		LOG("Bailing as this is not a regular file\n");
		swd_flags |= SWD_FILEOP_ERROR;
		goto exit;
	}
	VATTR_INIT(&va);
	VATTR_SET(&va, va_data_size, 0);
	vnode_setattr(vp, &va, ctx);


	if (buf != NULL) {
		error = vn_rdwr(UIO_WRITE, vp, buf, len, 0,
		    UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT, cred, (int *) NULL, vfs_context_proc(ctx));
		if (error != 0) {
			LOG("Failed to save sleep wake log. err 0x%x\n", error);
			swd_flags |= SWD_FILEOP_ERROR;
		} else {
			DLOG("Saved %d bytes to file %s\n", len, name);
		}
	}

exit:
	if (vp) {
		vnode_close(vp, FWRITE, ctx);
	}
	if (ctx) {
		vfs_context_rele(ctx);
	}

	return error;
}

#else /* defined(__i386__) || defined(__x86_64__) */

void
IOPMrootDomain::sleepWakeDebugTrig(bool restart)
{
	if (restart) {
		if (gSwdPanic == 0) {
			return;
		}
		panic("Sleep/Wake hang detected");
		return;
	}
}

void
IOPMrootDomain::takeStackshot(bool restart)
{
#pragma unused(restart)
}

void
IOPMrootDomain::deleteStackshot()
{
}

void
IOPMrootDomain::sleepWakeDebugMemAlloc()
{
}

void
IOPMrootDomain::saveFailureData2File()
{
}

void
IOPMrootDomain::sleepWakeDebugEnableWdog()
{
}

bool
IOPMrootDomain::sleepWakeDebugIsWdogEnabled()
{
	return false;
}

void
IOPMrootDomain::sleepWakeDebugSaveSpinDumpFile()
{
}

errno_t
IOPMrootDomain::sleepWakeDebugSaveFile(const char *name, char *buf, int len)
{
	return 0;
}

#endif /* defined(__i386__) || defined(__x86_64__) */

