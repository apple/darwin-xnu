/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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
#ifndef _IOKIT_IOPMPRIVATE_H
#define _IOKIT_IOPMPRIVATE_H

#include <IOKit/pwr_mgt/IOPM.h>

#pragma mark PM Timeline Logging
/**************************************************
*
* Timeline API Keys - Reports timing details for 
*   applications, drivers, and system during PM activity
*
* For kernel-internal use only
**************************************************/

// Keys for interfacing with IOPMrootDomain Timeline
/* @constant kIOPMTimelineDictionaryKey
 * @abstract RootDomain key for dictionary describing Timeline's info
 */
#define     kIOPMTimelineDictionaryKey                  "PMTimelineLogging"

/* @constant kIOPMTimelineEnabledKey
 * @abstract Boolean value indicating whether the system is recording PM events.
 * @discussion Key may be found in the dictionary at IOPMrootDomain's property 
 * kIOPMTimelineDictionaryKey. uint32_t value; may be 0.
 */
#define     kIOPMTimelineEnabledKey                     "TimelineEnabled"

/* @constant kIOMPTimelineSystemNumberTrackedKey
 * @abstract The maximum number of system power events the system may record.
 * @discussion Key may be found in the dictionary at IOPMrootDomain's property 
 * kIOPMTimelineDictionaryKey. uint32_t value; may be 0.
 */
#define     kIOPMTimelineSystemNumberTrackedKey         "TimelineSystemEventsTracked"

/* @constant kIOPMTimelineSystemBufferSizeKey
 * @abstract Size in bytes  of buffer recording system PM events
 * @discussion Key may be found in the dictionary at IOPMrootDomain's property 
 * kIOPMTimelineDictionaryKey. uint32_t value; may be 0.
 */
#define     kIOPMTimelineSystemBufferSizeKey            "TimelineSystemBufferSize"



/* @constant kIOPMEventTypeIntermediateFlag
 * @abstract This bit indicates the event is an intermediate event
 *      which must occur within a major system power event.
 */
#define kIOPMEventTypeIntermediateFlag              0x10000000

/* @enum SystemEventTypes
 * @abstract Potential system events logged in the system event record.
 */
enum {
	kIOPMEventTypeUndefined                     = 0,

    /* Event types mark driver events 
     */
    kIOPMEventTypeSetPowerStateImmediate        = 1001,
    kIOPMEventTypeSetPowerStateDelayed          = 1002,
    kIOPMEventTypePSWillChangeTo                = 1003,
    kIOPMEventTypePSDidChangeTo                 = 1004,
    kIOPMEventTypeAppResponse                   = 1005,


    /* Start and stop event types bracket major
     * system power management events.
     */
	kIOPMEventTypeSleep                         = 2001,
	kIOPMEventTypeSleepDone                     = 2002,
	kIOPMEventTypeWake                          = 3001,
	kIOPMEventTypeWakeDone                      = 3002,
	kIOPMEventTypeDoze                          = 4001,
	kIOPMEventTypeDozeDone                      = 4002,
	kIOPMEventTypeLiteWakeUp                    = 5001,
	kIOPMEventTypeLiteWakeUpDone                = 5002,
	kIOPMEventTypeLiteWakeDown                  = 5003,
	kIOPMEventTypeLiteWakeDownDone              = 5004,
	kIOPMEventTypeUUIDSet                       = 6001,
	kIOPMEventTypeUUIDClear                     = 6002,

    /* Intermediate events that may only occur within the bounds
     * of a major system event (between the event's initiation and its "done event".)
     * e.g. chronologically kIOPMEventTypeSleep may be followed by one or more
     *      intermediate events, which then must be followed by kIOPMEventTypeSleepDone.
     *
     * The intermediate events below will always occur in a Sleep or Wake event, and may
     *      or may not occur for any of the other events.
     */
    kIOPMEventTypeAppNotificationsFinished      = 501 | kIOPMEventTypeIntermediateFlag,
    kIOPMEventTypeDriverNotificationsFinished   = 502 | kIOPMEventTypeIntermediateFlag,
    kIOPMEventTypeCalTimeChange                 = 503 | kIOPMEventTypeIntermediateFlag
};


/* @enum SystemSleepReasons 
 * @abstract The potential causes for system sleep as logged in the system event record.
 */
enum {
    kIOPMSleepReasonClamshell                   = 101,
    kIOPMSleepReasonPowerButton                 = 102,
    kIOPMSleepReasonSoftware                    = 103,
    kIOPMSleepReasonOSSwitchHibernate           = 104,
    kIOPMSleepReasonIdle                        = 105,
    kIOPMSleepReasonLowPower                    = 106,
    kIOPMSleepReasonThermalEmergency            = 107,
    kIOPMSleepReasonMaintenance                 = 108
};

/*
 * Possible C-string sleep reasons found under kRootDomainSleepReasonsKey
 */
#define kIOPMClamshellSleepKey                      "Clamshell Sleep"
#define kIOPMPowerButtonSleepKey                    "Power Button Sleep"
#define kIOPMSoftwareSleepKey                       "Software Sleep"
#define kIOPMOSSwitchHibernationKey                 "OS Switch Sleep"
#define kIOPMIdleSleepKey                           "Idle Sleep"
#define kIOPMLowPowerSleepKey                       "Low Power Sleep"
#define kIOPMThermalEmergencySleepKey               "Thermal Emergency Sleep"


enum {
    kIOPMMaxSystemEventsTracked = 25000,
    kIOPMDefaultSystemEventsTracked = 1000,
    kMaxPMStringLength = 40,
};

/* @struct IOPMSystemEventRecord
 * @abstract Records a singe power event to a particular PM entity.
 * This includes changes to a driver's power state, application responses
 * to PM notifications, or system power management milestones.
 */
typedef struct {
    union {
        // For DRIVER events
        char        ownerName[kMaxPMStringLength];
        // For SYSTEM events, uuid contains the string describing the active UUID
        char        uuid[kMaxPMStringLength];
    };

    // For DRIVER events - records the name of the driver who generated the notifications.
    char        interestName[kMaxPMStringLength];
    
    // DRIVER & SYSTEM - Times are stored as uint64_t
    // The high 32 bytes are the seconds returned from clock_get_calendar_microtime, 
    // and the low 32 bytes are the accompanying microseconds.
    uint64_t    timestamp;

    union {
        // For DRIVER events - ownerDisambiguateID is a unique descriptor of the driver, to disambiguate
        // several similarly named drivers.
        uint64_t    ownerDisambiguateID;
        // For SYSTEM events - eventReason is a value in SystemSleepReason
        uint64_t    eventReason;
    };
    
    // DRIVER & SYSTEM - eventType is one of 'SystemEventTypes'
    // The value of eventType determines, among ohter things, whether this is a SYSTEM or
    //      DRIVER event type.
    uint32_t    eventType;

    // DRIVER & SYSTEM - eventResult is an IOReturn value
    uint32_t    eventResult;

    // DRIVER - If defined, elapsedTimeUS records the entire time a transaction took to complete
    uint32_t    elapsedTimeUS;

    // DRIVER - in power state changes, oldState & newState are PM power state indices.
    uint8_t     oldState;
    uint8_t     newState;
} IOPMSystemEventRecord;

/* @struct IOPMTraceBufferHeader
 * Occupies the first bytes in the buffer allocated by IOPMrootDomain
 * Describes the size and current index of the trace buffer
 */
typedef struct {
	uint32_t	sizeBytes;
	uint32_t    sizeEntries;
	uint32_t    index;
} IOPMTraceBufferHeader;

/* Argument to IOPMrootDomain::clientMemoryForType to acquire
 * memory mapping.
 */
enum {
    kPMRootDomainMapTraceBuffer = 1
};

/**************************************************
*
* Accountability API Ends here
*
**************************************************/


#pragma mark Stray Bitfields
// Private power commands issued to root domain
// bits 0-7 in IOPM.h

enum {
    kIOPMSetValue                   = (1<<16),
    // don't sleep on clamshell closure on a portable with AC connected
    kIOPMSetDesktopMode             = (1<<17),
    // set state of AC adaptor connected
    kIOPMSetACAdaptorConnected      = (1<<18)
};

/*****************************************************************************/
/*****************************************************************************/

/*
 * PM notification types
 */

/* @constant kIOPMStateConsoleUserShutdown
 * @abstract Notification of GUI shutdown state available to kexts.
 * @discussion This type can be passed as arguments to registerPMSettingController()
 * to receive callbacks.
 */
#define kIOPMStateConsoleShutdown   "ConsoleShutdown"

/* @enum ShutdownValues
 * @abstract Potential values shared with key kIOPMStateConsoleUserShutdown
 */
enum {
/* @constant kIOPMStateConsoleShutdownNone
 * @abstract System shutdown (or restart) hasn't started; system is ON.
 * @discussion Next state: 2
 */
    kIOPMStateConsoleShutdownNone   = 1,
/* @constant kIOPMStateConsoleShutdownPossible
 * @abstract User has been presented with the option to shutdown or restart. Shutdown may be cancelled.
 * @discussion Next state may be: 1, 4
 */
    kIOPMStateConsoleShutdownPossible = 2,
/* @constant kIOPMStateConsoleShutdownUnderway
 * @abstract Shutdown or restart is proceeding. It may still be cancelled.
 * @discussion Next state may be: 1, 4. This state is currently unused.
 */
    kIOPMStateConsoleShutdownUnderway = 3,
/* @constant kIOPMStateConsoleShutdownCertain
 * @abstract Shutdown is in progress and irrevocable.
 * @discussion State remains 4 until power is removed from CPU.
 */
    kIOPMStateConsoleShutdownCertain = 4
};

/*****************************************************************************/
/*****************************************************************************/

/* PM Statistics - event indices 
 * These are arguments to IOPMrootDomain::pmStatsRecordEvent().
 */
enum {
    kIOPMStatsHibernateImageWrite         = 1,
    kIOPMStatsHibernateImageRead,
    kIOPMStatsDriversNotify,
    kIOPMStatsApplicationNotify,
    kIOPMStatsLateDriverAcknowledge,
    kIOPMStatsLateAppAcknowledge,
    
    // To designate if you're specifying the start or stop end of 
    // each of the above events, do a bitwise OR of the appropriate
    // Start/Stop flag and pass the result to IOPMrootDomain to record
    // the event.
    kIOPMStatsEventStartFlag              = (1 << 24),
    kIOPMStatsEventStopFlag               = (1 << 25)
};

// Keys for IOPMrootDomain registry properties
#define kIOPMSleepStatisticsKey                 "SleepStatistics"
#define kIOPMSleepStatisticsAppsKey             "AppStatistics"

// Application response statistics
#define kIOPMStatsNameKey                       "Name"
#define kIOPMStatsPIDKey                        "Pid"
#define kIOPMStatsTimeMSKey                     "TimeMS"
#define kIOPMStatsApplicationResponseTypeKey    "ResponseType"
#define kIOPMStatsMessageTypeKey                "MessageType"
 
// PM Statistics: potential values for the key kIOPMStatsApplicationResponseTypeKey
// entry in the application results array.
#define kIOPMStatsResponseTimedOut      "ResponseTimedOut"
#define kIOPMStatsResponseCancel        "ResponseCancel"
#define kIOPMStatsResponseSlow          "ResponseSlow"

typedef struct {
    struct bounds{
        uint64_t start;
        uint64_t stop;
    };
    
    struct bounds    hibWrite;
    struct bounds    hibRead;
//    bounds    driverNotifySleep;
//    bounds    driverNotifyWake;
//    bounds    appNotifySleep;
//    bounds    appNotifyWake;  
//    OSDictionary    *tardyApps;    
//    OSDictionary    *tardyDrivers;
} PMStatsStruct;

/*****************************************************************************/

/* PM RootDomain tracePoints
 *
 * In the sleep/wake process, we expect the sleep trace points to proceed
 * in increasing order. Once sleep begins with code kIOPMTracePointSleepStarted,
 * we expect sleep to continue in a monotonically increasing order of tracepoints
 * to kIOPMTracePointSystemLoginwindowPhase. After trace point SystemLoginWindowPhase,
 * the system will return to kIOPMTracePointSystemUp.
 *
 * If the trace point decreases (instead of increasing) before reaching kIOPMTracePointSystemUp,
 * that indicates that the sleep process was cancelled. The cancel reason shall be indicated
 * in the cancel tracepoint. (TBD)
 */

enum {
/* When kTracePointSystemUp is the latest tracePoint,
 * the system is awake. It is not asleep, sleeping, or waking.
 *
 * Phase begins: At boot, at completion of wake from sleep,
 *      immediately following kIOPMTracePointSystemLoginwindowPhase.
 * Phase ends: When a sleep attempt is initiated.
 */
    kIOPMTracePointSystemUp                     = 0,

/* When kIOPMTracePointSleepStarted is the latest tracePoint,
 * sleep has been initiated.
 *
 * Phase begins: At initiation of system sleep (idle or forced).
 * Phase ends: PM starts to notify applications of system sleep.
 */
    kIOPMTracePointSleepStarted                 = 0x10,

/* When kIOPMTracePointSleepApplications is the latest tracePoint,
 * a system sleep has been initiated and PM waits for responses
 * from notified applications.
 *
 * Phase begins: Begin to asynchronously fire kIOMessageSystemWillSleep
 *      notifications, and also kIOMessageCanSystemSleep for the idle sleep case.
 * Phase ends: When PM has received all application responses.
 */
    kIOPMTracePointSleepApplications            = 0x11,

/* When kIOPMTracePointSleepPriorityClients is the latest tracePoint,
 * PM is notifying priority clients and in-kernel system capability
 * clients, and waiting for any asynchronous completions.
 *
 * Phase begins: Synchronous delivery of kIOMessageSystemWillSleep notifications.
 * Phase ends: All notified clients have acknowledged.
 */
    kIOPMTracePointSleepPriorityClients         = 0x12,
    
/* When kIOPMTracePointSleepWillChangeInterests is the latest tracePoint,
 * PM is calling powerStateWillChangeTo() on interested drivers of root domain.
 *
 * Phase begins: Dispatch a callout thread to call interested drivers.
 * Phase ends: Callout thread work done, and acknowledgePowerChange() called
 *      by drivers that indicated asynchronous completion.
 */
    kIOPMTracePointSleepWillChangeInterests     = 0x13,

/* When kIOPMTracePointSleepPowerPlaneDrivers is the latest tracePoint,
 * PM is directing power plane drivers to power off in leaf-to-root order.
 *
 * Phase begins: Root domain informs its power children that it will drop to
 *      sleep state. This has a cascade effect and triggers all drivers in
 *      the power plane to transition to a lower power state if necessary.
 * Phase ends: All power transitions in response to the root domain power
 *      change have completed.
 */
    kIOPMTracePointSleepPowerPlaneDrivers       = 0x14,
    
/* When kIOPMTracePointSleepDidChangeInterests is the latest tracePoint,
 * PM is calling powerStateDidChangeTo() on interested drivers of root domain.
 *
 * Phase begins: Dispatch a callout thread to call interested drivers.
 * Phase ends: Callout thread work done, and acknowledgePowerChange() called
 *      by drivers that indicated asynchronous completion.
 */
    kIOPMTracePointSleepDidChangeInterests      = 0x15,

/* When kIOPMTracePointSleepCapabilityClients is the latest tracePoint,
 * PM is notifying system capability clients about system sleep.
 *
 * Phase begins: Send kIOMessageSystemCapabilityChange notifications to inform
 *      capability clients that system has lost all capabilities.
 * Phase ends: Finished sending notifications.
 */
    kIOPMTracePointSleepCapabilityClients       = 0x16,

/* When kIOPMTracePointSleepPlatformActions is the latest tracePoint,
 * PM is calling drivers that have registered a platform sleep action.
 */
    kIOPMTracePointSleepPlatformActions         = 0x17,

/* When kIOPMTracePointSleepCPUs is the latest tracePoint,
 * PM is shutting down all non-boot processors.
 *
 * Phase begins: Shutdown all non-boot processors.
 * Phase ends: Reduced to only the boot processor running.
 */
    kIOPMTracePointSleepCPUs                    = 0x18,

/* When kIOPMTracePointSleepPlatformDriver is the latest tracePoint,
 * PM is executing platform dependent code to prepare for system sleep.
 */
    kIOPMTracePointSleepPlatformDriver          = 0x19,

/* When kIOPMTracePointHibernate is the latest tracePoint,
 * PM is writing the hibernate image to disk.
 */
    kIOPMTracePointHibernate                    = 0x1a,

/* When kIOPMTracePointSystemSleep is the latest tracePoint,
 * PM has recorded the final trace point before the hardware platform
 * enters sleep state, or low level wakeup is underway - such as restoring
 * the hibernate image from disk.
 *
 * Note: If a system is asleep and then loses power, and it does not have a
 * hibernate image to restore from (e.g. hibernatemode = 0), then OS X will
 * interpret this power loss as a failure in kIOPMTracePointSystemSleep.
 *
 * Phase begins: Before the OS directs the hardware to enter sleep state.
 * Phase ends: Control returns to the OS on wake, but before recording the first
 *      wake trace point.
 */
    kIOPMTracePointSystemSleep                  = 0x1f,

/* When kIOPMTracePointWakePlatformDriver is the latest tracePoint,
 * PM is executing platform dependent code to prepare for system wake.
 */
    kIOPMTracePointWakePlatformDriver           = 0x21,

/* When kIOPMTracePointWakePlatformActions is the latest tracePoint,
 * PM is calling drivers that have registered a platform wake action.
 */
    kIOPMTracePointWakePlatformActions          = 0x22,

/* When kIOPMTracePointWakeCPUs is the latest tracePoint,
 * PM is bringing all non-boot processors online.
 */
    kIOPMTracePointWakeCPUs                     = 0x23,

/* When kIOPMTracePointWakeWillPowerOnClients is the latest tracePoint,
 * PM is sending kIOMessageSystemWillPowerOn to both kernel clients and
 * applications. PM also notifies system capability clients about the
 * proposed capability change.
 *
 * Phase begins: Send kIOMessageSystemWillPowerOn and
 *      kIOMessageSystemCapabilityChange notifications.
 * Phase ends: Finished sending notifications.
 */
    kIOPMTracePointWakeWillPowerOnClients       = 0x24,

/* When kIOPMTracePointWakeWillChangeInterests is the latest tracePoint,
 * PM is calling powerStateWillChangeTo() on interested drivers of root domain.
 *
 * Phase begins: Dispatch a callout thread to call interested drivers.
 * Phase ends: Callout thread work done, and acknowledgePowerChange() called
 *      by drivers that indicated asynchronous completion.
 */
    kIOPMTracePointWakeWillChangeInterests      = 0x25,

/* When kIOPMTracePointWakeDidChangeInterests is the latest tracePoint,
 * PM is calling powerStateDidChangeTo() on interested drivers of root domain.
 *
 * Phase begins: Dispatch a callout thread to call interested drivers.
 * Phase ends: Callout thread work done, and acknowledgePowerChange() called
 *      by drivers that indicated asynchronous completion.
 */
    kIOPMTracePointWakeDidChangeInterests       = 0x26,

/* When kIOPMTracePointWakePowerPlaneDrivers is the latest tracePoint,
 * PM is directing power plane drivers to power up in root-to-leaf order.
 *
 * Phase begins: Root domain informs its power children that it transitioned
 *      to ON state. This has a cascade effect and triggers all drivers in
 *      the power plane to re-evaluate and potentially change power state.
 * Phase ends: All power transitions in response to the root domain power
 *      change have completed.
 */
    kIOPMTracePointWakePowerPlaneDrivers        = 0x27,

/* When kIOPMTracePointWakeCapabilityClients is the latest tracePoint,
 * PM is notifying system capability clients about system wake, and waiting
 * for any asynchronous completions.
 *
 * Phase begins: Inform capability clients that system has gained capabilities.
 * Phase ends: All notified clients have acknowledged.
 */
    kIOPMTracePointWakeCapabilityClients        = 0x28,

/* When kIOPMTracePointWakeApplications is the latest tracePoint,
 * System CPU is powered, PM has powered on each driver.
 *
 * Phase begins: Send asynchronous kIOMessageSystemHasPoweredOn notifications.
 * Phase ends: Finished sending asynchronous notifications.
 */
    kIOPMTracePointWakeApplications             = 0x29,

/* kIOPMTracePointSystemLoginwindowPhase
 * This phase represents a several minute window after the system has powered on.
 * Higher levels of system diagnostics are in a heightened state of alert in this phase,
 * in case any user errors occurred that we could not detect in software.
 *
 * Phase begins: After IOPMrootDomain sends kIOMessageSystemHasPoweredOn message.
 * Phase ends: When loginwindow calls IOPMSleepWakeSetUUID(NULL) the system shall 
 *      be considered awake and usable. The next phase shall be kIOPMTracePointSystemUp.
 */
    kIOPMTracePointSystemLoginwindowPhase       = 0x30,

/* When kIOPMTracePointDarkWakeEntry is the latest tracePoint,
 * PM has started a transition from full wake to dark wake.
 *
 * Phase begins: Start transition to dark wake.
 * Phase ends: System in dark wake. Before recording kIOPMTracePointSystemUp.
 */
    kIOPMTracePointDarkWakeEntry                = 0x31,

/* When kIOPMTracePointDarkWakeExit is the latest tracePoint,
 * PM has started a transition from dark wake to full wake.
 *
 * Phase begins: Start transition to full wake.
 * Phase ends: System in full wake. Before recording kIOPMTracePointSystemUp.
 */
    kIOPMTracePointDarkWakeExit                 = 0x32
};

/*****************************************************************************/

/*
Ê* kIOPMLoginWindowSecurityDebugKey - identifies PM debug data specific to LoginWindow
 *  for use with IOPMrootDomain.
Ê*/
#define kIOPMLoginWindowSecurityDebugKey        "LoginWindowSecurity"

// For PM internal use only - key to locate sleep failure results within SCDynamicStore.
#define kIOPMDynamicStoreSleepFailureKey        "SleepFailure"

/*****************************************************************************/

// For IOPMLibPrivate.h
#define kIOPMSleepWakeFailureKey            "PMFailurePhase"
#define kIOPMSleepWakeFailureCodeKey        "PMStatusCode"
#define kIOPMSleepWakeFailureLoginKey       "LWFailurePhase"
#define kIOPMSleepWakeFailureUUIDKey        "UUID"
#define kIOPMSleepWakeFailureDateKey        "Date"

/******************************************************************************/
/* System sleep policy
 * Shared between PM root domain and platform driver.
 */

// Platform specific property added by the platform driver.
// An OSData that describes the system sleep policy.
#define kIOPlatformSystemSleepPolicyKey     "IOPlatformSystemSleepPolicy"

// Root domain property updated before platform sleep.
// An OSData that describes the system sleep parameters.
#define kIOPMSystemSleepParametersKey       "IOPMSystemSleepParameters"

struct IOPMSystemSleepParameters
{
    uint32_t    version;
    uint32_t    sleepFlags;
    uint32_t    sleepTimer;
    uint32_t    wakeEvents;
};

// Sleep flags
enum {
    kIOPMSleepFlagHibernate         = 0x00000001,
    kIOPMSleepFlagSleepTimerEnable  = 0x00000002
};

#endif /* ! _IOKIT_IOPMPRIVATE_H */
