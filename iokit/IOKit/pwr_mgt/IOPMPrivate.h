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

/*****************************************************************************/

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
 * in increasing order. Once sleep begins with code kIOPMTracePointSleepStarted = 0x11,
 * we expect sleep to continue in a monotonically increasing order of tracepoints
 * to kIOPMTracePointSystemLoginwindowPhase = 0x30. After trace point SystemLoginWindowPhase,
 * the system will return to kIOPMTracePointSystemUp = 0x00.
 *
 * If the trace point decreases (instead of increasing) before reaching kIOPMTracePointSystemUp,
 * that indicates that the sleep process was cancelled. The cancel reason shall be indicated
 * in the cancel tracepoint. (TBD)
 */

enum {
/* When kTracePointSystemUp is the latest tracePoint,
   the system is awake. It is not asleep, sleeping, or waking.
   
   * Phase begins: At boot, at completion of wake from sleep,
          immediately following kIOPMTracePointSystemLoginwindowPhase.
   * Phase ends: When a sleep attempt is initiated.
 */
    kIOPMTracePointSystemUp                     = 0,

/* When kIOPMTracePointSleepStarted we have just initiated sleep.

    Note: The state prior to kIOPMTracePointSleepStarted may be only one of:
        * kIOPMTracePointSystemUp
        * kIOPMTracePointSystemLoginwindowPhase or 

   * Phase begins: At initiation of system sleep (idle or forced).
   * Phase ends: As we start to notify applications of system sleep.
 */
    kIOPMTracePointSleepStarted             = 0x11,

/* When kTracePointSystemSleepAppsPhase is the latest tracePoint,
   a system sleep has been irrevocably inititated and PM waits
   for responses from notified applications.

   * Phase begins: Begin to asynchronously fire kIOMessageSystemWillSleep notifications,
   *        and in the case of an idle sleep kIOMessageCanSystemSleep as well.
   * Phase ends: When we have received all user & interested kernel acknowledgements.
 */
    kIOPMTracePointSystemSleepAppsPhase         = 0x12,


/* When kIOPMTracePointSystemHibernatePhase is the latest tracePoint,
    PM is writing the hiernate image to disk.
 */
    kIOPMTracePointSystemHibernatePhase         = 0x13,

/* When kTracePointSystemSleepDriversPhase is the latest tracePoint,
    PM is iterating the driver tree powering off devices individually.

   * Phase begins: When IOPMrootDomain has received all of its power acknowledgements and begins
   *        executing IOService::powerDomainWillChangeTo()
   * Phase ends: When IOPMrootDomain::powerChangeDone begins executing CPU shutoff code.
 */
    kIOPMTracePointSystemSleepDriversPhase      = 0x14,

/* When kTracePointSystemSleepPlatformPhase is the latest tracePoint,
    all apps and drivers have notified of sleep. Plotfarm is powering
    off CPU; or system is asleep; or low level wakeup is underway.

    Note: If a system is asleep and then loses power, and it does not have a hibernate
        image to restore from (e.g. hibernatemode = 0), then OS X may interpret this power
        loss as a system crash in the kTracePointSystemSleepPlatformPhase, since the
        power loss resembles a hang or crash, and the power being removed by the user.

   * Phase begins: IOPMrootDomain has already shut off drivers, and is now powering off CPU.
   * Phase ends: Immediately after CPU's are powered back on during wakeup.
 */
    kIOPMTracePointSystemSleepPlatformPhase     = 0x15,

/* When kTracePointSystemWakeDriversPhase is the latest tracePoint,
    System CPU is powered, PM is notifying drivers of system wake.

   * Phase begins: CPU's have successfully powered up and OS is executing.
   * Phase ends: All drivers have handled power events & acknowledged completion.
        IOPMrootDomain is about to deliver kIOMessageSystemHasPoweredOn.
 */
    kIOPMTracePointSystemWakeDriversPhase       = 0x21,

/* When kTracePointSystemWakeAppsPhase is the latest tracePoint,
   System CPU is powered, PM has powered on each driver.

   * Phase begins: IOPMrootDomain::tellChangeUp before sending asynchronous 
        kIOMessageSystemHasPoweredOn notifications
   * Phase ends: IOPMrootDomain::tellChangeUp after sending asynchronous notifications
 */
    kIOPMTracePointSystemWakeAppsPhase          = 0x22,

/* kIOPMTracePointSystemLoginwindowPhase
    This phase represents a several minute window after the system has powered on.
    Higher levels of system diagnostics are in a heightened state of alert in this phase,
    in case any user errors occurred that we could not detect in software.
    
    This several minute window  

   * Phase begins: After IOPMrootDomain sends kIOMessageSystemHasPoweredOn message.
   * Phase ends: When loginwindow calls IOPMSleepWakeSetUUID(NULL) the system shall 
        be considered awake and usable. The next phase shall be kIOPMTracePointSystemUp.
 */
    kIOPMTracePointSystemLoginwindowPhase       = 0x30 
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

#endif /* ! _IOKIT_IOPMPRIVATE_H */

