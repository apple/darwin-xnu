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
#ifndef _IOKIT_IOPM_H
#define _IOKIT_IOPM_H

#include <IOKit/IOTypes.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOReturn.h>

#ifdef __ppc__
#include <IOKit/pwr_mgt/IOPMDeprecated.h>
#endif



enum {
    kIOPMMaxPowerStates = 10,
    IOPMMaxPowerStates = kIOPMMaxPowerStates
};

typedef unsigned long IOPMPowerFlags;
enum {
    // The following  bits are used in the input and output power fields.
    kIOPMClockNormal                = 0x0004,
    kIOPMClockRunning               = 0x0008,
    // Reserved - Used only between root and root parent.
    kIOPMAuxPowerOn                 = 0x0020,
    // Reserved - kIOPMPagingAvailable used only by now-defunct paging plexus
    kIOPMPagingAvailable            = 0x0020,
    kIOPMPassThrough                = 0x0100,
    kIOPMDoze                       = 0x0400,
    // Obsolete - use kIOPMDoze instead of kIOPMSoftSleep
    kIOPMSoftSleep                  = 0x0400,
    kIOPMSleep                      = 0x0001,
    kIOPMRestart                    = 0x0080,

    // The following bits are used in the capabilites field and the power fields
    kIOPMPowerOn                    = 0x0002,
    kIOPMPreventSystemSleep         = 0x0010,
    kIOPMPreventIdleSleep           = 0x0040,

    // The following  bits are used in the capabilites field only.
    // Used between a driver and its policy-maker
    kIOPMNotAttainable              = 0x0001,
    // Used internally in a power domain parent
    kIOPMChildClamp                 = 0x0080,
    // Used internally in a power domain parent
    kIOPMChildClamp2                = 0x0200,
    // Marks device as usable in this state
    kIOPMDeviceUsable               = 0x8000,
    // Device runs at max performance in this state
    kIOPMMaxPerformance             = 0x4000,
    kIOPMContextRetained            = 0x2000,
    kIOPMConfigRetained             = 0x1000,
    // Device is capable of system sleep in this state
    kIOPMSleepCapability            = 0x0004,
    kIOPMRestartCapability          = 0x0080,

    // Reserved - Error code. (this is an error return rather than a bit)
    kIOPMNotPowerManaged            = 0x0800,
    // Therefore this bit safely overloads it
    kIOPMStaticPowerValid           = 0x0800,
    
    kIOPMCapabilitiesMask =     kIOPMPowerOn | kIOPMDeviceUsable | 
                                kIOPMMaxPerformance | kIOPMContextRetained | 
                                kIOPMConfigRetained | kIOPMSleepCapability |
                                kIOPMRestartCapability
};


enum {
    IOPMNotAttainable           = kIOPMNotAttainable,
    IOPMPowerOn                 = kIOPMPowerOn,
    IOPMClockNormal             = kIOPMClockNormal,
    IOPMClockRunning            = kIOPMClockRunning,
    IOPMAuxPowerOn              = kIOPMAuxPowerOn,
    IOPMDeviceUsable            = kIOPMDeviceUsable,
    IOPMMaxPerformance          = kIOPMMaxPerformance,
    IOPMContextRetained         = kIOPMContextRetained,
    IOPMConfigRetained          = kIOPMConfigRetained,
    IOPMNotPowerManaged         = kIOPMNotPowerManaged,
    IOPMPagingAvailable         = kIOPMPagingAvailable,
    IOPMSoftSleep               = kIOPMSoftSleep
};


enum {
    kIOPMNextHigherState        = 1,
    kIOPMHighestState           = 2,
    kIOPMNextLowerState         = 3,
    kIOPMLowestState            = 4
};

enum {
    IOPMNextHigherState         = kIOPMNextHigherState,
    IOPMHighestState            = kIOPMHighestState,
    IOPMNextLowerState          = kIOPMNextLowerState,
    IOPMLowestState             = kIOPMLowestState
};

// Internal commands used by power managment command queue
enum {
    kIOPMBroadcastAggressiveness = 1,
    kIOPMUnidleDevice
};

// Power consumption unknown value
enum {
    kIOPMUnknown = 0xFFFF
};

/*******************************************************************************
 *
 * Root Domain property keys of interest
 *
 ******************************************************************************/

/* AppleClamshellState 
 * reflects the state of the clamshell (lid) on a portable.
 * It has a boolean value.
 *  true        == clamshell is closed
 *  false       == clamshell is open
 *  not present == no clamshell on this hardware
 */
#define kAppleClamshellStateKey             "AppleClamshellState"

/* AppleClamshellCausesSleep 
 * reflects the clamshell close behavior on a portable. 
 * It has a boolean value.
 *  true        == system will sleep when clamshell is closed
 *  false       == system will not sleep on clamshell close 
 *                  (typically external display mode)
 *  not present == no clamshell on this hardware
 */
#define kAppleClamshellCausesSleepKey       "AppleClamshellCausesSleep"

/*******************************************************************************
 *
 * Root Domain general interest messages
 *
 ******************************************************************************/

/* kIOPMMessageClamshellStateChange
 * Delivered as a general interest notification on the IOPMrootDomain
 * IOPMrootDomain sends this message when state of either AppleClamshellState
 * or AppleClamshellCausesSleep changes. If this clamshell change results in
 * a sleep, the sleep will initiate soon AFTER delivery of this message.
 * The state of both variables is encoded in a bitfield argument sent with
 * the message. Check bits 0 and 1 using kClamshellStateBit & kClamshellSleepBit
 */
enum {
    kClamshellStateBit = (1 << 0),
    kClamshellSleepBit = (1 << 1)
};

#define kIOPMMessageClamshellStateChange   \
                iokit_family_msg(sub_iokit_powermanagement, 0x100)

/* kIOPMMessageFeatureChange
 * Delivered when the set of supported features ("Supported Features" dictionary
 * under IOPMrootDomain registry) changes in some way. Typically addition or
 * removal of a supported feature.
 * RootDomain passes no argument with this message.
 */
#define kIOPMMessageFeatureChange           \
                iokit_family_msg(sub_iokit_powermanagement, 0x110)

/* kIOPMMessageInflowDisableCancelled
 * The battery has drained completely to its "Fully Discharged" state. 
 * If a user process has disabled battery inflow for battery 
 * calibration, we forcibly re-enable Inflow at this point.
 * If inflow HAS been forcibly re-enabled, bit 0
 * (kInflowForciblyEnabledBit) will be set.
 */
enum {
    kInflowForciblyEnabledBit = (1 << 0)
};

#define kIOPMMessageInternalBatteryFullyDischarged  \
                iokit_family_msg(sub_iokit_powermanagement, 0x120)


/*******************************************************************************
 *
 * Power commands issued to root domain
 *
 * These commands are issued from system drivers only:
 *      ApplePMU, AppleSMU, IOGraphics, AppleACPIFamily
 *
 ******************************************************************************/
enum {
  kIOPMSleepNow                 = (1<<0),  // put machine to sleep now
  kIOPMAllowSleep               = (1<<1),  // allow idle sleep
  kIOPMPreventSleep             = (1<<2),  // do not allow idle sleep
  kIOPMPowerButton              = (1<<3),  // power button was pressed
  kIOPMClamshellClosed          = (1<<4),  // clamshell was closed
  kIOPMPowerEmergency           = (1<<5),  // battery dangerously low
  kIOPMDisableClamshell         = (1<<6),  // do not sleep on clamshell closure
  kIOPMEnableClamshell          = (1<<7),  // sleep on clamshell closure
  kIOPMProcessorSpeedChange     = (1<<8),  // change the processor speed
  kIOPMOverTemp                 = (1<<9),  // system dangerously hot
  kIOPMClamshellOpened          = (1<<10)  // clamshell was opened
};

/*******************************************************************************
 *
 * Power Management Return Codes
 *
 ******************************************************************************/
enum {
    kIOPMNoErr                  = 0,
    // Returned by powerStateWillChange and powerStateDidChange:
    // Immediate acknowledgement of power state change
    kIOPMAckImplied             = 0,
    // Acknowledgement of power state change will come later 
    kIOPMWillAckLater           = 1,
    
    // Returned by requestDomainState:
    // Unrecognized specification parameter
    kIOPMBadSpecification       = 4,
    // No power state matches search specification
    kIOPMNoSuchState            = 5,
    
    // Device cannot change its power for some reason
    kIOPMCannotRaisePower       = 6,
    
  // Returned by changeStateTo:
    // Requested state doesn't exist
    kIOPMParameterError         = 7,
    // Device not yet fully hooked into power management
    kIOPMNotYetInitialized      = 8,

    // And the old constants; deprecated
    IOPMNoErr = kIOPMNoErr,
    IOPMAckImplied = kIOPMAckImplied, 
    IOPMWillAckLater = kIOPMWillAckLater,
    IOPMBadSpecification = kIOPMBadSpecification,
    IOPMNoSuchState = kIOPMNoSuchState,
    IOPMCannotRaisePower = kIOPMCannotRaisePower,
    IOPMParameterError = kIOPMParameterError,
    IOPMNotYetInitialized = kIOPMNotYetInitialized
};


// IOPMPowerSource class descriptive strings
// Power Source state is published as properties to the IORegistry under these 
// keys.
#define kIOPMPSExternalConnectedKey                 "ExternalConnected"
#define kIOPMPSExternalChargeCapableKey             "ExternalChargeCapable"
#define kIOPMPSBatteryInstalledKey                  "BatteryInstalled"
#define kIOPMPSIsChargingKey                        "IsCharging"
#define kIOPMFullyChargedKey                        "FullyCharged"
#define kIOPMPSAtWarnLevelKey                       "AtWarnLevel"
#define kIOPMPSAtCriticalLevelKey                   "AtCriticalLevel"
#define kIOPMPSCurrentCapacityKey                   "CurrentCapacity"
#define kIOPMPSMaxCapacityKey                       "MaxCapacity"
#define kIOPMPSDesignCapacityKey                    "DesignCapacity"
#define kIOPMPSTimeRemainingKey                     "TimeRemaining"
#define kIOPMPSAmperageKey                          "Amperage"
#define kIOPMPSVoltageKey                           "Voltage"
#define kIOPMPSCycleCountKey                        "CycleCount"
#define kIOPMPSMaxErrKey                            "MaxErr"
#define kIOPMPSAdapterInfoKey                       "AdapterInfo"
#define kIOPMPSLocationKey                          "Location"
#define kIOPMPSErrorConditionKey                    "ErrorCondition"
#define kIOPMPSManufacturerKey                      "Manufacturer"
#define kIOPMPSManufactureDateKey                   "ManufactureDate"
#define kIOPMPSModelKey                             "Model"
#define kIOPMPSSerialKey                            "Serial"
#define kIOPMDeviceNameKey                          "DeviceName"
#define kIOPMPSLegacyBatteryInfoKey                 "LegacyBatteryInfo"
#define kIOPMPSBatteryHealthKey                     "BatteryHealth"
#define kIOPMPSHealthConfidenceKey                  "HealthConfidence"

// Definitions for battery location, in case of multiple batteries.
// A location of 0 is unspecified
// Location is undefined for single battery systems
enum {
    kIOPMPSLocationLeft = 1001,
    kIOPMPSLocationRight = 1002
};

// Battery quality health types, specified by BatteryHealth and HealthConfidence
// properties in an IOPMPowerSource battery kext.
enum {
    kIOPMUndefinedValue = 0,
    kIOPMPoorValue      = 1,
    kIOPMFairValue      = 2,
    kIOPMGoodValue      = 3
};

// Battery's time remaining estimate is invalid this long (seconds) after a wake
#define kIOPMPSInvalidWakeSecondsKey           "BatteryInvalidWakeSeconds"

// Battery must wait this long (seconds) after being completely charged before
// the battery is settled.
#define kIOPMPSPostChargeWaitSecondsKey        "PostChargeWaitSeconds"

// Battery must wait this long (seconds) after being completely discharged 
// before the battery is settled.
#define kIOPMPSPostDishargeWaitSecondsKey      "PostDischargeWaitSeconds"



// PM Settings Controller setting types
// Settings types used primarily with:
//      IOPMrootDomain::registerPMSettingController
// The values are identical to the similarly named keys for use in user space
// PM settings work. Those keys are defined in IOPMLibPrivate.h.
#define kIOPMSettingWakeOnRingKey                   "Wake On Modem Ring"
#define kIOPMSettingRestartOnPowerLossKey           "Automatic Restart On Power Loss"
#define kIOPMSettingWakeOnACChangeKey               "Wake On AC Change"
#define kIOPMSettingSleepOnPowerButtonKey           "Sleep On Power Button"
#define kIOPMSettingWakeOnClamshellKey              "Wake On Clamshell Open"
#define kIOPMSettingReduceBrightnessKey             "ReduceBrightness"
#define kIOPMSettingDisplaySleepUsesDimKey          "Display Sleep Uses Dim"
#define kIOPMSettingTimeZoneOffsetKey               "TimeZoneOffsetSeconds"
#define kIOPMSettingMobileMotionModuleKey           "MobileMotionModule"

// Setting controlling drivers can register to receive scheduled wake data
// Either in "CF seconds" type, or structured calendar data in a formatted
// IOPMCalendarStruct defined below.
#define kIOPMSettingAutoWakeSecondsKey              "wake"
#define kIOPMSettingAutoWakeCalendarKey             "WakeByCalendarDate"
#define kIOPMSettingAutoPowerSecondsKey             "poweron"
#define kIOPMSettingAutoPowerCalendarKey            "PowerByCalendarDate"

// Debug seconds auto wake
// Used by sleep cycling debug tools
#define kIOPMSettingDebugWakeRelativeKey            "WakeRelativeToSleep"
#define kIOPMSettingDebugPowerRelativeKey           "PowerRelativeToShutdown"

struct IOPMCalendarStruct {
    UInt32      year;
    UInt8       month;
    UInt8       day;
    UInt8       hour;
    UInt8       minute;
    UInt8       second;
};
typedef struct IOPMCalendarStruct IOPMCalendarStruct;

// SetAggressiveness types
enum {
    kPMGeneralAggressiveness = 0,
    kPMMinutesToDim,
    kPMMinutesToSpinDown,
    kPMMinutesToSleep,
    kPMEthernetWakeOnLANSettings,
    kPMSetProcessorSpeed,
    kPMPowerSource,
    kPMMotionSensor,
    kPMLastAggressivenessType
};
#define kMaxType (kPMLastAggressivenessType-1)

// SetAggressiveness values for the kPMPowerSource aggressiveness type
enum {
    kIOPMInternalPower = 1,
    kIOPMExternalPower
};

#define kIOREMSleepEnabledKey               "REMSleepEnabled"

// Strings for deciphering the dictionary returned from IOPMCopyBatteryInfo
#define kIOBatteryInfoKey                   "IOBatteryInfo"
#define kIOBatteryCurrentChargeKey          "Current"
#define kIOBatteryCapacityKey               "Capacity"
#define kIOBatteryFlagsKey                  "Flags"
#define kIOBatteryVoltageKey                "Voltage"
#define kIOBatteryAmperageKey               "Amperage"
#define kIOBatteryCycleCountKey             "Cycle Count"

enum {
    kIOBatteryInstalled         = (1 << 2),
    kIOBatteryCharge            = (1 << 1),
    kIOBatteryChargerConnect    = (1 << 0)
};


// Private power management message indicating battery data has changed
// Indicates new data resides in the IORegistry
#define kIOPMMessageBatteryStatusHasChanged         iokit_family_msg(sub_iokit_pmu, 0x100)

// Apple private Legacy messages for re-routing AutoWake and AutoPower messages to the PMU
// through newer user space IOPMSchedulePowerEvent API
#define kIOPMUMessageLegacyAutoWake                 iokit_family_msg(sub_iokit_pmu, 0x200)
#define kIOPMUMessageLegacyAutoPower                iokit_family_msg(sub_iokit_pmu, 0x210)

// For use with IOPMPowerSource bFlags
#define IOPM_POWER_SOURCE_REV   2
enum {
  kIOPMACInstalled      = kIOBatteryChargerConnect,
  kIOPMBatteryCharging  = kIOBatteryCharge,
  kIOPMBatteryInstalled = kIOBatteryInstalled,
  kIOPMUPSInstalled     = (1<<3),
  kIOPMBatteryAtWarn    = (1<<4),
  kIOPMBatteryDepleted  = (1<<5),
  kIOPMACnoChargeCapability = (1<<6),     // AC adapter cannot charge battery
  kIOPMRawLowBattery    = (1<<7),         // used only by  Platform Expert
  kIOPMForceLowSpeed    = (1<<8),         // set by Platfm Expert, chk'd by Pwr Plugin
  kIOPMClosedClamshell  = (1<<9),         // set by PMU - reflects state of the clamshell
  kIOPMClamshellStateOnWake = (1<<10)     // used only by Platform Expert
};


// **********************************************
// Internal power management data structures
// **********************************************

#if KERNEL && __cplusplus
class IOService;

enum {
    kIOPowerEmergencyLevel = 1000
};

enum {
    kIOPMSubclassPolicy,
    kIOPMSuperclassPolicy1
};

struct stateChangeNote{
    IOPMPowerFlags    stateFlags;
    unsigned long    stateNum;
    void *         powerRef;
};
typedef struct stateChangeNote stateChangeNote;

struct IOPowerStateChangeNotification {
    void *        powerRef;
    unsigned long    returnValue;
    unsigned long    stateNumber;
    IOPMPowerFlags    stateFlags;
};
typedef struct IOPowerStateChangeNotification IOPowerStateChangeNotification;
typedef IOPowerStateChangeNotification sleepWakeNote;

extern void IOPMRegisterDevice(const char *, IOService *);
#endif /* KERNEL && __cplusplus */

#endif /* ! _IOKIT_IOPM_H */

