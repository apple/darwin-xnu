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
#ifndef _IOKIT_IOPM_H
#define _IOKIT_IOPM_H

#define IOPMMaxPowerStates 10

typedef unsigned long IOPMPowerFlags;

#define IOPMNotAttainable	0x0001
#define IOPMPowerOn		0x0002
#define IOPMClockNormal	0x0004
#define IOPMClockRunning	0x0008
#define IOPMWakeupEnabled	0x0010
#define IOPMAuxPowerOn		0x0020
                        // following "capabilites" exist for the convenience
                        // of the "interested drivers"
#define IOPMDeviceUsable	0x8000
#define IOPMMaxPerformance	0x4000
#define IOPMContextRetained	0x2000
#define IOPMConfigRetained	0x1000
#define IOPMNotPowerManaged	0x0800
#define IOPMSoftSleep		0x0400

#define IOPMNextHigherState	1
#define IOPMHighestState	2
#define IOPMNextLowerState	3
#define IOPMLowestState		4


enum {		// commands on power managment command queue
    kPMbroadcastAggressiveness = 1,
    kPMunIdleDevice,
    kPMsleepDemand,
    kPMwakeSignal,
    kPMallowSleep,
    kPMcancelSleep
};

// Power events
enum {
  kClamshellClosedEventMask  = (1<<0),  // User closed lid
  kDockingBarEventMask       = (1<<1),  // OBSOLETE
  kACPlugEventMask           = (1<<2),  // User plugged or unplugged adapter
  kFrontPanelButtonEventMask = (1<<3),  // User hit the front panel button
  kBatteryStatusEventMask    = (1<<4)   // Battery status has changed
};

// Power commands issued to root domain
enum {
  kIOPMSleepNow                  = (1<<0),  // put machine to sleep now
  kIOPMAllowSleep                = (1<<1),  // allow idle sleep
  kIOPMPreventSleep              = (1<<2),  // do not allow idle sleep
  kIOPMPowerButton		 = (1<<3),  // power button was pressed
  kIOPMClamshellClosed		 = (1<<4),  // clamshell was closed
  kIOPMPowerEmergency		 = (1<<5),  // battery dangerously low
  kIOPMIgnoreClamshell		 = (1<<6)   // take no action on clamshell closure
};
                                        // Return codes

// PUBLIC power management features
// NOTE: this is a direct port from classic, some of these bits
//       are obsolete but are included for completeness
enum {
  kPMHasWakeupTimerMask        = (1<<0),  // 1=wake timer is supported
  kPMHasSharedModemPortMask    = (1<<1),  // Not used
  kPMHasProcessorCyclingMask   = (1<<2),  // 1=processor cycling supported
  kPMMustProcessorCycleMask    = (1<<3),  // Not used
  kPMHasReducedSpeedMask       = (1<<4),  // 1=supports reduced processor speed
  kPMDynamicSpeedChangeMask    = (1<<5),  // 1=supports changing processor speed on the fly
  kPMHasSCSIDiskModeMask       = (1<<6),  // 1=supports using machine as SCSI drive
  kPMCanGetBatteryTimeMask     = (1<<7),  // 1=battery time can be calculated
  kPMCanWakeupOnRingMask       = (1<<8),  // 1=machine can wake on modem ring
  kPMHasDimmingSupportMask     = (1<<9),  // 1=has monitor dimming support
  kPMHasStartupTimerMask       = (1<<10), // 1=can program startup timer
  kPMHasChargeNotificationMask = (1<<11), // 1=client can determine charger status/get notifications
  kPMHasDimSuspendSupportMask  = (1<<12), // 1=can dim diplay to DPMS ('off') state
  kPMHasWakeOnNetActivityMask  = (1<<13), // 1=supports waking upon receipt of net packet
  kPMHasWakeOnLidMask          = (1<<14), // 1=can wake upon lid/case opening
  kPMCanPowerOffPCIBusMask     = (1<<15), // 1=can remove power from PCI bus on sleep
  kPMHasDeepSleepMask          = (1<<16), // 1=supports deep (hibernation) sleep
  kPMHasSleepMask              = (1<<17), // 1=machine support low power sleep (ala powerbooks)
  kPMSupportsServerModeAPIMask = (1<<18), // 1=supports reboot on AC resume for unexpected power loss
  kPMHasUPSIntegrationMask     = (1<<19)  // 1=supports incorporating UPS devices into power source calcs
};

// PRIVATE power management features
// NOTE: this is a direct port from classic, some of these bits
//       are obsolete but are included for completeness.
enum {
  kPMHasExtdBattInfoMask       = (1<<0),  // Not used
  kPMHasBatteryIDMask          = (1<<1),  // Not used
  kPMCanSwitchPowerMask        = (1<<2),  // Not used 
  kPMHasCelsiusCyclingMask     = (1<<3),  // Not used
  kPMHasBatteryPredictionMask  = (1<<4),  // Not used
  kPMHasPowerLevelsMask        = (1<<5),  // Not used
  kPMHasSleepCPUSpeedMask      = (1<<6),  // Not used
  kPMHasBtnIntHandlersMask     = (1<<7),  // 1=supports individual button interrupt handlers
  kPMHasSCSITermPowerMask      = (1<<8),  // 1=supports SCSI termination power switch
  kPMHasADBButtonHandlersMask  = (1<<9),  // 1=supports button handlers via ADB
  kPMHasICTControlMask         = (1<<10), // 1=supports ICT control
  kPMHasLegacyDesktopSleepMask = (1<<11), // 1=supports 'doze' style sleep
  kPMHasDeepIdleMask           = (1<<12), // 1=supports Idle2 in hardware
  kPMOpenLidPreventsSleepMask  = (1<<13), // 1=open case prevent machine from sleeping
  kPMClosedLidCausesSleepMask  = (1<<14), // 1=case closed (clamshell closed) causes sleep
  kPMHasFanControlMask         = (1<<15), // 1=machine has software-programmable fan/thermostat controls
  kPMHasThermalControlMask     = (1<<16), // 1=machine supports thermal monitoring
  kPMHasVStepSpeedChangeMask   = (1<<17), // 1=machine supports processor voltage/clock change
  kPMEnvironEventsPolledMask   = (1<<18)  // 1=machine doesn't generate pmu env ints, we must poll instead 
};

// DEFAULT public and private features for machines whose device tree
// does NOT contain this information (pre-Core99).

// For Cuda-based Desktops

#define kStdDesktopPMFeatures   kPMHasWakeupTimerMask         |\
                                kPMHasProcessorCyclingMask    |\
                                kPMHasDimmingSupportMask      |\
                                kPMHasStartupTimerMask        |\
                                kPMSupportsServerModeAPIMask  |\
                                kPMHasUPSIntegrationMask

#define kStdDesktopPrivPMFeatures  kPMHasExtdBattInfoMask     |\
                                   kPMHasICTControlMask       |\
                                   kPMHasLegacyDesktopSleepMask

#define kStdDesktopNumBatteries 0

// For Wallstreet (PowerBook G3 Series 1998)

#define kWallstreetPMFeatures   kPMHasWakeupTimerMask         |\
                                kPMHasProcessorCyclingMask    |\
                                kPMHasReducedSpeedMask        |\
                                kPMDynamicSpeedChangeMask     |\
                                kPMHasSCSIDiskModeMask        |\
                                kPMCanGetBatteryTimeMask      |\
                                kPMHasDimmingSupportMask      |\
                                kPMHasChargeNotificationMask  |\
                                kPMHasDimSuspendSupportMask   |\
                                kPMHasSleepMask

#define kWallstreetPrivPMFeatures  kPMHasExtdBattInfoMask      |\
                                   kPMHasBatteryIDMask         |\
                                   kPMCanSwitchPowerMask       |\
                                   kPMHasADBButtonHandlersMask |\
                                   kPMHasSCSITermPowerMask     |\
                                   kPMHasICTControlMask        |\
                                   kPMClosedLidCausesSleepMask |\
                                   kPMEnvironEventsPolledMask

#define kStdPowerBookPMFeatures      kWallstreetPMFeatures
#define kStdPowerBookPrivPMFeatures  kWallstreetPrivPMFeatures

#define kStdPowerBookNumBatteries 2

// For 101 (PowerBook G3 Series 1999)

#define k101PMFeatures          kPMHasWakeupTimerMask         |\
                                kPMHasProcessorCyclingMask    |\
                                kPMHasReducedSpeedMask        |\
                                kPMDynamicSpeedChangeMask     |\
                                kPMHasSCSIDiskModeMask        |\
                                kPMCanGetBatteryTimeMask      |\
                                kPMHasDimmingSupportMask      |\
                                kPMHasChargeNotificationMask  |\
                                kPMHasDimSuspendSupportMask   |\
                                kPMHasSleepMask               |\
                                kPMHasUPSIntegrationMask

#define k101PrivPMFeatures      kPMHasExtdBattInfoMask        |\
                                kPMHasBatteryIDMask           |\
                                kPMCanSwitchPowerMask         |\
                                kPMHasADBButtonHandlersMask   |\
                                kPMHasSCSITermPowerMask       |\
                                kPMHasICTControlMask          |\
                                kPMClosedLidCausesSleepMask   |\
                                kPMEnvironEventsPolledMask

#define IOPMNoErr		0	// normal return

                        // returned by powerStateWillChange and powerStateDidChange:
#define IOPMAckImplied		0	// acknowledgement of power state change is implied
#define IOPMWillAckLater	1	// acknowledgement of power state change will come later

                        // returned by requestDomainState
#define IOPMBadSpecification	4	// unrecognized specification parameter
#define IOPMNoSuchState		5	// no power state matches search specification

#define IOPMCannotRaisePower	6	// a device cannot change its power for some reason

                        // returned by changeStateTo
#define IOPMParameterError	7	// requested state doesn't exist
#define IOPMNotYetInitialized	8	// device not yet fully hooked into power management "graph"


						// used by Root Domain UserClient

enum {
    kPMGeneralAggressiveness = 0,
    kPMMinutesToDim,
    kPMMinutesToSpinDown,
    kPMMinutesToSleep
};
#define kMaxType kPMMinutesToSleep


#define kIOBatteryInfoKey		"IOBatteryInfo"
#define kIOBatteryCurrentChargeKey	"Current"
#define kIOBatteryCapacityKey		"Capacity"
#define kIOBatteryFlagsKey		"Flags"
#define kIOBatteryVoltageKey		"Voltage"
#define kIOBatteryAmperageKey		"Amperage"
enum {
    kIOBatteryInstalled		= (1 << 2),
    kIOBatteryCharge		= (1 << 1),
    kIOBatteryChargerConnect	= (1 << 0)
};


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
    IOPMPowerFlags	stateFlags;
    unsigned long	stateNum;
    void * 		powerRef;
};
typedef struct stateChangeNote stateChangeNote;

struct sleepWakeNote{
    void *		powerRef;
    unsigned long	returnValue;
};
typedef struct sleepWakeNote sleepWakeNote;

extern void IOPMRegisterDevice(const char *, IOService *);
#endif /* KERNEL && __cplusplus */

#endif /* ! _IOKIT_IOPM_H */

