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

#ifndef _IOPMDeprecated_h_
#define _IOPMDeprecated_h_

#ifdef __ppc__

// Power events
enum {
  kClamshellClosedEventMask  = (1<<0),  // User closed lid
  kDockingBarEventMask       = (1<<1),  // OBSOLETE
  kACPlugEventMask           = (1<<2),  // User plugged or unplugged adapter
  kFrontPanelButtonEventMask = (1<<3),  // User hit the front panel button
  kBatteryStatusEventMask    = (1<<4)   // Battery status has changed
};

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


// These flags are deprecated. Use the version with the kIOPM prefix in IOPM.h
enum {
  kACInstalled      = (1<<0),
  kBatteryCharging  = (1<<1),
  kBatteryInstalled = (1<<2),
  kUPSInstalled     = (1<<3),
  kBatteryAtWarn    = (1<<4),
  kBatteryDepleted  = (1<<5),
  kACnoChargeCapability = (1<<6),     // AC adapter cannot charge battery
  kRawLowBattery    = (1<<7),         // used only by  Platform Expert
  kForceLowSpeed    = (1<<8)         // set by Platfm Expert, chk'd by Pwr Plugin};
};

#endif /* __ppc32 */
#endif /* _IOPMDeprecated_h_ */
