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

#ifndef __IOKIT_IOMESSAGE_H
#define __IOKIT_IOMESSAGE_H

#include <IOKit/IOReturn.h>
#include <IOKit/IOTypes.h>

typedef UInt32 IOMessage;

#define iokit_common_msg(message)     (UInt32)(sys_iokit|sub_iokit_common|message)
#define iokit_family_msg(sub,message) (UInt32)(sys_iokit|sub|message)

#define kIOMessageServiceIsTerminated      iokit_common_msg(0x010)
#define kIOMessageServiceIsSuspended       iokit_common_msg(0x020)
#define kIOMessageServiceIsResumed         iokit_common_msg(0x030)

#define kIOMessageServiceIsRequestingClose iokit_common_msg(0x100)
#define kIOMessageServiceIsAttemptingOpen  iokit_common_msg(0x101)
#define kIOMessageServiceWasClosed         iokit_common_msg(0x110)

#define kIOMessageServiceBusyStateChange   iokit_common_msg(0x120)

#define kIOMessageCanDevicePowerOff        iokit_common_msg(0x200)
#define kIOMessageDeviceWillPowerOff       iokit_common_msg(0x210)
#define kIOMessageDeviceWillNotPowerOff    iokit_common_msg(0x220)
#define kIOMessageDeviceHasPoweredOn       iokit_common_msg(0x230)
#define kIOMessageCanSystemPowerOff        iokit_common_msg(0x240)
#define kIOMessageSystemWillPowerOff       iokit_common_msg(0x250)
#define kIOMessageSystemWillNotPowerOff    iokit_common_msg(0x260)
#define kIOMessageCanSystemSleep           iokit_common_msg(0x270)
#define kIOMessageSystemWillSleep          iokit_common_msg(0x280)
#define kIOMessageSystemWillNotSleep       iokit_common_msg(0x290)
#define kIOMessageSystemHasPoweredOn       iokit_common_msg(0x300)
#define kIOMessageSystemWillRestart        iokit_common_msg(0x310)

#endif /* ! __IOKIT_IOMESSAGE_H */
