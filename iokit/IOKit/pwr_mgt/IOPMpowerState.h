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
#include <IOKit/pwr_mgt/IOPM.h>

struct IOPMPowerState
{
 unsigned long	version;		// version number of this struct
IOPMPowerFlags	capabilityFlags;	// bits that describe (to interested drivers) the capability of the device in this state 
IOPMPowerFlags	outputPowerCharacter;	// description (to power domain children) of the power provided in this state 
IOPMPowerFlags	inputPowerRequirement;	// description (to power domain parent) of input power required in this state
unsigned long	staticPower;	// average consumption in milliwatts
unsigned long	unbudgetedPower;	// additional consumption from separate power supply (mw)
unsigned long	powerToAttain;	// additional power to attain this state from next lower state (in mw)
unsigned long	timeToAttain;	// time required to enter this state from next lower state (in microseconds)
unsigned long	settleUpTime;	// settle time required after entering this state from next lower state (microseconds)
unsigned long	timeToLower;	// time required to enter next lower state from this one (in microseconds)
unsigned long	settleDownTime;	// settle time required after entering next lower state from this state (microseconds)
unsigned long	powerDomainBudget;	// power in mw a domain in this state can deliver to its children
};

typedef struct IOPMPowerState IOPMPowerState;

