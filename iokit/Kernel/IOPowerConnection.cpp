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

#include <IOKit/pwr_mgt/IOPowerConnection.h>

#define super IOService
OSDefineMetaClassAndStructors(IOPowerConnection,IOService)


// **********************************************************************************
// setDesiredDomainState
//
// Parent of the connection calls here to save the childs desire
// **********************************************************************************
void IOPowerConnection::setDesiredDomainState (unsigned long stateNumber )
{
    desiredDomainState = stateNumber;
}


// **********************************************************************************
// getDesiredDomainState
//
// **********************************************************************************
unsigned long IOPowerConnection::getDesiredDomainState ( void )
{
    return desiredDomainState;
}


// **********************************************************************************
// setParentKnowsState
//
// Child of the connection calls here to set its reminder that the parent does
// or does not yet know the state if its domain.
// **********************************************************************************
void IOPowerConnection::setParentKnowsState (bool flag )
{
    stateKnown = flag;
}


// **********************************************************************************
// setParentCurrentPowerFlags
//
// Child of the connection calls here to save what the parent says
// is the state if its domain.
// **********************************************************************************
void IOPowerConnection::setParentCurrentPowerFlags (IOPMPowerFlags flags )
{
    currentPowerFlags = flags;
}


// **********************************************************************************
// parentKnowsState
//
// **********************************************************************************
bool IOPowerConnection::parentKnowsState (void )
{
    return stateKnown;
}


// **********************************************************************************
// parentCurrentPowerFlags
//
// **********************************************************************************
IOPMPowerFlags IOPowerConnection::parentCurrentPowerFlags (void )
{
    return currentPowerFlags;
}


