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
/*
 * 18 June 1998 sdouglas  Start IOKit version.
 * 17 Nov  1998 suurballe Port objc to c++
 */

#include <IOKit/adb/IOADBDevice.h>

#define super IOService
OSDefineMetaClassAndStructors(IOADBDevice,IOService)

// **********************************************************************************
// init
//
// **********************************************************************************
bool IOADBDevice::init ( OSDictionary * regEntry, ADBDeviceControl * us )
{
if( !super::init(regEntry))
    return false;

fBusRef = us;
return true;
}


// **********************************************************************************
// attach
//
// **********************************************************************************
bool IOADBDevice::attach ( IOADBBus * controller )
{
if( !super::attach(controller))
    return false;

bus = controller;
return true;
}

// **********************************************************************************
// matchPropertyTable
//
// **********************************************************************************

bool IOADBDevice::matchPropertyTable( OSDictionary * table )
{
  return( bus->matchNubWithPropertyTable( this, table ));
}

// **********************************************************************************
// seizeForClient
//
// **********************************************************************************
bool IOADBDevice::seizeForClient ( IOService * client, ADB_callback_func handler )
{
bus->setOwner(fBusRef,client,handler);

return true;
}


// **********************************************************************************
// releaseFromClient
//
// **********************************************************************************
void IOADBDevice::releaseFromClient ( IORegistryEntry * )
{
    kprintf("IOADBDevice::releaseFromClient\n");
    bus->clearOwner(fBusRef);
}


// **********************************************************************************
// flush
//
// **********************************************************************************
IOReturn IOADBDevice::flush ( void )
{
return( bus->flush(fBusRef) );
}


// **********************************************************************************
// readRegister
//
// **********************************************************************************
IOReturn IOADBDevice::readRegister ( IOADBRegister adbRegister, UInt8 * data,
		IOByteCount * length )
{
return( bus->readRegister(fBusRef,adbRegister,data,length) );
}


// **********************************************************************************
// writeRegister
//
// **********************************************************************************
IOReturn IOADBDevice::writeRegister ( IOADBRegister adbRegister, UInt8 * data,
		IOByteCount * length )
{
return( bus->writeRegister(fBusRef,adbRegister,data,length) );
}


// **********************************************************************************
// address
//
// **********************************************************************************
IOADBAddress IOADBDevice::address ( void )
{
return( bus->address(fBusRef) );
}


// **********************************************************************************
// defaultAddress
//
// **********************************************************************************
IOADBAddress IOADBDevice::defaultAddress ( void )
{
return( bus->defaultAddress(fBusRef) );
}


// **********************************************************************************
// handlerID
//
// **********************************************************************************
UInt8 IOADBDevice::handlerID ( void )
{
return( bus->handlerID(fBusRef) );
}


// **********************************************************************************
// defaultHandlerID
//
// **********************************************************************************
UInt8 IOADBDevice::defaultHandlerID ( void )
{
return( bus->defaultHandlerID(fBusRef) );
}


// **********************************************************************************
// setHandlerID
//
// **********************************************************************************
IOReturn IOADBDevice::setHandlerID ( UInt8 handlerID )
{
return( bus->setHandlerID(fBusRef,handlerID) );
}


// **********************************************************************************
// busRef
//
// **********************************************************************************
void * IOADBDevice::busRef ( void )
{
return fBusRef;
}
