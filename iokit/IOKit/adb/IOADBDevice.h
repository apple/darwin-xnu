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
#include <IOKit/IOService.h>
#include <IOKit/adb/adb.h>
#include <IOKit/adb/IOADBBus.h>

class IOADBBus;


class IOADBDevice : public IOService
{
OSDeclareDefaultStructors(IOADBDevice)

private:

IOADBBus *	bus;
ADBDeviceControl * fBusRef;

public:

bool init ( OSDictionary * regEntry, ADBDeviceControl * us );
bool attach ( IOADBBus * controller );
virtual bool matchPropertyTable( OSDictionary * table );
bool seizeForClient ( IOService * client, ADB_callback_func handler );
void releaseFromClient ( IORegistryEntry * client );
IOReturn flush ( void );
IOReturn readRegister ( IOADBRegister adbRegister, UInt8 * data, IOByteCount * length );
IOReturn writeRegister ( IOADBRegister adbRegister, UInt8 * data, IOByteCount * length );
IOADBAddress address ( void );
IOADBAddress defaultAddress ( void );
UInt8 handlerID ( void );
UInt8 defaultHandlerID ( void );
IOReturn setHandlerID ( UInt8 handlerID );
void * busRef ( void );

};
