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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 */
 
#include <IOKit/system.h>

#include <architecture/i386/kernBootStruct.h>

#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSUnserialize.h>

#include <IOKit/platform/ApplePlatformExpert.h>
#include "AppleI386PlatformExpert.h"

#include <IOKit/assert.h>

__BEGIN_DECLS
extern void kdreboot(void);
__END_DECLS
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOPlatformExpert

OSSymbol * gIntelPICName;

OSDefineMetaClassAndStructors(AppleI386PlatformExpert, IOPlatformExpert)

IOService * AppleI386PlatformExpert::probe(IOService * 	/* provider */,
                                           SInt32 *		score )
{
    *score = 2000;

    return (this);
}

bool  AppleI386PlatformExpert::start(IOService * provider)
{
    gIntelPICName = (OSSymbol *) OSSymbol::withCStringNoCopy("intel-pic");

    setBootROMType(kBootROMTypeNewWorld); /* hammer to new world for i386 */

//  setupPIC(provider);

    if (!super::start(provider))
        return false;

    // Install halt/restart handler.

    PE_halt_restart = handlePEHaltRestart;

    return true;
}

IOService * AppleI386PlatformExpert::createNub(OSDictionary * from)
{
    IOService *      nub;
    OSData *		 prop;
    KERNBOOTSTRUCT * bootStruct;

    nub = super::createNub(from);

    if (nub)
    {
        if (0 == strcmp( "pci", nub->getName()))
        {
        	bootStruct = (KERNBOOTSTRUCT *) PE_state.bootArgs;
        	prop = OSData::withBytesNoCopy(&bootStruct->pciInfo,
               	                           sizeof(bootStruct->pciInfo));
        	assert(prop);
        	if (prop)
                from->setObject( "pci-bus-info", prop);
        }
        else if (0 != strcmp("intel-pic", nub->getName()))
        {
            setupPIC(nub);
        }
    }

    return (nub);
}

#define kNumVectors	16

void
AppleI386PlatformExpert::setupPIC(IOService *nub)
{
    int            i;
    OSDictionary * propTable;
    OSArray *      controller;
    OSArray *      specifier;
    OSData *       tmpData;
    long           tmpLong;

    propTable = nub->getPropertyTable();

    //
    // For the moment.. assume a classic 8259 interrupt controller
    // with 16 interrupts.
    //
    // Later, this will be changed to detect a APIC and/or MP-Table
    // and then will set the nubs appropriately.

    // Create the interrupt specifer array.
    specifier = OSArray::withCapacity(kNumVectors);
    assert(specifier);
    for (i = 0; i < kNumVectors; i++) {
        tmpLong = i;
        tmpData = OSData::withBytes(&tmpLong, sizeof(tmpLong));
        specifier->setObject(tmpData);
    }

    // Create the interrupt controller array.
    controller = OSArray::withCapacity(kNumVectors);
    assert(controller);
    for (i = 0; i < kNumVectors; i++)
        controller->setObject(gIntelPICName);

    // Put the two arrays into the property table.
    propTable->setObject(gIOInterruptControllersKey, controller);
    propTable->setObject(gIOInterruptSpecifiersKey, specifier);

    // Release the arrays after being added to the property table.
    specifier->release();
    controller->release();
}

bool
AppleI386PlatformExpert::matchNubWithPropertyTable(IOService *    nub,
					                               OSDictionary * propTable )
{
    OSString * nameProp;
    OSString * match;

    if (0 == (nameProp = (OSString *) nub->getProperty(gIONameKey)))
        return (false);

    if ( 0 == (match = (OSString *) propTable->getObject(gIONameMatchKey)))
        return (false);

    return (match->isEqualTo( nameProp ));
}

bool AppleI386PlatformExpert::getMachineName( char * name, int maxLength )
{
    strncpy( name, "x86", maxLength );

    return (true);
}

bool AppleI386PlatformExpert::getModelName( char * name, int maxLength )
{
    strncpy( name, "x86", maxLength );

    return (true);
}

int AppleI386PlatformExpert::handlePEHaltRestart( unsigned int type )
{
    int ret = 1;
	
    switch ( type )
    {
        case kPERestartCPU:
            // Use the pexpert service to reset the system through
            // the keyboard controller.
            kdreboot();
            break;

        case kPEHaltCPU:
        default:
            ret = -1;
            break;
    }

    return ret;
}
