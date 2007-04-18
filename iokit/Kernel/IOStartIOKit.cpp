/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1998,1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

#include <libkern/c++/OSUnserialize.h>
#include <libkern/version.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitDebug.h>

#include <IOKit/assert.h>

#include "IOKitKernelInternal.h"

extern "C" {

extern void OSlibkernInit (void);

#include <kern/clock.h>

void IOKitResetTime( void )
{
	mach_timespec_t		t;

	t.tv_sec = 30;
	t.tv_nsec = 0;
	IOService::waitForService(
		IOService::resourceMatching("IORTC"), &t );
#ifndef i386
	IOService::waitForService(
		IOService::resourceMatching("IONVRAM"), &t );
#endif

    clock_initialize_calendar();
}

// From <osfmk/kern/debug.c>
extern int debug_mode;

void StartIOKit( void * p1, void * p2, void * p3, void * p4 )
{
    IOPlatformExpertDevice *	rootNub;
    int				debugFlags;
    IORegistryEntry *		root;
    OSObject *			obj;
    extern const char *         gIOKernelKmods;
    OSString *                  errorString = NULL; // must release
    OSDictionary *              fakeKmods;  // must release
    OSCollectionIterator *      kmodIter;   // must release
    OSString *                  kmodName;   // don't release

    if( PE_parse_boot_arg( "io", &debugFlags ))
	gIOKitDebug = debugFlags;

    // Check for the log synchronous bit set in io
    if (gIOKitDebug & kIOLogSynchronous)
        debug_mode = true;

    //
    // Have to start IOKit environment before we attempt to start
    // the C++ runtime environment.  At some stage we have to clean up
    // the initialisation path so that OS C++ can initialise independantly
    // of iokit basic service initialisation, or better we have IOLib stuff
    // initialise as basic OS services.
    //
    IOLibInit(); 
    OSlibkernInit();

   /*****
    * Declare the fake kmod_info structs for built-in components
    * that must be tracked as independent units for dependencies.
    */
    fakeKmods = OSDynamicCast(OSDictionary,
        OSUnserialize(gIOKernelKmods, &errorString));

    if (!fakeKmods) {
        if (errorString) {
            panic("Kernel kmod list syntax error: %s\n",
                    errorString->getCStringNoCopy());
            errorString->release();
        } else {
            panic("Error loading kernel kmod list.\n");
        }
    }

    kmodIter = OSCollectionIterator::withCollection(fakeKmods);
    if (!kmodIter) {
        panic("Can't declare in-kernel kmods.\n");
    }
    while ((kmodName = OSDynamicCast(OSString, kmodIter->getNextObject()))) {

        OSString * kmodVersion = OSDynamicCast(OSString,
            fakeKmods->getObject(kmodName));
        if (!kmodVersion) {
            panic("Can't declare in-kernel kmod; \"%s\" has "
                "an invalid version.\n",
                kmodName->getCStringNoCopy());
        }

	// empty version strings get replaced with current kernel version
	const char *vers = (strlen(kmodVersion->getCStringNoCopy())
				 ? kmodVersion->getCStringNoCopy()
				 : osrelease);

        if (KERN_SUCCESS != kmod_create_fake(kmodName->getCStringNoCopy(), vers)) {
            panic("Failure declaring in-kernel kmod \"%s\".\n",
                kmodName->getCStringNoCopy());
        }
    }

    kmodIter->release();
    fakeKmods->release();



    root = IORegistryEntry::initialize();
    assert( root );
    IOService::initialize();
    IOCatalogue::initialize();
    IOUserClient::initialize();
    IOMemoryDescriptor::initialize();

    obj = OSString::withCString( version );
    assert( obj );
    if( obj ) {
        root->setProperty( kIOKitBuildVersionKey, obj );
	obj->release();
    }
    obj = IOKitDiagnostics::diagnostics();
    if( obj ) {
        root->setProperty( kIOKitDiagnosticsKey, obj );
	obj->release();
    }

    rootNub = new IOPlatformExpertDevice;

    if( rootNub && rootNub->initWithArgs( p1, p2, p3, p4)) {
        rootNub->attach( 0 );

       /* Enter into the catalogue the drivers
        * provided by BootX.
        */
        gIOCatalogue->recordStartupExtensions();

        rootNub->registerService();
    }
}

}; /* extern "C" */
