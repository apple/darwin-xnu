/*
 * Copyright (c) 1998-2010 Apple Inc. All rights reserved.
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

#include <libkern/c++/OSUnserialize.h>
#include <libkern/c++/OSKext.h>
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
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMinformeeList.h>
#include <IOKit/IOStatisticsPrivate.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOInterruptAccountingPrivate.h>
#include <IOKit/assert.h>
#include <sys/conf.h>

#include "IOKitKernelInternal.h"

const OSSymbol * gIOProgressBackbufferKey;
OSSet *          gIORemoveOnReadProperties;

extern "C" {

void StartIOKit( void * p1, void * p2, void * p3, void * p4 );
void IORegistrySetOSBuildVersion(char * build_version);
void IORecordProgressBackbuffer(void * buffer, size_t size, uint32_t theme);

extern void OSlibkernInit (void);

void iokit_post_constructor_init(void);

#include <kern/clock.h>
#include <sys/time.h>

void IOKitInitializeTime( void )
{
	mach_timespec_t		t;

	t.tv_sec = 30;
	t.tv_nsec = 0;
	IOService::waitForService(
		IOService::resourceMatching("IORTC"), &t );
#if defined(__i386__) || defined(__x86_64__)
	IOService::waitForService(
		IOService::resourceMatching("IONVRAM"), &t );
#endif

    clock_initialize_calendar();
}

void iokit_post_constructor_init(void)
{
    IORegistryEntry *		root;
    OSObject *			obj;

    IOCPUInitialize();
    root = IORegistryEntry::initialize();
    assert( root );
    IOService::initialize();
    IOCatalogue::initialize();
    IOStatistics::initialize();
    OSKext::initialize();
    IOUserClient::initialize();
    IOMemoryDescriptor::initialize();
    IORootParent::initialize();

    // Initializes IOPMinformeeList class-wide shared lock
    IOPMinformeeList::getSharedRecursiveLock();

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
}

// From <osfmk/kern/debug.c>
extern int debug_mode;

/*****
 * Pointer into bootstrap KLD segment for functions never used past startup.
 */
void (*record_startup_extensions_function)(void) = 0;

void StartIOKit( void * p1, void * p2, void * p3, void * p4 )
{
    IOPlatformExpertDevice *	rootNub;
    int				debugFlags;

    if( PE_parse_boot_argn( "io", &debugFlags, sizeof (debugFlags) ))
	gIOKitDebug = debugFlags;
#if DEVELOPMENT || DEBUG
    else gIOKitDebug |= kIOWaitQuietPanics;
#endif /* DEVELOPMENT || DEBUG */
	
    if( PE_parse_boot_argn( "iotrace", &debugFlags, sizeof (debugFlags) ))
	gIOKitTrace = debugFlags;
	
    // Compat for boot-args
    gIOKitTrace |= (gIOKitDebug & kIOTraceCompatBootArgs);
	
    // Check for the log synchronous bit set in io
    if (gIOKitDebug & kIOLogSynchronous)
        debug_mode = true;

    if( PE_parse_boot_argn( "pmtimeout", &debugFlags, sizeof (debugFlags) ))
        gCanSleepTimeout = debugFlags;
    //
    // Have to start IOKit environment before we attempt to start
    // the C++ runtime environment.  At some stage we have to clean up
    // the initialisation path so that OS C++ can initialise independantly
    // of iokit basic service initialisation, or better we have IOLib stuff
    // initialise as basic OS services.
    //
    IOLibInit(); 
    OSlibkernInit();
    devsw_init();

    gIOProgressBackbufferKey  = OSSymbol::withCStringNoCopy(kIOProgressBackbufferKey);
    gIORemoveOnReadProperties = OSSet::withObjects((const OSObject **) &gIOProgressBackbufferKey, 1);

    interruptAccountingInit();

    rootNub = new IOPlatformExpertDevice;

    if( rootNub && rootNub->initWithArgs( p1, p2, p3, p4)) {
        rootNub->attach( 0 );

       /* If the bootstrap segment set up a function to record startup
        * extensions, call it now.
        */
        if (record_startup_extensions_function) {
            record_startup_extensions_function();
        }

        rootNub->registerService();

#if !NO_KEXTD
       /* Add a busy count to keep the registry busy until kextd has
        * completely finished launching. This is decremented when kextd
        * messages the kernel after the in-kernel linker has been
        * removed and personalities have been sent.
        */
        IOService::getServiceRoot()->adjustBusy(1);
#endif
    }
}

void
IORegistrySetOSBuildVersion(char * build_version)
{
    IORegistryEntry * root = IORegistryEntry::getRegistryRoot();

    if (root) {
        if (build_version) {
            root->setProperty(kOSBuildVersionKey, build_version);
        } else {
            root->removeProperty(kOSBuildVersionKey);
        }
    }

    return;
}

void
IORecordProgressBackbuffer(void * buffer, size_t size, uint32_t theme)
{
    IORegistryEntry * chosen;
    if ((chosen = IORegistryEntry::fromPath(kIODeviceTreePlane ":/chosen")))
    {
        chosen->setProperty(kIOProgressBackbufferKey, buffer, size);
	chosen->setProperty(kIOProgressColorThemeKey, theme, 32);

        chosen->release();
    }
}

}; /* extern "C" */
