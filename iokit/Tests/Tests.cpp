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
 *
 */

#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IOLib.h>

#include <assert.h>


extern "C" {
extern int debug_container_malloc_size;
extern int debug_ivars_size;
}

static void DumpTree( void )
{
    IORegistryEntry *		next;
    IORegistryEntry *		packages = 0;
    IORegistryEntry *		deblocker = 0;
    IORegistryEntry *		keyboard = 0;
    IORegistryIterator * 	iter;
    OSOrderedSet *		all;

    IOLog("ivars %08x, containers %08x\n",
	debug_ivars_size, debug_container_malloc_size);

    iter = IORegistryIterator::iterateOver( gIODTPlane );
    assert( iter );

    all = iter->iterateAll();
    IOLog("\nCount %d\n", all->getCount() );
    all->release();

    iter->reset();
    while( (next = iter->nextEntryRecursive())) {
	if( 0 == strcmp( "packages", next->getName()))
	    packages = next;
	if( 0 == strcmp( "deblocker", next->getName()))
	    deblocker = next;
	if( 0 == strcmp( "keyboard", next->getName()))
	    keyboard = next;
    }

    if( deblocker && keyboard)
	deblocker->attachToParent( keyboard, gIODTPlane);

    iter->reset();
    while( (next = iter->nextEntryRecursive())) {
	IOLog("%s=%d,", next->getName(), next->getDepth( gIODTPlane ));
	if( 0 == strcmp( "gc", next->getName())) {
	    packages = next;
	}
    }

    IOLog("ivars %08x, containers %08x\n",
	debug_ivars_size, debug_container_malloc_size);

    if( packages)
	packages->detachAll( gIODTPlane);
    all = iter->iterateAll();
    IOLog("del gc/, count now %d\n", all->getCount() );
    all->release();

    iter->release();

    IOLog("ivars %08x, containers %08x\n",
	debug_ivars_size, debug_container_malloc_size);

}

extern "C" {
void PathTests( void )
{
    const char * tests[] = {
        "IODeviceTree:/bandit",
        "IODeviceTree:/",
	"IODeviceTree:/xxxx",
	"IODeviceTree:/bandit/xxx",
        "IODeviceTree:/bandit@F2000000",
        "IODeviceTree:/bandit/gc",
        "IODeviceTree:/bandit/gc/mace:17.202.42.95,\\mach_kernel",
        "IODeviceTree:/bandit/@10/mesh",
        "IODeviceTree:enet:17.202",
        "IODeviceTree:scsi/@0:0",
        "IODeviceTree:scsi-int",
        "IODeviceTree:/bandit/gc@10/mesh",
        "IODeviceTree:/bandit/gc/53c94/disk@0:6,mach_kernel",
        "IOService:/",
        "IOService:/ApplePlatformExpert",
        "IOService:/ApplePlatformExpert/hammerhead@F8000000",
        "IOService:/ApplePlatformExpert/bandit/AppleMacRiscPCI"
    };

    IORegistryEntry *	entry;
    char		str[256];
    int			len;

    for( unsigned int i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

	len = sizeof( str );
	entry = IORegistryEntry::fromPath( tests[i], 0, str, &len );
        IOLog("\"%s\" ", tests[i] );
	if( entry) {
	    IOLog("found %s, tail = \"%s\"\n", entry->getName(), str );
            len = sizeof( str );
	    if( entry->getPath( str, &len,
			IORegistryEntry::getPlane("IODeviceTree"))) {
		IOLog("path = \"%s\"\n", str);
	    }
	    entry->release();
	} else
	    IOLog("not found\n");
    }
}
}

void TestsCpp( void * dtTop )
{
    IORegistryEntry * dt;

    IOLog("\nivars %08x, containers %08x\n",
	debug_ivars_size, debug_container_malloc_size);

    OSMetaClass::printInstanceCounts();
    dt = IODeviceTreeAlloc( dtTop );
    assert( dt );

//    OSMetaClass::printInstanceCounts();
    DumpTree();
//    OSMetaClass::printInstanceCounts();
    dt->detachAll( gIODTPlane);
    OSMetaClass::printInstanceCounts();
    IOLog("ivars %08x, containers %08x\n",
	debug_ivars_size, debug_container_malloc_size);
}

