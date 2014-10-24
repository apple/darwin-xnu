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

#include <sys/sysctl.h>

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSCPPDebug.h>

#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/assert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>

#ifdef IOKITDEBUG
#define DEBUG_INIT_VALUE IOKITDEBUG
#else
#define DEBUG_INIT_VALUE 0
#endif

SInt64		gIOKitDebug = DEBUG_INIT_VALUE;
SInt64		gIOKitTrace = 0;

#if DEVELOPMENT || DEBUG
#define IODEBUG_CTLFLAGS	CTLFLAG_RW
#else
#define IODEBUG_CTLFLAGS	CTLFLAG_RD
#endif

SYSCTL_QUAD(_debug, OID_AUTO, iokit, IODEBUG_CTLFLAGS | CTLFLAG_LOCKED, &gIOKitDebug, "boot_arg io");
SYSCTL_QUAD(_debug, OID_AUTO, iotrace, CTLFLAG_RW | CTLFLAG_LOCKED, &gIOKitTrace, "trace io");


int 		debug_malloc_size;
int		debug_iomalloc_size;

vm_size_t	debug_iomallocpageable_size;
int 		debug_container_malloc_size;
// int 		debug_ivars_size; // in OSObject.cpp

extern "C" {

#if 0
#define DEBG(fmt, args...)   { kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)   { IOLog(fmt, ## args); }
#endif

void IOPrintPlane( const IORegistryPlane * plane )
{
    IORegistryEntry *		next;
    IORegistryIterator * 	iter;
    OSOrderedSet *		all;
    char			format[] = "%xxxs";
    IOService *			service;

    iter = IORegistryIterator::iterateOver( plane );
    assert( iter );
    all = iter->iterateAll();
    if( all) {
        DEBG("Count %d\n", all->getCount() );
        all->release();
    } else
	DEBG("Empty\n");

    iter->reset();
    while( (next = iter->getNextObjectRecursive())) {
	snprintf(format + 1, sizeof(format) - 1, "%ds", 2 * next->getDepth( plane ));
	DEBG( format, "");
	DEBG( "\033[33m%s", next->getName( plane ));
	if( (next->getLocation( plane )))
            DEBG("@%s", next->getLocation( plane ));
	DEBG("\033[0m <class %s", next->getMetaClass()->getClassName());
        if( (service = OSDynamicCast(IOService, next)))
            DEBG(", busy %ld", (long) service->getBusyState());
	DEBG( ">\n");
//	IOSleep(250);
    }
    iter->release();
}

void db_piokjunk(void)
{
}

void db_dumpiojunk( const IORegistryPlane * plane __unused )
{
}

void IOPrintMemory( void )
{

//    OSMetaClass::printInstanceCounts();

    IOLog("\n"
	    "ivar kalloc()       0x%08x\n"
	    "malloc()            0x%08x\n"
            "containers kalloc() 0x%08x\n"
	    "IOMalloc()          0x%08x\n"
            "----------------------------------------\n",
	    debug_ivars_size,
            debug_malloc_size,
            debug_container_malloc_size,
            debug_iomalloc_size
            );
}

} /* extern "C" */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super OSObject
OSDefineMetaClassAndStructors(IOKitDiagnostics, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSObject * IOKitDiagnostics::diagnostics( void )
{
    IOKitDiagnostics * diags;

    diags = new IOKitDiagnostics;
    if( diags && !diags->init()) {
	diags->release();
	diags = 0;
    }

    return( diags );
}

void IOKitDiagnostics::updateOffset( OSDictionary * dict,
			UInt32 value, const char * name )
{
    OSNumber * off;

    off = OSNumber::withNumber( value, 32 );
    if( !off)
	return;

    dict->setObject( name, off );
    off->release();
}

bool IOKitDiagnostics::serialize(OSSerialize *s) const
{
    OSDictionary * 	dict;
    bool		ok;

    dict = OSDictionary::withCapacity( 5 );
    if( !dict)
	return( false );

    updateOffset( dict, debug_ivars_size, "Instance allocation" );
    updateOffset( dict, debug_container_malloc_size, "Container allocation" );
    updateOffset( dict, debug_iomalloc_size, "IOMalloc allocation" );
    updateOffset( dict, debug_iomallocpageable_size, "Pageable allocation" );

    OSMetaClass::serializeClassDictionary(dict);

    ok = dict->serialize( s );

    dict->release();

    return( ok );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
