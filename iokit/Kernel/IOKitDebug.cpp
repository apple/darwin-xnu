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
 *
 */

#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/assert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSCPPDebug.h>

extern "C" {

SInt64		gIOKitDebug
#ifdef IOKITDEBUG
                            = IOKITDEBUG
#endif
;

int 		debug_malloc_size;
int		debug_iomalloc_size;
int 		debug_container_malloc_size;
// int 		debug_ivars_size; // in OSObject.cpp

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
        IOLog("Count %d\n", all->getCount() );
        all->release();
    } else
	IOLog("Empty\n");

    iter->reset();
    while( (next = iter->getNextObjectRecursive())) {
	sprintf( format + 1, "%ds", next->getDepth( plane ));
	IOLog( format, "");
        if( (service = OSDynamicCast(IOService, next)))
            IOLog("<%ld>", service->getBusyState());
	IOLog( "%s\n", next->getName());
    }
    iter->release();
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

    dict->setObject( "Classes", OSMetaClass::getClassDictionary() );

    ok = dict->serialize( s );

    dict->release();

    return( ok );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
