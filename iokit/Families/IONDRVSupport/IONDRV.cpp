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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  21 Jul 98 - start IOKit
 * sdouglas  14 Dec 98 - start cpp.
 */



#include <IOKit/IOLib.h>
#include <libkern/c++/OSContainers.h>

extern "C" {
#include <pexpert/pexpert.h>
};

#include "IONDRV.h"
#include "IOPEFLoader.h"

#define LOG		if(1) kprintf

#define USE_TREE_NDRVS	1
#define USE_ROM_NDRVS	1


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super OSObject

OSDefineMetaClassAndStructors(IONDRV, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IONDRV * IONDRV::instantiate( IORegistryEntry * regEntry,
                              IOLogicalAddress container,
                              IOByteCount containerSize,
                              IONDRVUndefinedSymbolHandler undefHandler,
                              void * self )
{
    OSStatus	err = 1;
    IONDRV *	inst;

    inst = new IONDRV;

    if( inst) do {
	if( false == inst->init())
	    continue;

        err = PCodeOpen( (void *)container, containerSize, &inst->pcInst );
        if( err)
	    continue;

        err = PCodeInstantiate( inst->pcInst, undefHandler, self );
        if( err)
	    continue;

	inst->getSymbol( "DoDriverIO",
				(IOLogicalAddress *) &inst->fDoDriverIO );
	if( kIOReturnSuccess == inst->getSymbol( "TheDriverDescription", 
				(IOLogicalAddress *) &inst->theDriverDesc )) {

            char * 	name;
            int		plen;

            name = (char *) inst->theDriverDesc->driverOSRuntimeInfo.driverName;
            plen = name[ 0 ];
            strncpy( name, name + 1, plen);
	    name[ plen ] = 0;

	    kprintf("ndrv version %08x\n",
			inst->theDriverDesc-> driverType.version);
	}

    } while( false);

    if( inst && err) {
	inst->release();
	inst = 0;
    }

    return( inst );
}

void IONDRV::free( void )
{
    if( pcInst)
        PCodeClose( pcInst );
    super::free();
}

IOReturn IONDRV::getSymbol( const char * symbolName,
				IOLogicalAddress * address )
{
    OSStatus            err;

    err = PCodeFindExport( pcInst, symbolName,
				(LogicalAddress *)address, NULL );
    if( err)
	*address = 0;

    return( err);
}

#if 0
            if(	(err = NDRVGetShimClass( ioDevice, instance, 0, classNames ))
            ) continue;
            err = [propTable createProperty:"AAPL,dk_Driver Name" flags:0
                        value:classNames length:strlen( classNames) ];
            err = [propTable createProperty:"AAPL,dk_Server Name" flags:0
                        value:classNames length:strlen( classNames) ];

OSStatus    NDRVGetShimClass( id ioDevice, NDRVInstance instance, UInt32 serviceIndex, char * className )
{
    NDRVInstanceVars  * 	ndrvInst = (NDRVInstanceVars *) instance;
    OSStatus            	err;
    static const char *		driverDescProperty = "TheDriverDescription";
    static const char *		frameBufferShim = "IONDRVFramebuffer";
    DriverDescription * 	desc;
    UInt32			serviceType;

    className[ 0 ] = 0;
    do {
	err = PCodeFindExport( ndrvInst->pcInst, driverDescProperty, (IOLogicalAddress *)&desc, NULL );
        if( err) continue;

	if( desc->driverDescSignature != kTheDescriptionSignature) {
	    err = -1;
	    continue;
	}
	if( serviceIndex >= desc->driverServices.nServices) {
	    err = -1;
	    continue;
	}

	serviceType = desc->driverServices.service[ serviceIndex ].serviceType;
	switch( desc->driverServices.service[ serviceIndex ].serviceCategory) {

	    case kServiceCategoryNdrvDriver:
		if( serviceType == kNdrvTypeIsVideo) {
                    strcpy( className, frameBufferShim);
		    break;
		}
	    default:
		err = -1;
	}
    } while( false);

    return( err);
}
#endif



IOReturn IONDRV::doDriverIO( UInt32 commandID, void * contents,
				UInt32 commandCode, UInt32 commandKind )
{
    OSStatus            	err;

    if( 0 == fDoDriverIO)
	return( kIOReturnUnsupported );

    err = CallTVector( /*AddressSpaceID*/ 0, (void *)commandID, contents,
		(void *)commandCode, (void *)commandKind, /*p6*/ 0,
		fDoDriverIO );

#if 0
    if( err) {
	UInt32 i;
	static const char * commands[] = 
		{ "kOpenCommand", "kCloseCommand",
		"kReadCommand", "kWriteCommand",
		"kControlCommand", "kStatusCommand", "kKillIOCommand",
		"kInitializeCommand", "kFinalizeCommand",
		"kReplaceCommand", "kSupersededCommand" };

	LOG("Driver failed (%d) on %s : ", err, commands[ commandCode ] );

	switch( commandCode) {
	    case kControlCommand:
	    case kStatusCommand:
		LOG("%d : ", ((UInt16 *)contents)[ 0x1a / 2 ]);
		contents = ((void **)contents)[ 0x1c / 4 ];
		for( i = 0; i<5; i++ )
		    LOG("%08x, ", ((UInt32 *)contents)[i] );
		break;
	}
	LOG("\n");
    }
#endif

    return( err);
}


IONDRV * IONDRV::fromRegistryEntry( IORegistryEntry * regEntry,
                                    IONDRVUndefinedSymbolHandler handler,
                                    void * self )
{
    IOLogicalAddress	pef = 0;
    IOByteCount		propSize = 0;
    OSData *		prop;
    IONDRV *		inst;

    inst = (IONDRV *) regEntry->getProperty("AAPL,ndrvInst");
    if( inst) {
	inst->retain();
	return( inst );
    }

    prop = (OSData *) regEntry->getProperty( "driver,AAPL,MacOS,PowerPC" );
    if( USE_TREE_NDRVS && prop) {
        pef = (IOLogicalAddress) prop->getBytesNoCopy();
	propSize = prop->getLength();
    }

    // God awful hack:
    // Some onboard devices don't have the ndrv in the tree. The booter
    // can load & match PEF's but only from disk, not network boots.

#if USE_ROM_NDRVS
    if( !pef && (0 == strcmp( regEntry->getName(), "ATY,mach64_3DU")) ) {

        int * patch;

        patch = (int *) 0xffe88140;
        propSize = 0x10a80;

	// Check ati PEF exists there
        if( patch[ 0x1f0 / 4 ] == 'ATIU') {

            pef = (IOLogicalAddress) IOMalloc( propSize );
            bcopy( (void *) patch, (void *) pef, propSize );
        }
    }

    if( !pef && (0 == strcmp( regEntry->getName(), "ATY,mach64_3DUPro")) ) {

        int * patch;

        patch = (int *) 0xffe99510;
        propSize = 0x12008;
	// Check ati PEF exists there
        if( patch[ 0x1fc / 4 ] != 'ATIU') {

            // silk version
            patch = (int *) 0xffe99550;
            propSize = 0x12058;
            if( patch[ 0x1fc / 4 ] != 'ATIU')
		propSize = 0;
	}

	if( propSize) {
            pef = (IOLogicalAddress) IOMalloc( propSize );
            bcopy( (void *) patch, (void *) pef, propSize );
        }
    }

    if( !pef && (0 == strcmp( regEntry->getName(), "control")) ) {

#define ins(i,d,a,simm) ((i<<26)+(d<<21)+(a<<16)+simm)
        int * patch;

        patch = (int *) 0xffe6bd50;
        propSize = 0xac10;

	// Check control PEF exists there
        if( patch[ 0x41ac / 4 ] == ins( 32, 3, 0, 0x544)) { // lwz r3,0x544(0)

            pef = (IOLogicalAddress) IOMalloc( propSize );
            bcopy( (void *) patch, (void *) pef, propSize );
            patch = (int *) pef;
	    // patch out low mem accesses
            patch[ 0x8680 / 4 ] = ins( 14, 12, 0, 0);	  // addi r12,0,0x0
            patch[ 0x41ac / 4 ] = ins( 14, 3, 0, 0x544);  // addi r3,0,0x544;
            patch[ 0x8fa0 / 4 ] = ins( 14, 3, 0, 0x648);  // addi r3,0,0x648;
        }
    }
#endif

    if( pef) {
        kprintf( "pef = %08x, %08x\n", pef, propSize );
	inst = IONDRV::instantiate( regEntry, pef, propSize, handler, self );
	if( inst )
            regEntry->setProperty( "AAPL,ndrvInst", inst);

    } else
	inst = 0;

    return( inst );
}

const char * IONDRV::driverName( void )
{
    return( (const char *) theDriverDesc->driverOSRuntimeInfo.driverName);
}


