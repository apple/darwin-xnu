/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
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

#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOService.h>
#include <IOKit/IOCatalogue.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>

#include <pexpert/device_tree.h>

typedef UInt32  dtptr_t;

#include <machine/machine_routines.h>

extern "C" {

int IODTGetLoaderInfo( const char *key, void **infoAddr, int *infosize );
void IODTFreeLoaderInfo( const char *key, void *infoAddr, int infoSize );
int IODTGetDefault(const char *key, void *infoAddr, unsigned int infoSize );

}

#include <IOKit/assert.h>

#define IODTSUPPORTDEBUG 0

const IORegistryPlane * gIODTPlane;

static OSArray *	gIODTPHandles;
static OSArray *	gIODTPHandleMap;

const OSSymbol *	gIODTNameKey;
const OSSymbol *	gIODTUnitKey;
const OSSymbol *	gIODTCompatibleKey;
const OSSymbol * 	gIODTTypeKey;
const OSSymbol * 	gIODTModelKey;
const OSSymbol * 	gIODTTargetTypeKey;

const OSSymbol * 	gIODTSizeCellKey;
const OSSymbol * 	gIODTAddressCellKey;
const OSSymbol * 	gIODTRangeKey;

const OSSymbol *	gIODTPersistKey;

const OSSymbol *	gIODTDefaultInterruptController;
const OSSymbol *	gIODTAAPLInterruptsKey;
const OSSymbol *	gIODTPHandleKey;
const OSSymbol *	gIODTInterruptCellKey;
const OSSymbol *	gIODTInterruptParentKey;
const OSSymbol *	gIODTNWInterruptMappingKey;

OSDictionary   *	gIODTSharedInterrupts;

static IORegistryEntry * MakeReferenceTable( DTEntry dtEntry, bool copy );
static void AddPHandle( IORegistryEntry * regEntry );
static void FreePhysicalMemory( vm_offset_t * range );
static bool IODTMapInterruptsSharing( IORegistryEntry * regEntry, OSDictionary * allInts );

IORegistryEntry *
IODeviceTreeAlloc( void * dtTop )
{
    IORegistryEntry *		parent;
    IORegistryEntry *		child;
    IORegistryIterator *	regIter;
    DTEntryIterator		iter;
    DTEntry			dtChild;
    DTEntry			mapEntry;
    OSArray *			stack;
    OSData *			prop;
    OSDictionary *		allInts;
    vm_offset_t *		dtMap;
    unsigned int		propSize;
    bool			intMap;
    bool			freeDT;

    gIODTPlane = IORegistryEntry::makePlane( kIODeviceTreePlane );

    gIODTNameKey 		= OSSymbol::withCStringNoCopy( "name" );
    gIODTUnitKey 		= OSSymbol::withCStringNoCopy( "AAPL,unit-string" );
    gIODTCompatibleKey 	= OSSymbol::withCStringNoCopy( "compatible" );
    gIODTTypeKey 		= OSSymbol::withCStringNoCopy( "device_type" );
    gIODTModelKey 		= OSSymbol::withCStringNoCopy( "model" );
    gIODTTargetTypeKey		= OSSymbol::withCStringNoCopy( "target-type" );
    gIODTSizeCellKey 	= OSSymbol::withCStringNoCopy( "#size-cells" );
    gIODTAddressCellKey = OSSymbol::withCStringNoCopy( "#address-cells" );
    gIODTRangeKey 		= OSSymbol::withCStringNoCopy( "ranges" );
    gIODTPersistKey		= OSSymbol::withCStringNoCopy( "IODTPersist" );

    assert(    gIODTPlane && gIODTCompatibleKey
            && gIODTTypeKey && gIODTModelKey
            && gIODTSizeCellKey && gIODTAddressCellKey && gIODTRangeKey
            && gIODTPersistKey );

    gIODTDefaultInterruptController
		= OSSymbol::withCStringNoCopy("IOPrimaryInterruptController");
    gIODTNWInterruptMappingKey
		= OSSymbol::withCStringNoCopy("IONWInterrupts");

    gIODTAAPLInterruptsKey
		= OSSymbol::withCStringNoCopy("AAPL,interrupts");
    gIODTPHandleKey
		= OSSymbol::withCStringNoCopy("AAPL,phandle");

    gIODTInterruptParentKey
		= OSSymbol::withCStringNoCopy("interrupt-parent");

    gIODTPHandles	= OSArray::withCapacity( 1 );
    gIODTPHandleMap	= OSArray::withCapacity( 1 );

    gIODTInterruptCellKey
		= OSSymbol::withCStringNoCopy("#interrupt-cells");

    assert(    gIODTDefaultInterruptController && gIODTNWInterruptMappingKey 
	    && gIODTAAPLInterruptsKey
	    && gIODTPHandleKey && gIODTInterruptParentKey
	    && gIODTPHandles && gIODTPHandleMap
            && gIODTInterruptCellKey
	 );

    freeDT = (kSuccess == DTLookupEntry( 0, "/chosen/memory-map", &mapEntry ))
	  && (kSuccess == DTGetProperty( mapEntry,
                "DeviceTree", (void **) &dtMap, &propSize ))
	  && ((2 * sizeof(uint32_t)) == propSize);

    parent = MakeReferenceTable( (DTEntry)dtTop, freeDT );

    stack = OSArray::withObjects( (const OSObject **) &parent, 1, 10 );
    DTCreateEntryIterator( (DTEntry)dtTop, &iter );

    do {
        parent = (IORegistryEntry *)stack->getObject( stack->getCount() - 1);
        //parent->release();
        stack->removeObject( stack->getCount() - 1);

        while( kSuccess == DTIterateEntries( iter, &dtChild) ) {

            child = MakeReferenceTable( dtChild, freeDT );
            child->attachToParent( parent, gIODTPlane);

            AddPHandle( child );

            if( kSuccess == DTEnterEntry( iter, dtChild)) {
                stack->setObject( parent);
                parent = child;
            }
            // only registry holds retain
            child->release();
        }

    } while( stack->getCount()
		&& (kSuccess == DTExitEntry( iter, &dtChild)));

    stack->release();
    DTDisposeEntryIterator( iter);

    // parent is now root of the created tree

    // make root name first compatible entry (purely cosmetic)
    if( (prop = (OSData *) parent->getProperty( gIODTCompatibleKey))) {
        parent->setName( parent->getName(), gIODTPlane );
        parent->setName( (const char *) prop->getBytesNoCopy() );
    }

    // attach tree to meta root
    parent->attachToParent( IORegistryEntry::getRegistryRoot(), gIODTPlane);
    parent->release();

    if( freeDT ) {
        // free original device tree
        DTInit(0);
        IODTFreeLoaderInfo( "DeviceTree",
			    (void *)dtMap[0], (int) round_page(dtMap[1]) );
    }

    // adjust tree

    gIODTSharedInterrupts = OSDictionary::withCapacity(4);
    allInts = OSDictionary::withCapacity(4);
    intMap = false;
    regIter = IORegistryIterator::iterateOver( gIODTPlane,
						kIORegistryIterateRecursively );
    assert( regIter && allInts && gIODTSharedInterrupts );
    if( regIter && allInts && gIODTSharedInterrupts ) {
        while( (child = regIter->getNextObject())) {
            IODTMapInterruptsSharing( child, allInts );
            if( !intMap && child->getProperty( gIODTInterruptParentKey))
                intMap = true;

        }
        regIter->release();
    }

#if IODTSUPPORTDEBUG
    parent->setProperty("allInts", allInts);
    parent->setProperty("sharedInts", gIODTSharedInterrupts);

    regIter = IORegistryIterator::iterateOver( gIODTPlane,
						kIORegistryIterateRecursively );
    if (regIter) {
        while( (child = regIter->getNextObject())) {
	    OSArray *
	    array = OSDynamicCast(OSArray, child->getProperty( gIOInterruptSpecifiersKey ));
	    for( UInt32 i = 0; array && (i < array->getCount()); i++)
	    {
		IOOptionBits options;
		IOReturn ret = IODTGetInterruptOptions( child, i, &options );
		if( (ret != kIOReturnSuccess) || options)
		    IOLog("%s[%ld] %ld (%x)\n", child->getName(), i, options, ret);
	    }
	}
        regIter->release();
    }
#endif

    allInts->release();

    if( intMap)
        // set a key in the root to indicate we found NW interrupt mapping
        parent->setProperty( gIODTNWInterruptMappingKey,
                (OSObject *) gIODTNWInterruptMappingKey );

    return( parent);
}

int IODTGetLoaderInfo( const char *key, void **infoAddr, int *infoSize )
{
    IORegistryEntry		*chosen;
    OSData				*propObj;
    dtptr_t				*propPtr;
    unsigned int		propSize;
    int ret = -1;

    chosen = IORegistryEntry::fromPath( "/chosen/memory-map", gIODTPlane );
    if ( chosen == 0 ) return -1;

    propObj = OSDynamicCast( OSData, chosen->getProperty(key) );
    if ( propObj == 0 ) goto cleanup;

    propSize = propObj->getLength();
    if ( propSize != (2 * sizeof(dtptr_t)) ) goto cleanup;
 
    propPtr = (dtptr_t *)propObj->getBytesNoCopy();
    if ( propPtr == 0 ) goto cleanup;

    *infoAddr = (void *)(uintptr_t) (propPtr[0]);
    *infoSize = (int)               (propPtr[1]);

    ret = 0;

cleanup:
    chosen->release();

    return ret;
}

void IODTFreeLoaderInfo( const char *key, void *infoAddr, int infoSize )
{
    vm_offset_t			range[2];
    IORegistryEntry		*chosen;

    range[0] = (vm_offset_t)infoAddr;
    range[1] = (vm_offset_t)infoSize;
    FreePhysicalMemory( range );

    if ( key != 0 ) {
        chosen = IORegistryEntry::fromPath( "/chosen/memory-map", gIODTPlane );
        if ( chosen != 0 ) {
            chosen->removeProperty(key);
            chosen->release();
        }
    }
}

int IODTGetDefault(const char *key, void *infoAddr, unsigned int infoSize )
{
    IORegistryEntry		*defaults;
    OSData			*defaultObj;
    unsigned int		defaultSize;

    defaults = IORegistryEntry::fromPath( "/defaults", gIODTPlane );
    if ( defaults == 0 ) return -1;

    defaultObj = OSDynamicCast( OSData, defaults->getProperty(key) );
    if ( defaultObj == 0 ) return -1;

    defaultSize = defaultObj->getLength();
    if ( defaultSize > infoSize) return -1;

    memcpy( infoAddr, defaultObj->getBytesNoCopy(), defaultSize );

    return 0;
}

static void FreePhysicalMemory( vm_offset_t * range )
{
    vm_offset_t	virt;

    virt = ml_static_ptovirt( range[0] );
    if( virt) {
        ml_static_mfree( virt, range[1] );
    }
}

static IORegistryEntry *
MakeReferenceTable( DTEntry dtEntry, bool copy )
{
    IORegistryEntry		*regEntry;
    OSDictionary		*propTable;
    const OSSymbol		*nameKey;
    OSData				*data;
    const OSSymbol		*sym;
    DTPropertyIterator	dtIter;
    void				*prop;
    unsigned int		propSize;
    char				*name;
    char				location[ 32 ];
    bool				noLocation = true;
    bool				kernelOnly;

    regEntry = new IOService;

    if( regEntry && (false == regEntry->init())) {
        regEntry->release();
        regEntry = 0;
    }

    if( regEntry &&
      (kSuccess == DTCreatePropertyIterator( dtEntry, &dtIter))) {

        kernelOnly = (kSuccess == DTGetProperty(dtEntry, "kernel-only", &prop, &propSize));
        propTable = regEntry->getPropertyTable();

        while( kSuccess == DTIterateProperties( dtIter, &name)) {

            if(  kSuccess != DTGetProperty( dtEntry, name, &prop, &propSize ))
                continue;

            if( copy) {
                nameKey = OSSymbol::withCString(name);
                data = OSData::withBytes(prop, propSize);
            } else {
                nameKey = OSSymbol::withCStringNoCopy(name);
                data = OSData::withBytesNoCopy(prop, propSize);
            }
            assert( nameKey && data );

            if (kernelOnly)
                data->setSerializable(false);

            propTable->setObject( nameKey, data);
            data->release();
            nameKey->release();

            if( nameKey == gIODTNameKey ) {
                if( copy)
                    sym = OSSymbol::withCString( (const char *) prop);
                else
                    sym = OSSymbol::withCStringNoCopy( (const char *) prop);
                regEntry->setName( sym );
                sym->release();

            } else if( nameKey == gIODTUnitKey ) {
                // all OF strings are null terminated... except this one
                if( propSize >= (int) sizeof(location))
                    propSize = sizeof(location) - 1;
                strncpy( location, (const char *) prop, propSize );
                location[ propSize ] = 0;
                regEntry->setLocation( location );
                propTable->removeObject( gIODTUnitKey );
                noLocation = false;
    
            } else if(noLocation && (!strncmp(name, "reg", sizeof("reg")))) {
                // default location - override later
                snprintf(location, sizeof(location), "%X", *((uint32_t *) prop));
                regEntry->setLocation( location );
            }
        }
        DTDisposePropertyIterator( dtIter);
    }

    return( regEntry);
}

static void AddPHandle( IORegistryEntry * regEntry )
{
    OSData *	data;

    if( regEntry->getProperty( gIODTInterruptCellKey)
      && (data = OSDynamicCast( OSData, regEntry->getProperty( gIODTPHandleKey )))) {
        // a possible interrupt-parent
        gIODTPHandles->setObject( data );
        gIODTPHandleMap->setObject( regEntry );
    }
}

static IORegistryEntry * FindPHandle( UInt32 phandle )
{
    OSData			*data;
    IORegistryEntry *regEntry = 0;
    int				i;

    for( i = 0; (data = (OSData *)gIODTPHandles->getObject( i )); i++ ) {
        if( phandle == *((UInt32 *)data->getBytesNoCopy())) {
            regEntry = (IORegistryEntry *)
            gIODTPHandleMap->getObject( i );
            break;
        }
    }

    return( regEntry );
}

static bool GetUInt32( IORegistryEntry * regEntry, const OSSymbol * name,
			UInt32 * value )
{
    OSObject * obj;
    OSData   * data;
    bool       result;

    if (!(obj = regEntry->copyProperty(name))) return (false);

    result = ((data = OSDynamicCast(OSData, obj)) && (sizeof(UInt32) == data->getLength()));
    if (result) *value = *((UInt32 *) data->getBytesNoCopy());

    obj->release();
    return(result);
}

static IORegistryEntry * IODTFindInterruptParent( IORegistryEntry * regEntry, IOItemCount index )
{
    IORegistryEntry *	parent;
    UInt32		phandle;
    OSData	    *	data;
    unsigned int	len;

    if( (data = OSDynamicCast( OSData, regEntry->getProperty( gIODTInterruptParentKey )))
      && (sizeof(UInt32) <= (len = data->getLength()))) {
	if (((index + 1) * sizeof(UInt32)) > len)
	    index = 0;
	phandle = ((UInt32 *) data->getBytesNoCopy())[index];
	parent = FindPHandle( phandle );

    } else if( 0 == regEntry->getProperty( "interrupt-controller"))
        parent = regEntry->getParentEntry( gIODTPlane);
    else
        parent = 0;

    return( parent );
}

const OSSymbol * IODTInterruptControllerName( IORegistryEntry * regEntry )
{
    const OSSymbol	*sym;
    UInt32		phandle;
    bool		ok;
    char 		buf[48];

    ok = GetUInt32( regEntry, gIODTPHandleKey, &phandle);
    assert( ok );

    if( ok) {
        snprintf(buf, sizeof(buf), "IOInterruptController%08X", (uint32_t)phandle);
        sym = OSSymbol::withCString( buf );
    } else
        sym = 0;

    return( sym );
}

#define unexpected(a) { kprintf("unexpected %s:%d\n", __FILE__, __LINE__); a; }

static void IODTGetICellCounts( IORegistryEntry * regEntry,
			    UInt32 * iCellCount, UInt32 * aCellCount)
{
    if( !GetUInt32( regEntry, gIODTInterruptCellKey, iCellCount))
        unexpected( *iCellCount = 1 );
    if( !GetUInt32( regEntry, gIODTAddressCellKey, aCellCount))
        *aCellCount = 0;
}

static UInt32 IODTMapOneInterrupt( IORegistryEntry * regEntry, UInt32 * intSpec, UInt32 index,
				    OSData ** spec, const OSSymbol ** controller )
{
    IORegistryEntry *parent = 0;
    OSData			*data;
    UInt32			*addrCmp;
    UInt32			*maskCmp;
    UInt32			*map;
    UInt32			*endMap;
    UInt32			acells, icells, pacells, picells, cell;
    UInt32			i, original_icells;
    bool			cmp, ok = false;

    parent = IODTFindInterruptParent( regEntry, index );    
    IODTGetICellCounts( parent, &icells, &acells );
    addrCmp = 0;
    if( acells) {
        data = OSDynamicCast( OSData, regEntry->getProperty( "reg" ));
        if( data && (data->getLength() >= (acells * sizeof(UInt32))))
            addrCmp = (UInt32 *) data->getBytesNoCopy();
    }
    original_icells = icells;
    regEntry = parent;
    
    do {
#if IODTSUPPORTDEBUG
        kprintf ("IODTMapOneInterrupt: current regEntry name %s\n", regEntry->getName());
        kprintf ("acells - icells: ");
        for (i = 0; i < acells; i++) kprintf ("0x%08X ", addrCmp[i]);
        kprintf ("- ");
        for (i = 0; i < icells; i++) kprintf ("0x%08X ", intSpec[i]);
        kprintf ("\n");
#endif

        if( parent && (data = OSDynamicCast( OSData,
            regEntry->getProperty( "interrupt-controller")))) {
            // found a controller - don't want to follow cascaded controllers
            parent = 0;
            *spec = OSData::withBytesNoCopy( (void *) intSpec,
                                            icells * sizeof(UInt32));
            *controller = IODTInterruptControllerName( regEntry );
            ok = (*spec && *controller);
        } else if( parent && (data = OSDynamicCast( OSData,
                    regEntry->getProperty( "interrupt-map")))) {
            // interrupt-map
            map = (UInt32 *) data->getBytesNoCopy();
            endMap = map + (data->getLength() / sizeof(UInt32));
            data = OSDynamicCast( OSData, regEntry->getProperty( "interrupt-map-mask" ));
            if( data && (data->getLength() >= ((acells + icells) * sizeof(UInt32))))
                maskCmp = (UInt32 *) data->getBytesNoCopy();
            else
                maskCmp = 0;

#if IODTSUPPORTDEBUG
            if (maskCmp) {
                kprintf ("        maskCmp: ");
                for (i = 0; i < acells + icells; i++) {
                    if (i == acells)
                        kprintf ("- ");
                    kprintf ("0x%08X ", maskCmp[i]);
                }
                kprintf ("\n");
                kprintf ("         masked: ");
                for (i = 0; i < acells + icells; i++) {
                    if (i == acells)
                        kprintf ("- ");
                    kprintf ("0x%08X ", ((i < acells) ? addrCmp[i] : intSpec[i-acells]) & maskCmp[i]);
                }
                kprintf ("\n");
            } else
                kprintf ("no maskCmp\n");
#endif
            do {
#if IODTSUPPORTDEBUG
                kprintf ("            map: ");
                for (i = 0; i < acells + icells; i++) {
                    if (i == acells)
                        kprintf ("- ");
                    kprintf ("0x%08X ", map[i]);
                }
                kprintf ("\n");
#endif
                for( i = 0, cmp = true; cmp && (i < (acells + icells)); i++) {
                    cell = (i < acells) ? addrCmp[i] : intSpec[ i - acells ];
                    if( maskCmp)
                        cell &= maskCmp[i];
                    cmp = (cell == map[i]);
                }

                map += acells + icells;
                if( 0 == (parent = FindPHandle( *(map++) )))
                    unexpected(break);

                IODTGetICellCounts( parent, &picells, &pacells );
                if( cmp) {
                    addrCmp = map;
                    intSpec = map + pacells;
                    regEntry = parent;
                } else {
                    map += pacells + picells;
                }
            } while( !cmp && (map < endMap) );
            if (!cmp)
                parent = 0;
        } 

        if( parent) {
            IODTGetICellCounts( parent, &icells, &acells );
            regEntry = parent;
        }

    } while( parent);

    return( ok ? original_icells : 0 );
}

IOReturn IODTGetInterruptOptions( IORegistryEntry * regEntry, int source, IOOptionBits * options )
{
    OSArray *	controllers;
    OSArray *	specifiers;
    OSArray *	shared;
    OSObject *	spec;
    OSObject *	oneSpec;

    *options = 0;

    controllers = OSDynamicCast(OSArray, regEntry->getProperty(gIOInterruptControllersKey));
    specifiers  = OSDynamicCast(OSArray, regEntry->getProperty(gIOInterruptSpecifiersKey));

    if( !controllers || !specifiers)
        return (kIOReturnNoInterrupt);
    
    shared = (OSArray *) gIODTSharedInterrupts->getObject(
                        (const OSSymbol *) controllers->getObject(source) );
    if (!shared)
        return (kIOReturnSuccess);

    spec = specifiers->getObject(source);
    if (!spec)
        return (kIOReturnNoInterrupt);

    for (unsigned int i = 0;
            (oneSpec = shared->getObject(i))
            && (!oneSpec->isEqualTo(spec));
            i++ )	{}

    if (oneSpec)
        *options = kIODTInterruptShared;

    return (kIOReturnSuccess);
}

static bool IODTMapInterruptsSharing( IORegistryEntry * regEntry, OSDictionary * allInts )
{
    IORegistryEntry *	parent;
    OSData *		local;
    OSData *		local2;
    UInt32 *		localBits;
    UInt32 *		localEnd;
    IOItemCount		index;
    OSData * 		map;
    OSObject *		oneMap;
    OSArray *		mapped;
    OSArray *		controllerInts;
    const OSSymbol *	controller = 0;
    OSArray *		controllers;
    UInt32		skip = 1;
    bool		ok, nw;

    nw = (0 == (local = OSDynamicCast( OSData,
        regEntry->getProperty( gIODTAAPLInterruptsKey))));
    if( nw && (0 == (local = OSDynamicCast( OSData,
        regEntry->getProperty( "interrupts")))))
        return( true );		// nothing to see here

    if( nw && (parent = regEntry->getParentEntry( gIODTPlane))) {
        // check for bridges on old world
        if( (local2 = OSDynamicCast( OSData,
                parent->getProperty( gIODTAAPLInterruptsKey)))) {
            local = local2;
            nw = false;
        }
    }

    localBits = (UInt32 *) local->getBytesNoCopy();
    localEnd = localBits + (local->getLength() / sizeof(UInt32));
    index = 0;
    mapped = OSArray::withCapacity( 1 );
    controllers = OSArray::withCapacity( 1 );

    ok = (mapped && controllers);

    if( ok) do {
        if( nw) {
            skip = IODTMapOneInterrupt( regEntry, localBits, index, &map, &controller );
            if( 0 == skip) {
                IOLog("%s: error mapping interrupt[%d]\n",
                        regEntry->getName(), mapped->getCount());
                break;
            }
        } else {
            map = OSData::withData( local, mapped->getCount() * sizeof(UInt32),
				sizeof(UInt32));
            controller = gIODTDefaultInterruptController;
            controller->retain();
        }

	index++;
        localBits += skip;
        mapped->setObject( map );
        controllers->setObject( controller );

        if (allInts)
        {
            controllerInts = (OSArray *) allInts->getObject( controller );
            if (controllerInts)
	    {
                for (unsigned int i = 0; (oneMap = controllerInts->getObject(i)); i++)
                {
                    if (map->isEqualTo(oneMap))
                    {
                        controllerInts = (OSArray *) gIODTSharedInterrupts->getObject( controller );
                        if (controllerInts)
                            controllerInts->setObject(map);
                        else
                        {
                            controllerInts = OSArray::withObjects( (const OSObject **) &map, 1, 4 );
                            if (controllerInts)
                            {
                                gIODTSharedInterrupts->setObject( controller, controllerInts );
                                controllerInts->release();
                            }
                        }
                        break;
                    }
                }
		if (!oneMap)
                    controllerInts->setObject(map);
            }
            else
            {
                controllerInts = OSArray::withObjects( (const OSObject **) &map, 1, 16 );
                if (controllerInts)
                {
                    allInts->setObject( controller, controllerInts );
                    controllerInts->release();
                }
            }
        }

        map->release();
        controller->release();

    } while( localBits < localEnd);

    ok &= (localBits == localEnd);

    if( ok ) {
        // store results
        ok  = regEntry->setProperty( gIOInterruptControllersKey, controllers);
        ok &= regEntry->setProperty( gIOInterruptSpecifiersKey, mapped);
    }

    if( controllers)
        controllers->release();
    if( mapped)
        mapped->release();

    return( ok );
}

bool IODTMapInterrupts( IORegistryEntry * regEntry )
{
    return( IODTMapInterruptsSharing( regEntry, 0 ));
}

/*
 */

static bool
CompareKey( OSString * key,
		const IORegistryEntry * table, const OSSymbol * propName,
		OSString ** matchingName )
{
    OSObject		*prop;
    OSData			*data;
    OSString		*string;
    const char		*ckey;
    UInt32			keyLen;
    UInt32          nlen;
    const char		*names;
    const char		*lastName;
    bool			wild;
    bool			matched;
    const char		*result = 0;

    if( 0 == (prop = table->copyProperty( propName ))) return( 0 );

    if( (data = OSDynamicCast( OSData, prop ))) {
        names = (const char *) data->getBytesNoCopy();
        lastName = names + data->getLength();
    } else if( (string = OSDynamicCast( OSString, prop ))) {
        names = string->getCStringNoCopy();
        lastName = names + string->getLength() + 1;
    } else names = 0;

	if (names) {
		ckey = key->getCStringNoCopy();
		keyLen = key->getLength();
		wild = ('*' == key->getChar( keyLen - 1 ));

		do {
			// for each name in the property
			nlen = strnlen(names, lastName - names);
			if( wild)
				matched = ((nlen >= (keyLen - 1)) && (0 == strncmp(ckey, names, keyLen - 1)));
			else
				matched = (keyLen == nlen) && (0 == strncmp(ckey, names, keyLen));

			if( matched)
				result = names;

			names = names + nlen + 1;

		} while( (names < lastName) && (false == matched));
	}

    if (result && matchingName)	*matchingName = OSString::withCString( result );

	if (prop) prop->release();

    return (result != 0);
}


bool IODTCompareNubName( const IORegistryEntry * regEntry,
			 OSString * name, OSString ** matchingName )
{
    bool matched;

    matched = CompareKey( name, regEntry, gIODTNameKey,       matchingName)
		   || CompareKey( name, regEntry, gIODTCompatibleKey, matchingName)
		   || CompareKey( name, regEntry, gIODTTypeKey,       matchingName)
		   || CompareKey( name, regEntry, gIODTModelKey,      matchingName);

    return (matched);
}

bool IODTMatchNubWithKeys( IORegistryEntry * regEntry,
                                    const char * keys )
{
    OSObject	*obj;
    bool		result = false;

    obj = OSUnserialize( keys, 0 );

    if( obj) {
        result = regEntry->compareNames( obj );
		obj->release();
    }
#if DEBUG
    else IOLog("Couldn't unserialize %s\n", keys );
#endif

    return( result );
}

OSCollectionIterator * IODTFindMatchingEntries( IORegistryEntry * from,
			IOOptionBits options, const char * keys )
{
    OSSet					*result = 0;
    IORegistryEntry			*next;
    IORegistryIterator		*iter;
    OSCollectionIterator	*cIter;
    bool					cmp;
    bool					minus = options & kIODTExclusive;


    iter = IORegistryIterator::iterateOver( from, gIODTPlane,
		(options & kIODTRecursive) ? kIORegistryIterateRecursively : 0 );
    if( iter) {

        do {

            if( result)
                result->release();
            result = OSSet::withCapacity( 3 );
            if( !result)
                break;

            iter->reset();
            while( (next = iter->getNextObject())) {
    
                // Look for existence of a debug property to skip
                if( next->getProperty("AAPL,ignore"))
                    continue;
    
                if( keys) {
                    cmp = IODTMatchNubWithKeys( next, keys );
                    if( (minus && (false == cmp))
                            || ((false == minus) && (false != cmp)) )
                        result->setObject( next);
                } else
                    result->setObject( next);
            }
        } while( !iter->isValid());

        iter->release();
    }

    cIter = OSCollectionIterator::withCollection( result);
    if (result) result->release();

    return( cIter);
}


struct IODTPersistent {
    IODTCompareAddressCellFunc	compareFunc;
    IODTNVLocationFunc		locationFunc;
};

void IODTSetResolving( IORegistryEntry * 	regEntry,
		IODTCompareAddressCellFunc	compareFunc,
		IODTNVLocationFunc		locationFunc )
{
    IODTPersistent	persist;
    OSData			*prop;

    persist.compareFunc = compareFunc;
    persist.locationFunc = locationFunc;
    prop = OSData::withBytes( &persist, sizeof(persist));
    if( !prop)
        return;

    prop->setSerializable(false);
    regEntry->setProperty( gIODTPersistKey, prop);
    prop->release();
    return;
}

#if   defined(__arm__) || defined(__i386__) || defined(__x86_64__)
static SInt32 DefaultCompare( UInt32 cellCount, UInt32 left[], UInt32 right[] )
{
	cellCount--;
	return( left[ cellCount ] - right[ cellCount ] ); 
}
#else
#error Unknown architecture.
#endif

static void AddLengthToCells( UInt32 numCells, UInt32 *cells, UInt64 offset)
{
    if (numCells == 1)
    {
        cells[0] += (UInt32)offset;
    }
    else {
        UInt64 sum = cells[numCells - 1] + offset;
        cells[numCells - 1] = (UInt32)sum;
        if (sum > UINT32_MAX) {
            cells[numCells - 2] += (UInt32)(sum >> 32);
        }
    }
}

static IOPhysicalAddress CellsValue( UInt32 numCells, UInt32 *cells)
{
    if (numCells == 1) {
        return IOPhysical32( 0, cells[0] );
    } else {
        return IOPhysical32( cells[numCells - 2], cells[numCells - 1] );
    }
}

void IODTGetCellCounts( IORegistryEntry * regEntry,
			    UInt32 * sizeCount, UInt32 * addressCount)
{
    if( !GetUInt32( regEntry, gIODTSizeCellKey, sizeCount))
        *sizeCount = 1;
    if( !GetUInt32( regEntry, gIODTAddressCellKey, addressCount))
        *addressCount = 2;
    return;
}

// Given addr & len cells from our child, find it in our ranges property, then
// look in our parent to resolve the base of the range for us.

// Range[]: child-addr  our-addr  child-len
// #cells:    child       ours     child

bool IODTResolveAddressCell( IORegistryEntry * regEntry,
                             UInt32 cellsIn[],
                             IOPhysicalAddress * phys, IOPhysicalLength * lenOut )
{
    IORegistryEntry	*parent;
    OSData		*prop;
    // cells in addresses at regEntry
    UInt32		sizeCells, addressCells;
    // cells in addresses below regEntry
    UInt32		childSizeCells, childAddressCells;
    UInt32		childCells;
    UInt32		cell[ 8 ], propLen;
    UInt64		offset = 0;
    UInt32		endCell[ 8 ];
    UInt32		*range;
    UInt32		*lookRange;
    UInt32		*startRange;
    UInt32		*endRanges;
    bool		ok = true;
    SInt64		diff, diff2, endDiff;
    UInt64		len, rangeLen;

    IODTPersistent	*persist;
    IODTCompareAddressCellFunc	compare;

    IODTGetCellCounts( regEntry, &childSizeCells, &childAddressCells );
    childCells = childAddressCells + childSizeCells;

    if (childCells > sizeof(cell)/sizeof(cell[0]))
        panic("IODTResolveAddressCell: Invalid device tree (%u,%u)", (uint32_t)childAddressCells, (uint32_t)childSizeCells);

    bcopy( cellsIn, cell, sizeof(UInt32) * childCells );
    *lenOut = CellsValue( childSizeCells, cellsIn + childAddressCells );

    do
    {
        prop = OSDynamicCast( OSData, regEntry->getProperty( gIODTRangeKey ));
        if( 0 == prop) {
            /* end of the road */
            *phys = CellsValue( childAddressCells, cell );
            *phys += offset;
            break;
        }

        parent = regEntry->getParentEntry( gIODTPlane );
        IODTGetCellCounts( parent, &sizeCells, &addressCells );

        if( (propLen = prop->getLength())) {
            // search
            startRange = (UInt32 *) prop->getBytesNoCopy();
            range = startRange;
            endRanges = range + (propLen / sizeof(UInt32));

            prop = (OSData *) regEntry->getProperty( gIODTPersistKey );
            if( prop) {
                persist = (IODTPersistent *) prop->getBytesNoCopy();
                compare = persist->compareFunc;
            } else if (addressCells == childAddressCells) {
                compare = DefaultCompare;
            } else {
                panic("There is no mixed comparison function yet...");
            }

            for( ok = false;
                    range < endRanges;
                    range += (childCells + addressCells) ) {

                // is cell start within range?
                diff = (*compare)( childAddressCells, cell, range );

                if (childAddressCells > sizeof(endCell)/sizeof(endCell[0]))
                    panic("IODTResolveAddressCell: Invalid device tree (%u)", (uint32_t)childAddressCells);

                bcopy(range, endCell, childAddressCells * sizeof(UInt32));

                rangeLen = CellsValue(childSizeCells, range + childAddressCells + addressCells);
                AddLengthToCells(childAddressCells, endCell, rangeLen);

                diff2 = (*compare)( childAddressCells, cell, endCell );

                // if start of cell < start of range, or end of range >= start of cell, skip
                if ((diff < 0) || (diff2 >= 0))
                    continue;

                len = CellsValue(childSizeCells, cell + childAddressCells);
                ok = (0 == len);

                if (!ok)
                {
                    // search for cell end
                    bcopy(cell, endCell, childAddressCells * sizeof(UInt32));

                    AddLengthToCells(childAddressCells, endCell, len - 1);

                    for( lookRange = startRange;
                            lookRange < endRanges;
                            lookRange += (childCells + addressCells) )
                    {
                        // make sure end of cell >= range start
                        endDiff = (*compare)( childAddressCells, endCell, lookRange );
                        if( endDiff < 0)
                            continue;

                        UInt64 rangeStart = CellsValue(addressCells, range + childAddressCells);
                        UInt64 lookRangeStart = CellsValue(addressCells, lookRange + childAddressCells);
                        if ((endDiff - len + 1 + lookRangeStart) == (diff + rangeStart))
                        {
                            ok = true;
                            break;
                        }
                    }
                    if (!ok)
                        continue;
                }
                offset += diff;
                break;
            }

            if (addressCells + sizeCells > sizeof(cell)/sizeof(cell[0]))
                panic("IODTResolveAddressCell: Invalid device tree (%u, %u)", (uint32_t)addressCells, (uint32_t)sizeCells);

            // Get the physical start of the range from our parent
            bcopy( range + childAddressCells, cell, sizeof(UInt32) * addressCells );
            bzero( cell + addressCells, sizeof(UInt32) * sizeCells );

        } /* else zero length range => pass thru to parent */

        regEntry		= parent;
        childSizeCells		= sizeCells;
        childAddressCells	= addressCells;
        childCells		= childAddressCells + childSizeCells;
    }
    while( ok && regEntry);

    return( ok);
}


OSArray * IODTResolveAddressing( IORegistryEntry * regEntry,
			const char * addressPropertyName,
			IODeviceMemory * parent )
{
    IORegistryEntry		*parentEntry;
    OSData				*addressProperty;
    UInt32				sizeCells, addressCells, cells;
    int					i, num;
    UInt32				*reg;
    IOPhysicalAddress	phys;
    IOPhysicalLength	len;
    OSArray				*array;
    IODeviceMemory		*range;

    parentEntry = regEntry->getParentEntry( gIODTPlane );
    addressProperty = (OSData *) regEntry->getProperty( addressPropertyName );
    if( (0 == addressProperty) || (0 == parentEntry))
        return( 0);

    IODTGetCellCounts( parentEntry, &sizeCells, &addressCells );
    if( 0 == sizeCells)
        return( 0);

    cells = sizeCells + addressCells;
    reg = (UInt32 *) addressProperty->getBytesNoCopy();
    num = addressProperty->getLength() / (4 * cells);

    array = OSArray::withCapacity( 1 );
    if( 0 == array)
        return( 0);

    for( i = 0; i < num; i++) {
        if( IODTResolveAddressCell( parentEntry, reg, &phys, &len )) {
            range = 0;
            if( parent)
                range = IODeviceMemory::withSubRange( parent,
                        phys - parent->getPhysicalSegment(0, 0, kIOMemoryMapperNone), len );
            if( 0 == range)
                range = IODeviceMemory::withRange( phys, len );
            if( range)
                array->setObject( range );
        }
        reg += cells;
    }

    regEntry->setProperty( gIODeviceMemoryKey, array);
    array->release();	/* ??? */

    return( array);
}

static void IODTGetNVLocation(
	IORegistryEntry * parent,
	IORegistryEntry * regEntry,
	UInt8 * busNum, UInt8 * deviceNum, UInt8 * functionNum )
{

    OSData			*prop;
    IODTPersistent	*persist;
    UInt32			*cell;

    prop = (OSData *) parent->getProperty( gIODTPersistKey );
    if( prop) {
        persist = (IODTPersistent *) prop->getBytesNoCopy();
        (*persist->locationFunc)( regEntry, busNum, deviceNum, functionNum );
    } else {
        prop = (OSData *) regEntry->getProperty( "reg" );
        *functionNum	= 0;
        if( prop) {
            cell = (UInt32 *) prop->getBytesNoCopy();
            *busNum 	= 3;
            *deviceNum 	= 0x1f & (cell[ 0 ] >> 24);
        } else {
            *busNum 	= 0;
            *deviceNum 	= 0;
        }
    }
    return;
}

/*
 * Try to make the same messed up descriptor as Mac OS
 */

IOReturn IODTMakeNVDescriptor( IORegistryEntry * regEntry,
				IONVRAMDescriptor * hdr )
{
    IORegistryEntry		*parent;
    UInt32				level;
    UInt32				bridgeDevices;
    UInt8				busNum;
    UInt8				deviceNum;
    UInt8				functionNum;

    hdr->format 	= 1;
    hdr->marker 	= 0;

    for(level = 0, bridgeDevices = 0; 
    	(parent = regEntry->getParentEntry( gIODTPlane )) && (level < 7); level++ ) {

        IODTGetNVLocation( parent, regEntry,
			&busNum, &deviceNum, &functionNum );
        if( level)
            bridgeDevices |= ((deviceNum & 0x1f) << ((level - 1) * 5));
        else {
            hdr->busNum 	= busNum;
            hdr->deviceNum 	= deviceNum;
            hdr->functionNum 	= functionNum;
        }
        regEntry = parent;
    }
    hdr->bridgeCount 	= level - 2;
    hdr->bridgeDevices 	= bridgeDevices;

    return( kIOReturnSuccess );
}

OSData * IODTFindSlotName( IORegistryEntry * regEntry, UInt32 deviceNumber )
{
    IORegistryEntry		*parent;
    OSData				*data;
    OSData				*ret = 0;
    UInt32				*bits;
    UInt32				i;
    size_t              nlen;
    char				*names;
    char				*lastName;
    UInt32				mask;

    data = (OSData *) regEntry->getProperty("AAPL,slot-name");
    if( data)
        return( data);
    parent = regEntry->getParentEntry( gIODTPlane );
    if( !parent)
        return( 0 );
    data = OSDynamicCast( OSData, parent->getProperty("slot-names"));
    if( !data)
        return( 0 );
    if( data->getLength() <= 4)
        return( 0 );

    bits = (UInt32 *) data->getBytesNoCopy();
    mask = *bits;
    if( (0 == (mask & (1 << deviceNumber))))
        return( 0 );

    names = (char *)(bits + 1);
    lastName = names + (data->getLength() - 4);

    for( i = 0; (i <= deviceNumber) && (names < lastName); i++ ) {

        if( mask & (1 << i)) {
            nlen = 1 + strnlen(names, lastName - names);
            if( i == deviceNumber) {
                data = OSData::withBytesNoCopy(names, nlen);
                if( data) {
                    regEntry->setProperty("AAPL,slot-name", data);
                    ret = data;
                    data->release();
                }
            } else
                names += nlen;
        }
    }

    return( ret );
}

extern "C" IOReturn IONDRVLibrariesInitialize( IOService * provider )
{
    return( kIOReturnUnsupported );
}
