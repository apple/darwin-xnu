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
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/ndrvsupport/IONDRVSupport.h>
#include <IOKit/ndrvsupport/IONDRVFramebuffer.h>

#include <libkern/OSByteOrder.h>
#include <libkern/OSAtomic.h>
#include <IOKit/assert.h>

#include <pexpert/pexpert.h>

#include "IOPEFLibraries.h"
#include "IOPEFLoader.h"
#include "IONDRV.h"

#include <string.h>

extern "C"
{

extern void *kern_os_malloc(size_t size);
extern void kern_os_free(void * addr);

#define LOG		if(1) kprintf

#define LOGNAMEREG	0

/* NameRegistry error codes */
enum {
    nrLockedErr                    = -2536,
    nrNotEnoughMemoryErr        = -2537,
    nrInvalidNodeErr            = -2538,
    nrNotFoundErr                = -2539,
    nrNotCreatedErr                = -2540,
    nrNameErr                     = -2541,
    nrNotSlotDeviceErr            = -2542,
    nrDataTruncatedErr            = -2543,
    nrPowerErr                    = -2544,
    nrPowerSwitchAbortErr        = -2545,
    nrTypeMismatchErr            = -2546,
    nrNotModifiedErr            = -2547,
    nrOverrunErr                = -2548,
    nrResultCodeBase             = -2549,
    nrPathNotFound                 = -2550,    /* a path component lookup failed */
    nrPathBufferTooSmall         = -2551,    /* buffer for path is too small */    
    nrInvalidEntryIterationOp     = -2552,    /* invalid entry iteration operation */
    nrPropertyAlreadyExists     = -2553,    /* property already exists */
    nrIterationDone                = -2554,    /* iteration operation is done */
    nrExitedIteratorScope        = -2555,    /* outer scope of iterator was exited */
    nrTransactionAborted        = -2556        /* transaction was aborted */
};

enum {
    kNVRAMProperty        	= 0x00000020L,            // matches NR
    kRegMaximumPropertyNameLength	= 31
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

UInt32 _eEndianSwap32Bit( UInt32 data )
{
    return( OSReadSwapInt32(&data, 0));
}

UInt16 _eEndianSwap16Bit( UInt16 data )
{
    return( OSReadSwapInt16(&data, 0));
}

OSStatus _eExpMgrConfigReadLong( RegEntryID entryID, UInt8 offset, UInt32 * value )
{
    IORegistryEntry *	regEntry;
    IOPCIDevice *	ioDevice;
    UInt32		adj;

    REG_ENTRY_TO_OBJ( entryID, regEntry)

    ioDevice = OSDynamicCast( IOPCIDevice, regEntry );
    if( !ioDevice)
        ioDevice = OSDynamicCast( IOPCIDevice, regEntry->getParentEntry( gIODTPlane) );
    if( !ioDevice)
	return( nrNotSlotDeviceErr );

    adj = ioDevice->configRead32( offset );
#if 0
    IOMemoryMap *	map = 0;
    if( (offset >= kIOPCIConfigBaseAddress2)
     && (offset <= kIOPCIConfigBaseAddress5)) {
	if( (map = ioDevice->mapDeviceMemoryWithRegister( offset, kIOMapReference))) {
	    adj = (adj & 3) | (map->getVirtualAddress());
	    map->release();
	}
    }
#endif
    *value = adj;

    return( noErr );
}

OSStatus _eExpMgrConfigWriteLong( RegEntryID entryID, UInt8 offset, UInt32 value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    ioDevice->configWrite32( offset, value);

    return( noErr );
}


OSStatus _eExpMgrConfigReadWord( RegEntryID entryID, UInt8 offset, UInt16 * value )
{
    IORegistryEntry *	regEntry;
    IOPCIDevice *	ioDevice;

    REG_ENTRY_TO_OBJ( entryID, regEntry)

    ioDevice = OSDynamicCast( IOPCIDevice, regEntry );
    if( !ioDevice)
        ioDevice = OSDynamicCast( IOPCIDevice, regEntry->getParentEntry( gIODTPlane) );
    if( !ioDevice)
	return( nrNotSlotDeviceErr );

    *value = ioDevice->configRead16( offset );

    return( noErr );
}

OSStatus _eExpMgrConfigWriteWord( RegEntryID entryID, UInt8 offset, UInt16 value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    ioDevice->configWrite16( offset, value);

    return( noErr);
}

OSStatus _eExpMgrConfigReadByte( RegEntryID entryID, UInt8 offset, UInt8 * value )
{
    IORegistryEntry *	regEntry;
    IOPCIDevice *	ioDevice;

    REG_ENTRY_TO_OBJ( entryID, regEntry)

    ioDevice = OSDynamicCast( IOPCIDevice, regEntry );
    if( !ioDevice)
        ioDevice = OSDynamicCast( IOPCIDevice, regEntry->getParentEntry( gIODTPlane) );
    if( !ioDevice)
	return( nrNotSlotDeviceErr );

    *value = ioDevice->configRead8( offset );

    return( noErr );
}

OSStatus _eExpMgrConfigWriteByte( RegEntryID entryID, UInt8 offset, UInt8 value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    ioDevice->configWrite8( offset, value);

    return( noErr);
}

OSStatus _eExpMgrIOReadLong( RegEntryID entryID, UInt16 offset, UInt32 * value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    *value = ioDevice->ioRead32( offset );

    return( noErr);
}

OSStatus _eExpMgrIOWriteLong( RegEntryID entryID, UInt16 offset, UInt32 value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    ioDevice->ioWrite32( offset, value );

    return( noErr);
}

OSStatus _eExpMgrIOReadWord( RegEntryID entryID, UInt16 offset, UInt16 * value )
{
    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    *value = ioDevice->ioRead16( offset );

    return( noErr);
}

OSStatus _eExpMgrIOWriteWord( RegEntryID entryID, UInt16 offset, UInt16 value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    ioDevice->ioWrite16( offset, value );

    return( noErr);
}

OSStatus _eExpMgrIOReadByte( RegEntryID entryID, UInt16 offset, UInt8 * value )
{
    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    *value = ioDevice->ioRead8( offset );

    return( noErr);
}

OSStatus _eExpMgrIOWriteByte( RegEntryID entryID, UInt16 offset, UInt8 value )
{

    REG_ENTRY_TO_SERVICE( entryID, IOPCIDevice, ioDevice)

    ioDevice->ioWrite8( offset, value );

    return( noErr);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSStatus _eRegistryEntryIDCopy( RegEntryID entryID, RegEntryID to )
{
    bcopy( entryID, to, sizeof( RegEntryID) );
    return( noErr);
}


OSStatus _eRegistryEntryIDInit( RegEntryID entryID )
{
    MAKE_REG_ENTRY( entryID, 0);
    return( noErr);
}

/*
 * Compare EntryID's for equality or if invalid
 *
 * If a NULL value is given for either id1 or id2, the other id 
 * is compared with an invalid ID.  If both are NULL, the id's 
 * are consided equal (result = true). 
 *   note: invalid != uninitialized
 */
Boolean _eRegistryEntryIDCompare( RegEntryID entryID1, RegEntryID entryID2 )
{
    IORegistryEntry *	regEntry1;
    IORegistryEntry *	regEntry2;

    if( entryID1) {
 	REG_ENTRY_TO_OBJ_RET( entryID1, regEntry1, false)
    } else
	regEntry1 = 0;

    if( entryID2) {
	REG_ENTRY_TO_OBJ_RET( entryID2, regEntry2, false)
    } else
	regEntry2 = 0;

    return( regEntry1 == regEntry2 );
}

OSStatus _eRegistryPropertyGetSize( void *entryID, char *propertyName,
					UInt32 * propertySize )
{
    OSStatus		err = noErr;
    OSData *		prop;

    REG_ENTRY_TO_PT( entryID, regEntry)

    prop = (OSData *) regEntry->getProperty( propertyName); 
    if( prop)
	*propertySize = prop->getLength();
    else
	err = nrNotFoundErr;

#if LOGNAMEREG
    LOG("RegistryPropertyGetSize: %s : %d\n", propertyName, err);
#endif
    return( err);

}

OSStatus _eRegistryPropertyGet(void *entryID, char *propertyName, UInt32 *propertyValue, UInt32 *propertySize)
{
    OSStatus		err = noErr;
    OSData *		prop;
    UInt32		len;

    REG_ENTRY_TO_PT( entryID, regEntry)

    prop = OSDynamicCast( OSData, regEntry->getProperty( propertyName));
    if( prop) {

	len = *propertySize;
	*propertySize = prop->getLength();
	len = (len > prop->getLength()) ? prop->getLength() : len;
	bcopy( prop->getBytesNoCopy(), propertyValue, len);
#if LOGNAMEREG
	LOG("value: %08x ", *propertyValue);
#endif
    } else
	err = nrNotFoundErr;

#if LOGNAMEREG
    LOG("RegistryPropertyGet: %s : %d\n", propertyName, err);
#endif
    return( err);
}

OSStatus _eRegistryPropertyCreate( void *entryID, char *propertyName,
				void * propertyValue, UInt32 propertySize )
{
    OSStatus		err = noErr;
    OSData *		prop;

    REG_ENTRY_TO_PT( entryID, regEntry)

    prop = OSData::withBytes( propertyValue, propertySize );

    if( prop) {

        regEntry->setProperty( propertyName, prop);
	prop->release();

    } else
	err = nrNotCreatedErr;

#if LOGNAMEREG
    LOG("RegistryPropertyCreate: %s : %d\n", propertyName, err);
#endif
    return( err);
}

OSStatus _eRegistryPropertyDelete( void *entryID, char *propertyName )
{
    OSStatus		err = noErr;
    OSObject *		old;

    REG_ENTRY_TO_PT( entryID, regEntry)

    old = regEntry->getProperty(propertyName);
    if ( old )
        regEntry->removeProperty(propertyName);
    else
	err = nrNotFoundErr;

#if LOGNAMEREG
    LOG("RegistryPropertyDelete: %s : %d\n", propertyName, err);
#endif
    return( err);
}

void IONDRVSetNVRAMPropertyName( IORegistryEntry * regEntry,
				const OSSymbol * sym )
{
    regEntry->setProperty( "IONVRAMProperty", (OSObject *) sym );
}

static IOReturn IONDRVSetNVRAMPropertyValue( IORegistryEntry * regEntry,
				const OSSymbol * name, OSData * value )
{
    IOReturn			err;
    IODTPlatformExpert *	platform =
                (IODTPlatformExpert *) IOService::getPlatform();

    err = platform->writeNVRAMProperty( regEntry, name, value );

    return( err );
}

OSStatus _eRegistryPropertySet( void *entryID, char *propertyName, void * propertyValue, UInt32 propertySize )
{
    OSStatus			err = noErr;
    OSData *			prop;
    const OSSymbol *		sym;

    REG_ENTRY_TO_PT( entryID, regEntry)

    sym = OSSymbol::withCString( propertyName );
    if( !sym)
	return( kIOReturnNoMemory );

    prop = OSDynamicCast( OSData, regEntry->getProperty( sym ));
    if( 0 == prop)
	err = nrNotFoundErr;

    else if( (prop = OSData::withBytes( propertyValue, propertySize))) {
        regEntry->setProperty( sym, prop);

	if( (sym == (const OSSymbol *)
		regEntry->getProperty("IONVRAMProperty")))
	    err = IONDRVSetNVRAMPropertyValue( regEntry, sym, prop );
	prop->release();

    } else
	err = nrNotCreatedErr;

    sym->release();

#if LOGNAMEREG
    LOG("RegistryPropertySet: %s : %d\n", propertyName, err);
#endif
    return( err);
}

OSStatus _eRegistryPropertyGetMod(void * entryID, char * propertyName,
				 UInt32 * mod)
{
    const OSSymbol *	sym;

    REG_ENTRY_TO_PT( entryID, regEntry)

    if( (sym = OSDynamicCast( OSSymbol,
		regEntry->getProperty("IONVRAMProperty")))
      && (0 == strcmp( propertyName, sym->getCStringNoCopy())))

	*mod = kNVRAMProperty;
    else
	*mod = 0;

    return( noErr);
}

OSStatus _eRegistryPropertySetMod(void *entryID, char *propertyName, 
		UInt32 mod )
{
    OSStatus		err = noErr;
    OSData *		data;
    const OSSymbol *	sym;

    REG_ENTRY_TO_PT( entryID, regEntry)

    if( (mod & kNVRAMProperty)
      && (sym = OSSymbol::withCString( propertyName ))) {

	if( (data = OSDynamicCast( OSData, regEntry->getProperty( sym))) ) {
	    err = IONDRVSetNVRAMPropertyValue( regEntry, sym, data );
	    if( kIOReturnSuccess == err)
                IONDRVSetNVRAMPropertyName( regEntry, sym );
	}
	sym->release();
    }

    return( err);
}

OSStatus _eVSLSetDisplayConfiguration(RegEntryID * entryID,
                        char *	propertyName,
                        void *	configData,
                        long	configDataSize)
{
    IOReturn		err = nrNotCreatedErr;
    IORegistryEntry *	options;
    const OSSymbol *	sym = 0;
    OSData *		data = 0;
    enum {		kMaxDisplayConfigDataSize = 64 };

    if( (configDataSize > kMaxDisplayConfigDataSize)
     || (strlen(propertyName) > kRegMaximumPropertyNameLength))
        return( nrNotCreatedErr );

    do {
        options = IORegistryEntry::fromPath( "/options", gIODTPlane);
        if( !options)
            continue;
        data = OSData::withBytes( configData, configDataSize );
        if( !data)
            continue;
        sym = OSSymbol::withCString( propertyName );
        if( !sym)
            continue;
        if( !options->setProperty( sym, data ))
            continue;
        err = kIOReturnSuccess;

    } while( false );

    if( options)
        options->release();
    if( data)
        data->release();
    if( sym)
        sym->release();

    return( err );
}

OSStatus _eRegistryPropertyIterateCreate( RegEntryID * entryID,
						OSCollectionIterator ** cookie)
{

    REG_ENTRY_TO_PT( entryID, regEntry)

    // NB. unsynchronized. But should only happen on an owned nub!
    // Should non OSData be filtered out?
    *cookie = OSCollectionIterator::withCollection(
		 regEntry->getPropertyTable());

    if( *cookie)
	return( noErr);
    else
	return( nrNotEnoughMemoryErr);
}

OSStatus _eRegistryPropertyIterateDispose( OSCollectionIterator ** cookie)
{
    if( *cookie) {
        (*cookie)->release();
        *cookie = NULL;
        return( noErr);
    } else
	return( nrIterationDone);
}


OSStatus _eRegistryPropertyIterate( OSCollectionIterator ** cookie,
					char * name, Boolean * done )
{
    const OSSymbol *	key;

    key = (const OSSymbol *) (*cookie)->getNextObject();
    if( key)
	strncpy( name, key->getCStringNoCopy(), kRegMaximumPropertyNameLength);

    // Seems to be differences in handling "done".
    // ATI assumes done = true when getting the last property.
    // The Book says done is true after last property.
    // ATI does check err, so this will work.
    // Control ignores err and checks done.

    *done = (key == 0);

    if( 0 != key)
	return( noErr);
    else
	return( nrIterationDone );
}

OSStatus
_eRegistryEntryIterateCreate( IORegistryIterator ** cookie)
{
    *cookie = IORegistryIterator::iterateOver( gIODTPlane );
    if( *cookie)
	return( noErr);
    else
	return( nrNotEnoughMemoryErr);
}

OSStatus
_eRegistryEntryIterateDispose( IORegistryIterator ** cookie)
{
    if( *cookie) {
        (*cookie)->release();
        *cookie = NULL;
        return( noErr);
    } else
	return( nrIterationDone);
}

OSStatus
_eRegistryEntryIterate( IORegistryIterator **	cookie,
			UInt32		/* relationship */,
			RegEntryID 	foundEntry,
			Boolean *	done)
{
    IORegistryEntry *	regEntry;

    // TODO: check requested type of iteration
    regEntry = (*cookie)->getNextObjectRecursive();

    MAKE_REG_ENTRY( foundEntry, regEntry);
    *done = (0 == regEntry);

#if LOGNAMEREG
    if( regEntry)
        LOG("RegistryEntryIterate: %s\n", regEntry->getName( gIODTPlane ));
#endif

    if( regEntry)
	return( noErr);
    else
	return( nrNotFoundErr);
}

OSStatus
_eRegistryCStrEntryToName( const RegEntryID *	entryID,
			RegEntryID		parentEntry,
			char *			nameComponent,
			Boolean *		done )
{
    IORegistryEntry *	regEntry;

    REG_ENTRY_TO_OBJ( entryID, regEntry)

    strncpy( nameComponent, regEntry->getName( gIODTPlane ), kRegMaximumPropertyNameLength );
    nameComponent[ kRegMaximumPropertyNameLength ] = 0;

    regEntry = regEntry->getParentEntry( gIODTPlane );
    if( regEntry) {
	MAKE_REG_ENTRY( parentEntry, regEntry);
	*done = false;
    } else
	*done = true;

    return( noErr);
}

OSStatus
_eRegistryCStrEntryLookup(  const RegEntryID *	parentEntry,
			    const char 	*	path,
			    RegEntryID		newEntry)
{
    IOReturn		err;
    IORegistryEntry *	regEntry = 0;
    char *		buf;
    char *		cvtPath;
    char		c;
#define kDTRoot		"Devices:device-tree:"
#define kMacIORoot	"Devices:device-tree:pci:mac-io:"

    if( parentEntry) {
        REG_ENTRY_TO_OBJ( parentEntry, regEntry)
    } else
        regEntry = 0;

    buf = IONew( char, 512 );
    if( !buf)
	return( nrNotEnoughMemoryErr );

    cvtPath = buf;
    if( ':' == path[0])
	path++;
    else if( 0 == strncmp( path, kMacIORoot, strlen( kMacIORoot ))) {
	path += strlen( kMacIORoot ) - 7;
	regEntry = 0;
    }
    else if( 0 == strncmp( path, kDTRoot, strlen( kDTRoot ))) {
	path += strlen( kDTRoot ) - 1;
	regEntry = 0;
    }

    do {
	c = *(path++);
	if( ':' == c)
	    c = '/';
	*(cvtPath++) = c;
    } while( c != 0 );

    if( regEntry)
	regEntry = regEntry->childFromPath( buf, gIODTPlane );
    else
	regEntry = IORegistryEntry::fromPath( buf, gIODTPlane );

    if( regEntry) {
	MAKE_REG_ENTRY( newEntry, regEntry);
	regEntry->release();
	err = noErr;
    } else
	err = nrNotFoundErr;

    IODelete( buf, char, 512 );

    return( err );
}


OSStatus
_eRegistryCStrEntryCreate(  const RegEntryID *	parentEntry,
			    char 	*	name,
			    RegEntryID		newEntry)
{
    IORegistryEntry *	newDev;
    IORegistryEntry *	parent;

    REG_ENTRY_TO_OBJ( parentEntry, parent)

    // NOT published

    newDev = new IORegistryEntry;
    if( newDev && (false == newDev->init()))
	newDev = 0;

    if( newDev) {
	newDev->attachToParent( parent, gIODTPlane );
	if( ':' == name[0])
	    name++;
	newDev->setName( name );
    }

    MAKE_REG_ENTRY( newEntry, newDev);

    if( newDev)
	return( noErr);
    else
	return( nrNotCreatedErr);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" {

// in NDRVLibrariesAsm.s
extern void _eSynchronizeIO( void );

// platform expert
extern vm_offset_t
PEResidentAddress( vm_offset_t address, vm_size_t length );

};

enum {
    kProcessorCacheModeDefault		= 0,
    kProcessorCacheModeInhibited 	= 1,
    kProcessorCacheModeWriteThrough 	= 2,
    kProcessorCacheModeCopyBack		= 3
};

OSStatus _eSetProcessorCacheMode( UInt32 /* space */, void * /* addr */,
				 UInt32 /* len */, UInt32 /* mode */ )
{
#if 0
    struct phys_entry*	pp;
    vm_offset_t 	spa;
    vm_offset_t 	epa;
    int			wimg;

    // This doesn't change any existing kernel mapping eg. BAT changes etc.
    // but this is enough to change user level mappings for DPS etc.
    // Should use a kernel service when one is available.

    spa = kvtophys( (vm_offset_t)addr);
    if( spa == 0) {
	spa = PEResidentAddress( (vm_offset_t)addr, len);
	if( spa == 0)
	    return( kIOReturnVMError);
    }
    epa = (len + spa + 0xfff) & 0xfffff000;
    spa &=  0xfffff000;

    switch( mode) {
	case kProcessorCacheModeWriteThrough:
	    wimg = PTE_WIMG_WT_CACHED_COHERENT_GUARDED;
	    break;
	case kProcessorCacheModeCopyBack:
	    wimg = PTE_WIMG_CB_CACHED_COHERENT_GUARDED;
	    break;
	default:
	    wimg = PTE_WIMG_UNCACHED_COHERENT_GUARDED;
	    break;
    }

    while( spa < epa) {
	pp = pmap_find_physentry(spa);
	if (pp != PHYS_NULL)
	    pp->pte1.bits.wimg = wimg;
	spa += PAGE_SIZE;
    }
#endif
    _eSynchronizeIO();
    return( noErr);
}

char * _ePStrCopy( char *to, const char *from )
{
    UInt32	len;
    char   *	copy;

    copy = to;
    len = *(from++);
    *(copy++) = len;
    bcopy( from, copy, len);
    return( to);
}

LogicalAddress _ePoolAllocateResident(ByteCount byteSize, Boolean clear)
{
    LogicalAddress  mem;

    mem = (LogicalAddress) kern_os_malloc( (size_t) byteSize );
    if( clear && mem)
        memset( mem, 0, byteSize);

    return( mem);
}

OSStatus _ePoolDeallocate( LogicalAddress address )
{
    kern_os_free( (void *) address );
    return( noErr);
}

UInt32	_eCurrentExecutionLevel(void)
{
	return(0);		// == kTaskLevel, HWInt == 6
}

// don't expect any callers of this
OSErr _eIOCommandIsComplete( UInt32 /* commandID */, OSErr result)
{
    LOG("_eIOCommandIsComplete\n");
    return( result);		// !!??!!
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <kern/clock.h>


AbsoluteTime _eUpTime( void )
{
    AbsoluteTime    result;

    clock_get_uptime( &result);

    return( result);
}

AbsoluteTime _eAddAbsoluteToAbsolute(AbsoluteTime left, AbsoluteTime right)
{
    AbsoluteTime    result = left;

    ADD_ABSOLUTETIME( &left, &right);

    return( result);
}


AbsoluteTime _eSubAbsoluteFromAbsolute(AbsoluteTime left, AbsoluteTime right)
{
    AbsoluteTime    result = left;

    // !! ATI bug fix here:
    // They expect the 64-bit result to be signed. The spec says < 0 => 0
    // To workaround, make sure this routine takes 10 us to execute.
    IODelay( 10);

    if( CMP_ABSOLUTETIME( &result, &right) < 0) {
        AbsoluteTime_to_scalar( &result ) = 0;
    } else {
        result = left;
        SUB_ABSOLUTETIME( &result, &right);
    }

    return( result);
}


AbsoluteTime    _eDurationToAbsolute( Duration theDuration)
{
    AbsoluteTime    result;

    if( theDuration > 0) {
        clock_interval_to_absolutetime_interval( theDuration, kMillisecondScale,
                                                 &result );

    } else {
        clock_interval_to_absolutetime_interval( (-theDuration), kMicrosecondScale,
                                                 &result );
    }

    return( result);
}

AbsoluteTime _eAddDurationToAbsolute( Duration duration, AbsoluteTime absolute )
{
    return( _eAddAbsoluteToAbsolute(_eDurationToAbsolute( duration), absolute));
}

#define UnsignedWideToUInt64(x)		(*(UInt64 *)(x))
#define UInt64ToUnsignedWide(x)		(*(UnsignedWide *)(x))

AbsoluteTime    _eNanosecondsToAbsolute ( UnsignedWide theNanoseconds)
{
    AbsoluteTime result;
    UInt64	nano = UnsignedWideToUInt64(&theNanoseconds);

    nanoseconds_to_absolutetime( nano, &result);

    return( result);
}

UnsignedWide    _eAbsoluteToNanoseconds( AbsoluteTime absolute )
{
    UnsignedWide result;
    UInt64	nano;

    absolutetime_to_nanoseconds( absolute, &nano);
    result = UInt64ToUnsignedWide( &nano );

    return( result);
}

Duration    _eAbsoluteDeltaToDuration( AbsoluteTime left, AbsoluteTime right )
{
    Duration		dur;
    AbsoluteTime	result;
    UInt64		nano;
    
    if( CMP_ABSOLUTETIME( &left, &right) < 0)
	return( 0);

    result = left;
    SUB_ABSOLUTETIME( &result, &right);
    absolutetime_to_nanoseconds( result, &nano);

    if( nano >= ((1ULL << 31) * 1000ULL)) {
        // +ve milliseconds
        if( nano >= ((1ULL << 31) * 1000ULL * 1000ULL))
	    dur = 0x7fffffff;
        else
            dur = nano / 1000000ULL;
    } else {
        // -ve microseconds
        dur = -(nano / 1000ULL);
    }

    return( dur);
}


OSStatus    _eDelayForHardware( AbsoluteTime time )
{
    AbsoluteTime	deadline;

    clock_absolutetime_interval_to_deadline( time, &deadline );
    clock_delay_until( deadline );

    return( noErr);
}

OSStatus    _eDelayFor( Duration theDuration )
{
#if 1

// In Marconi, DelayFor uses the old toolbox Delay routine
// which is based on the 60 Hz timer. Durations are not
// rounded up when converting to ticks. Yes, really.
// Some ATI drivers call DelayFor(1) 50000 times starting up.
// There is some 64-bit math there so we'd better reproduce
// the overhead of that calculation.

#define DELAY_FOR_TICK_NANO		16666666
#define DELAY_FOR_TICK_MILLI		17
#define NANO32_MILLI			4295

    UnsignedWide	nano;
    AbsoluteTime	abs;
    unsigned int	ms;

    abs = _eDurationToAbsolute( theDuration);
    nano = _eAbsoluteToNanoseconds( abs);

    ms = (nano.lo / DELAY_FOR_TICK_NANO) * DELAY_FOR_TICK_MILLI;
    ms += nano.hi * NANO32_MILLI;
    if( ms)
        IOSleep( ms);

#else
    // Accurate, but incompatible, version

#define SLEEP_THRESHOLD		5000

    if( theDuration < 0) {

	// us duration
	theDuration -= theDuration;
	if( theDuration > SLEEP_THRESHOLD)
	    IOSleep( (theDuration + 999) / 1000);
	else
	    IODelay( theDuration);

    } else {

	// ms duration
        if( theDuration > (SLEEP_THRESHOLD / 1000))
            IOSleep( theDuration );                     	// ms
	else
            IODelay( theDuration * 1000);			// us
    }
#endif

    return( noErr);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSStatus _eCallOSTrapUniversalProc( UInt32 /* theProc */,
					UInt32 procInfo, UInt32 trap, UInt8 * pb )
{
    OSStatus    err = -40;
    struct PMgrOpParamBlock {
        SInt16	pmCommand;
        SInt16	pmLength;
        UInt8 *	pmSBuffer;
        UInt8 *	pmRBuffer;
        UInt8	pmData[4];
    };
#define	readExtSwitches	0xDC

    if( (procInfo == 0x133822)
     && (trap == 0xa085) ) {

        PMgrOpParamBlock * pmOp = (PMgrOpParamBlock *) pb;

        if( (readExtSwitches == pmOp->pmCommand) && pmOp->pmRBuffer) {
            OSNumber * num = OSDynamicCast(OSNumber,
                                IOService::getPlatform()->getProperty("AppleExtSwitchBootState"));
            *pmOp->pmRBuffer = (num->unsigned32BitValue() & 1);
            err = noErr;
        }

    } else if( (procInfo == 0x133822)
            && (trap == 0xa092) ) {

	UInt8 addr, reg, data;

	addr = pb[ 2 ];
	reg = pb[ 3 ];
	pb = *( (UInt8 **) ((UInt32) pb + 8));
	data = pb[ 1 ];
	(*PE_write_IIC)( addr, reg, data );
	err = noErr;
    }
    return( err);
}

const UInt32 * _eGetKeys( void )
{
    static const UInt32 zeros[] = { 0, 0, 0, 0 };

    return( zeros);
}

UInt32 _eGetIndADB( void * adbInfo, UInt32 /* index */)
{
    bzero( adbInfo, 10);
    return( 0);		// orig address
}

char * _eLMGetPowerMgrVars( void )
{
    static char * powerMgrVars = NULL;

    if( powerMgrVars == NULL) {
	powerMgrVars = (char *) IOMalloc( 0x3c0);
	if( powerMgrVars)
	    bzero( powerMgrVars, 0x3c0);
    }
    return( powerMgrVars);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSStatus _eNoErr( void )
{
    return( noErr);
}

OSStatus _eFail( void )
{
    return( -40);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// fix this!

#define 	heathrowID		((volatile UInt32 *)0xf3000034)
#define 	heathrowTermEna		(1 << 3)
#define 	heathrowTermDir		(1 << 0)

#define 	heathrowFeatureControl	((volatile UInt32 *)0xf3000038)
#define 	heathrowMBRES		(1 << 24)

#define 	heathrowBrightnessControl ((volatile UInt8 *)0xf3000032)
#define		defaultBrightness	144
#define 	heathrowContrastControl ((volatile UInt8 *)0xf3000033)
#define		defaultContrast		183

#define 	gossamerSystemReg1	((volatile UInt16 *)0xff000004)
#define		gossamerAllInOne	(1 << 4)

void _eATISetMBRES( UInt32 state )
{
    UInt32	value;

    value = *heathrowFeatureControl;

    if( state == 0)
	value &= ~heathrowMBRES;
    else if( state == 1)
	value |= heathrowMBRES;

    *heathrowFeatureControl = value;
    eieio();
}

void _eATISetMonitorTermination( Boolean enable )
{

    UInt32	value;

    value = *heathrowID;

    value |= heathrowTermEna;
    if( enable)
	value |= heathrowTermDir;
    else
	value &= ~heathrowTermDir;

    *heathrowID = value;
    eieio();
}

Boolean _eATIIsAllInOne( void )
{
    Boolean	rtn;
    static bool	didBrightness;

    rtn = (0 == ((*gossamerSystemReg1) & gossamerAllInOne));
    if( rtn && !didBrightness) {
	*heathrowBrightnessControl = defaultBrightness;
        eieio();
	*heathrowContrastControl = defaultContrast;
        eieio();
        didBrightness = true;
    }
    return( rtn);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void IONDRVInterruptAction(	OSObject * target, void * refCon,
					IOService * provider, int index )
{
    IONDRVInterruptSet *	set;
    IONDRVInterruptSource *	source;
    SInt32			result;

    set = (IONDRVInterruptSet *) target;
    index++;

    do {

	assert( (UInt32) index <= set->count);
	if( (UInt32) index > set->count)
	    break;

        source = set->sources + index;
        result = CallTVector( set, (void *) index, source->refCon, 0, 0, 0,
                                    source->handler );

	switch( result ) {

            case kIONDRVIsrIsNotComplete:
		index++;
            case kIONDRVIsrIsComplete:
		break;

            case kIONDRVMemberNumberParent:
		assert( false );
		break;

            default:
                index = result;
		set = set->child;
		break;
	}

    } while( result != kIONDRVIsrIsComplete );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static SInt32 IONDRVStdInterruptHandler( IONDRVInterruptSetMember setMember,
					void *refCon, UInt32 theIntCount )
{
//    assert( false );

    return( kIONDRVIsrIsComplete );
}

static bool IONDRVStdInterruptDisabler( IONDRVInterruptSetMember setMember,
					void *refCon )
{
    IONDRVInterruptSet *	set;
    IONDRVInterruptSource *	source;
    bool			was;

    set = (IONDRVInterruptSet *) setMember.setID;
    assert( OSDynamicCast( IONDRVInterruptSet, set ));
    assert( setMember.member <= set->count );
    source = set->sources + setMember.member;

    was = source->enabled;
    source->enabled = false;

    assert( set->provider );
    set->provider->disableInterrupt( setMember.member - 1 );

    return( was );
}

static void IONDRVStdInterruptEnabler( IONDRVInterruptSetMember setMember,
					void *refCon )
{
    IONDRVInterruptSet *	set;
    IONDRVInterruptSource *	source;

    set = (IONDRVInterruptSet *) setMember.setID;
    assert( OSDynamicCast( IONDRVInterruptSet, set ));
    assert( setMember.member <= set->count );
    source = set->sources + setMember.member;

    source->enabled = true;

    assert( set->provider );

    if( !source->registered) {
        source->registered = true;
        set->provider->registerInterrupt( setMember.member - 1, set,
				&IONDRVInterruptAction, (void *) 0x53 );
    }

    set->provider->enableInterrupt( setMember.member - 1 );
}

static IOTVector tvIONDRVStdInterruptHandler  = { IONDRVStdInterruptHandler,  0 };
static IOTVector tvIONDRVStdInterruptEnabler  = { IONDRVStdInterruptEnabler,  0 };
static IOTVector tvIONDRVStdInterruptDisabler = { IONDRVStdInterruptDisabler, 0 };


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSStatus
_eGetInterruptFunctions(    void *	setID,
			    UInt32	member,
			    void **	refCon,
			    IOTVector **	handler,
			    IOTVector **	enabler,
			    IOTVector **	disabler )
{
    IONDRVInterruptSet *	set;
    IONDRVInterruptSource *	source;
    OSStatus			err = noErr;

    set = (IONDRVInterruptSet *) setID;
    assert( OSDynamicCast( IONDRVInterruptSet, set ));
    assert( member <= set->count );
    source = set->sources + member;

    if( refCon)
	*refCon   = source->refCon;
    if( handler)
	*handler  = source->handler;
    if( enabler)
	*enabler  = source->enabler;
    if( disabler)
	*disabler = source->disabler;

    return( err);
}

IOReturn
IONDRVInstallInterruptFunctions(void *	setID,
			    UInt32	member,
			    void *	refCon,
			    IOTVector *	handler,
			    IOTVector *	enabler,
			    IOTVector *	disabler )
{
    IONDRVInterruptSet *	set;
    IONDRVInterruptSource *	source;
    OSStatus			err = noErr;

    set = (IONDRVInterruptSet *) setID;
    assert( OSDynamicCast( IONDRVInterruptSet, set ));
    if( member > set->count )
        return( paramErr );
    source = set->sources + member;

    source->refCon = refCon;
    if( handler)
	source->handler  = handler;
    if( enabler)
	source->enabler  = enabler;
    if( disabler)
	source->disabler = disabler;

    return( err);
}

OSStatus
_eInstallInterruptFunctions(void *	setID,
			    UInt32	member,
			    void *	refCon,
			    IOTVector *	handler,
			    IOTVector *	enabler,
			    IOTVector *	disabler )
{
    return( IONDRVInstallInterruptFunctions( setID, member, refCon,
                                    handler, enabler, disabler ));
}

OSStatus
_eCreateInterruptSet(	void *		parentSet,
			UInt32		parentMember,
			UInt32		setSize,
			void **		setID,
			IOOptionBits	options )
{
    IONDRVInterruptSet *	set;
    IONDRVInterruptSet *	newSet;
    IONDRVInterruptSource *	source;
    OSStatus			err = noErr;

    set = (IONDRVInterruptSet *) parentSet;
    assert( OSDynamicCast( IONDRVInterruptSet, set ));
    assert( parentMember <= set->count );
    source = set->sources + parentMember;

    newSet = IONDRVInterruptSet::with( 0, options, setSize );
    assert( newSet );

    if( newSet) for( UInt32 i = 1; i <= setSize; i++ ) {

	source = newSet->sources + i;
	source->handler 	= &tvIONDRVStdInterruptHandler;
	source->enabler 	= &tvIONDRVStdInterruptEnabler;
	source->disabler 	= &tvIONDRVStdInterruptDisabler;
    }

    set->child = newSet;
    *setID = newSet;

    return( err );
}

OSStatus 
_eDeleteInterruptSet(	void *		setID )
{
    IONDRVInterruptSet *	set;
    OSStatus			err = noErr;

    set = (IONDRVInterruptSet *) setID;
    assert( OSDynamicCast( IONDRVInterruptSet, set ));

    set->release();

    return( err );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define MAKEFUNC(s,e) { s, e, 0 }

static FunctionEntry PCILibFuncs[] =
{
    MAKEFUNC( "ExpMgrConfigReadLong", _eExpMgrConfigReadLong),
    MAKEFUNC( "ExpMgrConfigReadWord", _eExpMgrConfigReadWord),
    MAKEFUNC( "ExpMgrConfigReadByte", _eExpMgrConfigReadByte),
    MAKEFUNC( "ExpMgrConfigWriteLong", _eExpMgrConfigWriteLong),
    MAKEFUNC( "ExpMgrConfigWriteWord", _eExpMgrConfigWriteWord),
    MAKEFUNC( "ExpMgrConfigWriteByte", _eExpMgrConfigWriteByte),

    MAKEFUNC( "ExpMgrIOReadLong", _eExpMgrIOReadLong),
    MAKEFUNC( "ExpMgrIOReadWord", _eExpMgrIOReadWord),
    MAKEFUNC( "ExpMgrIOReadByte", _eExpMgrIOReadByte),
    MAKEFUNC( "ExpMgrIOWriteLong", _eExpMgrIOWriteLong),
    MAKEFUNC( "ExpMgrIOWriteWord", _eExpMgrIOWriteWord),
    MAKEFUNC( "ExpMgrIOWriteByte", _eExpMgrIOWriteByte),

    MAKEFUNC( "EndianSwap16Bit", _eEndianSwap16Bit),
    MAKEFUNC( "EndianSwap32Bit", _eEndianSwap32Bit)
};

static FunctionEntry VideoServicesLibFuncs[] =
{
    MAKEFUNC( "VSLPrepareCursorForHardwareCursor",
		IONDRVFramebuffer::VSLPrepareCursorForHardwareCursor),
    MAKEFUNC( "VSLNewInterruptService", IONDRVFramebuffer::VSLNewInterruptService),
    MAKEFUNC( "VSLDisposeInterruptService", IONDRVFramebuffer::VSLDisposeInterruptService),
    MAKEFUNC( "VSLDoInterruptService", IONDRVFramebuffer::VSLDoInterruptService),
    MAKEFUNC( "VSLSetDisplayConfiguration", _eVSLSetDisplayConfiguration)
};

static FunctionEntry NameRegistryLibFuncs[] =
{
    MAKEFUNC( "RegistryEntryIDCopy", _eRegistryEntryIDCopy),
    MAKEFUNC( "RegistryEntryIDInit", _eRegistryEntryIDInit),
    MAKEFUNC( "RegistryEntryIDDispose", _eNoErr),
    MAKEFUNC( "RegistryEntryIDCompare", _eRegistryEntryIDCompare),
    MAKEFUNC( "RegistryPropertyGetSize", _eRegistryPropertyGetSize),
    MAKEFUNC( "RegistryPropertyGet", _eRegistryPropertyGet),
    MAKEFUNC( "RegistryPropertyGetMod", _eRegistryPropertyGetMod),
    MAKEFUNC( "RegistryPropertySetMod", _eRegistryPropertySetMod),

    MAKEFUNC( "RegistryPropertyIterateCreate", _eRegistryPropertyIterateCreate),
    MAKEFUNC( "RegistryPropertyIterateDispose", _eRegistryPropertyIterateDispose),
    MAKEFUNC( "RegistryPropertyIterate", _eRegistryPropertyIterate),

    MAKEFUNC( "RegistryEntryIterateCreate", _eRegistryEntryIterateCreate),
    MAKEFUNC( "RegistryEntryIterateDispose", _eRegistryEntryIterateDispose),
    MAKEFUNC( "RegistryEntryIterate", _eRegistryEntryIterate),
    MAKEFUNC( "RegistryCStrEntryToName", _eRegistryCStrEntryToName),
    MAKEFUNC( "RegistryCStrEntryLookup", _eRegistryCStrEntryLookup),

    MAKEFUNC( "RegistryCStrEntryCreate", _eRegistryCStrEntryCreate),
    MAKEFUNC( "RegistryEntryDelete", _eNoErr),

    MAKEFUNC( "RegistryPropertyCreate", _eRegistryPropertyCreate),
    MAKEFUNC( "RegistryPropertyDelete", _eRegistryPropertyDelete),
    MAKEFUNC( "RegistryPropertySet", _eRegistryPropertySet)
};


static FunctionEntry DriverServicesLibFuncs[] =
{
    MAKEFUNC( "SynchronizeIO", _eSynchronizeIO),
    MAKEFUNC( "SetProcessorCacheMode", _eSetProcessorCacheMode),
    MAKEFUNC( "BlockCopy", bcopy),
    MAKEFUNC( "BlockMove", bcopy),
    MAKEFUNC( "BlockMoveData", bcopy),
    MAKEFUNC( "CStrCopy", strcpy),
    MAKEFUNC( "CStrCmp", strcmp),
    MAKEFUNC( "CStrLen", strlen),
    MAKEFUNC( "CStrCat", strcat),
    MAKEFUNC( "CStrNCopy", strncpy),
    MAKEFUNC( "CStrNCmp", strncmp),
    MAKEFUNC( "CStrNCat", strncat),
    MAKEFUNC( "PStrCopy", _ePStrCopy),

    MAKEFUNC( "PoolAllocateResident", _ePoolAllocateResident),
    MAKEFUNC( "MemAllocatePhysicallyContiguous", _ePoolAllocateResident),
    MAKEFUNC( "PoolDeallocate", _ePoolDeallocate),

    MAKEFUNC( "UpTime", _eUpTime),
    MAKEFUNC( "AbsoluteDeltaToDuration", _eAbsoluteDeltaToDuration),
    MAKEFUNC( "AddAbsoluteToAbsolute", _eAddAbsoluteToAbsolute),
    MAKEFUNC( "SubAbsoluteFromAbsolute", _eSubAbsoluteFromAbsolute),
    MAKEFUNC( "AddDurationToAbsolute", _eAddDurationToAbsolute),
    MAKEFUNC( "NanosecondsToAbsolute", _eNanosecondsToAbsolute),
    MAKEFUNC( "AbsoluteToNanoseconds", _eAbsoluteToNanoseconds),
    MAKEFUNC( "DurationToAbsolute", _eDurationToAbsolute),
    MAKEFUNC( "DelayForHardware", _eDelayForHardware),
    MAKEFUNC( "DelayFor", _eDelayFor),

    MAKEFUNC( "CurrentExecutionLevel", _eCurrentExecutionLevel),
    MAKEFUNC( "IOCommandIsComplete", _eIOCommandIsComplete),

    MAKEFUNC( "SysDebugStr", _eNoErr),
    MAKEFUNC( "SysDebug", _eNoErr),

    MAKEFUNC( "CompareAndSwap", OSCompareAndSwap),

    MAKEFUNC( "CreateInterruptSet", _eCreateInterruptSet),
    MAKEFUNC( "DeleteInterruptSet", _eDeleteInterruptSet),
    MAKEFUNC( "GetInterruptFunctions", _eGetInterruptFunctions),
    MAKEFUNC( "InstallInterruptFunctions", _eInstallInterruptFunctions)

};

static FunctionEntry ATIUtilsFuncs[] =
{
    // Gossamer onboard ATI
    MAKEFUNC( "ATISetMBRES", _eATISetMBRES),
    MAKEFUNC( "ATISetMonitorTermination", _eATISetMonitorTermination),
    MAKEFUNC( "ATIIsAllInOne", _eATIIsAllInOne)
};

// These are all out of spec

static FunctionEntry InterfaceLibFuncs[] =
{
    // Apple control : XPRam and EgretDispatch
    MAKEFUNC( "CallUniversalProc", _eFail),
    MAKEFUNC( "CallOSTrapUniversalProc", _eCallOSTrapUniversalProc),

    // Apple chips65550
//    MAKEFUNC( "NewRoutineDescriptor", _eCallOSTrapUniversalProc),
//    MAKEFUNC( "DisposeRoutineDescriptor", _eNoErr),
//    MAKEFUNC( "InsTime", _eInsTime),
//    MAKEFUNC( "PrimeTime", _ePrimeTime),

    // Radius PrecisionColor 16
    MAKEFUNC( "CountADBs", _eNoErr),
    MAKEFUNC( "GetIndADB", _eGetIndADB),
    MAKEFUNC( "GetKeys", _eGetKeys)
};

static FunctionEntry PrivateInterfaceLibFuncs[] =
{
    // Apple chips65550
    MAKEFUNC( "LMGetPowerMgrVars", _eLMGetPowerMgrVars )
};

#define NUMLIBRARIES	7
const ItemCount IONumNDRVLibraries = NUMLIBRARIES;
LibraryEntry IONDRVLibraries[ NUMLIBRARIES ] =
{
    { "PCILib", sizeof(PCILibFuncs) / sizeof(FunctionEntry), PCILibFuncs },
    { "VideoServicesLib", sizeof(VideoServicesLibFuncs) / sizeof(FunctionEntry), VideoServicesLibFuncs },
    { "NameRegistryLib", sizeof(NameRegistryLibFuncs) / sizeof(FunctionEntry), NameRegistryLibFuncs },
    { "DriverServicesLib", sizeof(DriverServicesLibFuncs) / sizeof(FunctionEntry), DriverServicesLibFuncs },

    // G3
    { "ATIUtils", sizeof(ATIUtilsFuncs) / sizeof(FunctionEntry), ATIUtilsFuncs },

    // out of spec stuff
    { "InterfaceLib", sizeof(InterfaceLibFuncs) / sizeof(FunctionEntry), InterfaceLibFuncs },
    { "PrivateInterfaceLib", sizeof(PrivateInterfaceLibFuncs) / sizeof(FunctionEntry), PrivateInterfaceLibFuncs }
};

} /* extern "C" */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super OSObject

OSDefineMetaClassAndStructors(IONDRVInterruptSet, OSObject)

IONDRVInterruptSet * IONDRVInterruptSet::with(IOService * provider,
                                    IOOptionBits options, SInt32 count )
{
    IONDRVInterruptSet * set;

    set = new IONDRVInterruptSet;
    if( set && !set->init()) {
	set->release();
	set = 0;
    }

    if( set) {

	set->provider	= provider;
	set->options	= options;
	set->count	= count;

	count++;
	set->sources = IONew( IONDRVInterruptSource, count );
	assert( set->sources );
	bzero( set->sources, count * sizeof( IONDRVInterruptSource));
    }

    return( set );
}

void IONDRVInterruptSet::free()
{
    if( sources)
	IODelete( sources, IONDRVInterruptSource, count + 1 );

    super::free();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if NDRVLIBTEST

static void IONDRVLibrariesTest( IOService * provider )
{
    UInt64 nano;
    UnsignedWide nano2;
    AbsoluteTime abs1, abs2;

    nano = 1000ULL;
    abs1 = _eNanosecondsToAbsolute(UInt64ToUnsignedWide(&nano));
    IOLog("_eNanosecondsToAbsolute %08lx:%08lx\n", abs1.hi, abs1.lo);
    nano2 = _eAbsoluteToNanoseconds(abs1);
    IOLog("_eAbsoluteToNanoseconds %08lx:%08lx\n", nano2.hi, nano2.lo);
    AbsoluteTime_to_scalar(&abs2) = 0;
    IOLog("_eAbsoluteDeltaToDuration %ld\n", _eAbsoluteDeltaToDuration(abs1,abs2));

    nano = 0x13161b000ULL;
    abs1 = _eNanosecondsToAbsolute(UInt64ToUnsignedWide(&nano));
    IOLog("_eNanosecondsToAbsolute %08lx:%08lx\n", abs1.hi, abs1.lo);
    nano2 = _eAbsoluteToNanoseconds(abs1);
    IOLog("_eAbsoluteToNanoseconds %08lx:%08lx\n", nano2.hi, nano2.lo);
    AbsoluteTime_to_scalar(&abs2) = 0;
    IOLog("_eAbsoluteDeltaToDuration %ld\n", _eAbsoluteDeltaToDuration(abs1,abs2));

    nano = 0x6acfc00000000ULL;
    abs1 = _eNanosecondsToAbsolute(UInt64ToUnsignedWide(&nano));
    IOLog("_eNanosecondsToAbsolute %08lx:%08lx\n", abs1.hi, abs1.lo);
    nano2 = _eAbsoluteToNanoseconds(abs1);
    IOLog("_eAbsoluteToNanoseconds %08lx:%08lx\n", nano2.hi, nano2.lo);
    AbsoluteTime_to_scalar(&abs2) = 0;
    IOLog("_eAbsoluteDeltaToDuration %ld\n", _eAbsoluteDeltaToDuration(abs1,abs2));

    abs1 = _eUpTime();
    IODelay(10);
    abs2 = _eUpTime();
    IOLog("10us duration %ld\n", _eAbsoluteDeltaToDuration(abs2,abs1));

    abs1 = _eUpTime();
    for( int i =0; i < 50000; i++)
        _eDelayFor(1);
    abs2 = _eUpTime();
    IOLog("50000 DelayFor(1) %ld\n", _eAbsoluteDeltaToDuration(abs2,abs1));

    abs1 = _eUpTime();
    _eDelayFor(50);
    abs2 = _eUpTime();
    IOLog("DelayFor(50) %ld\n", _eAbsoluteDeltaToDuration(abs2,abs1));

    abs1 = _eDurationToAbsolute( -10);
    IOLog("_eDurationToAbsolute(-10) %08lx:%08lx\n", abs1.hi, abs1.lo);
    abs1 = _eDurationToAbsolute( 10);
    IOLog("_eDurationToAbsolute(10) %08lx:%08lx\n", abs1.hi, abs1.lo);

}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IONDRVLibrariesInitialize( IOService * provider )
{
    IODTPlatformExpert *	platform;
    const OSSymbol *		sym;
    OSData *			data;
    OSArray *			intSpec;
    unsigned int		len, i;

#if NDRVLIBTEST
    IONDRVLibrariesTest( provider );
#endif

    // copy nvram property

    if( (platform = OSDynamicCast( IODTPlatformExpert,
            IOService::getPlatform()))) {

//	IOService::waitForService( IOService::resourceMatching( "IONVRAM" ));

        if( kIOReturnSuccess == platform->readNVRAMProperty( provider,
							&sym, &data )) {

            IONDRVSetNVRAMPropertyName( provider, sym );
            provider->setProperty( sym, data);
            data->release();
            sym->release();
        }
    }

    // create interrupt properties, if none present

    if( (intSpec = (OSArray *)provider->getProperty( gIOInterruptSpecifiersKey))
     && (0 == provider->getProperty( gIODTAAPLInterruptsKey ))) {
        // make AAPL,interrupts property if not present (NW)
        for( i = 0, len = 0; i < intSpec->getCount(); i++ ) {
            data = (OSData *) intSpec->getObject(i);
            assert( data );
            len += data->getLength();
        }
        if( len)
            data = OSData::withCapacity( len );
        if( data) {
            for( i = 0; i < intSpec->getCount(); i++ )
                data->appendBytes( (OSData *) intSpec->getObject(i));
            provider->setProperty( gIODTAAPLInterruptsKey, data );
            data->release();
        }
    }

    // make NDRV interrupts

    data = OSData::withCapacity( kIONDRVISTPropertyMemberCount
				 * sizeof( IONDRVInterruptSetMember));

    IONDRVInterruptSetMember 	setMember;
    IONDRVInterruptSet *	set;
    IONDRVInterruptSource *	source;

    set = IONDRVInterruptSet::with( provider, 0,
				kIONDRVISTPropertyMemberCount );

    if( set) for( i = 1; i <= kIONDRVISTPropertyMemberCount; i++ ) {

	source = set->sources + i;
	source->handler 	= &tvIONDRVStdInterruptHandler;
	source->enabler 	= &tvIONDRVStdInterruptEnabler;
	source->disabler 	= &tvIONDRVStdInterruptDisabler;

	setMember.setID 	= (void *) set;
	setMember.member	= i;
	data->appendBytes( &setMember, sizeof( setMember));

    } else
	data = 0;

    if( data) {
        provider->setProperty( kIONDRVISTPropertyName, data );
        data->release();
        data = 0;
    }

    // map memory

    IOItemCount 	numMaps = provider->getDeviceMemoryCount();
    IOVirtualAddress	virtAddress;

    for( i = 0; i < numMaps; i++) {
        IODeviceMemory * mem;
        IOMemoryMap *	 map;
        bool		 consoleDevice;

        consoleDevice = (0 != provider->getProperty("AAPL,boot-display"));

        mem = provider->getDeviceMemoryWithIndex( i );
        if( 0 == mem)
            continue;

        // set up a 1-1 mapping for the BAT map of the console device
        // remove this soon
        if( consoleDevice && (0 == mem->map( kIOMapReference)))
            mem->setMapping( kernel_task, mem->getPhysicalAddress() );

        map = mem->map();
        if( 0 == map) {
//		IOLog("%s: map[%ld] failed\n", provider->getName(), i);
            continue;
        }

        virtAddress = map->getVirtualAddress();
        if( !data)
            data = OSData::withCapacity( numMaps * sizeof( IOVirtualAddress));
        if( !data)
            continue;
        data->appendBytes( &virtAddress, sizeof( IOVirtualAddress));
        kprintf("ndrv base = %lx\n", virtAddress);
    }

    // NDRV aperture vectors
    if( data) {
        provider->setProperty( "AAPL,address", data );
        data->release();
    }

    return( kIOReturnSuccess );
}

