/*
 * Copyright (c) 1998-2006 Apple Inc. All rights reserved.
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
 * Copyright (c) 1998 Apple Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

extern "C" {
#include <machine/machine_routines.h>
#include <libkern/kernel_mach_header.h>
#include <kern/host.h>
#include <security/mac_data.h>
};

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/c++/OSKext.h>
#include <libkern/OSKextLibPrivate.h>

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>
#include <IOKit/IOCatalogue.h>

#include <IOKit/IOLib.h>
#include <IOKit/assert.h>

#if PRAGMA_MARK
#pragma mark Internal Declarations
#endif
/*********************************************************************
*********************************************************************/

#define CATALOGTEST 0

IOCatalogue    * gIOCatalogue;
const OSSymbol * gIOClassKey;
const OSSymbol * gIOProbeScoreKey;
const OSSymbol * gIOModuleIdentifierKey;
IOLock         * gIOCatalogLock;

#if PRAGMA_MARK
#pragma mark Utility functions
#endif
/*********************************************************************
*********************************************************************/
static void
UniqueProperties(OSDictionary * dict)
{
    OSString * data;

    data = OSDynamicCast(OSString, dict->getObject(gIOClassKey));
    if (data) {
        const OSSymbol *classSymbol = OSSymbol::withString(data);

        dict->setObject( gIOClassKey, (OSSymbol *) classSymbol);
        classSymbol->release();
    }

    data = OSDynamicCast(OSString, dict->getObject(gIOMatchCategoryKey));
    if (data) {
        const OSSymbol *classSymbol = OSSymbol::withString(data);

        dict->setObject(gIOMatchCategoryKey, (OSSymbol *) classSymbol);
        classSymbol->release();
    }
    return;
}

/*********************************************************************
* Add a new personality to the set if it has a unique IOResourceMatchKey value.
* XXX -- svail: This should be optimized.
* esb - There doesn't seem like any reason to do this - it causes problems
* esb - when there are more than one loadable driver matching on the same provider class
*********************************************************************/
static void
AddNewImports(OSOrderedSet * set, OSDictionary * dict)
{
    set->setObject(dict);
}

#if PRAGMA_MARK
#pragma mark IOCatalogue class implementation
#endif
/*********************************************************************
*********************************************************************/

#define super OSObject
OSDefineMetaClassAndStructors(IOCatalogue, OSObject)

/*********************************************************************
*********************************************************************/
void IOCatalogue::initialize(void)
{
    OSArray              * array;
    OSString             * errorString;
    bool		   rc;

    extern const char * gIOKernelConfigTables;

    array = OSDynamicCast(OSArray, OSUnserialize(gIOKernelConfigTables, &errorString));
    if (!array && errorString) {
        IOLog("KernelConfigTables syntax error: %s\n",
            errorString->getCStringNoCopy());
        errorString->release();
    }

    gIOClassKey              = OSSymbol::withCStringNoCopy( kIOClassKey );
    gIOProbeScoreKey 	     = OSSymbol::withCStringNoCopy( kIOProbeScoreKey );
    gIOModuleIdentifierKey   = OSSymbol::withCStringNoCopy( kCFBundleIdentifierKey );

    assert( array && gIOClassKey && gIOProbeScoreKey 
	    && gIOModuleIdentifierKey);

    gIOCatalogue = new IOCatalogue;
    assert(gIOCatalogue);
    rc = gIOCatalogue->init(array);
    assert(rc);
    array->release();
}

/*********************************************************************
* Initialize the IOCatalog object.
*********************************************************************/
bool IOCatalogue::init(OSArray * initArray)
{
    OSDictionary         * dict;
    
    if ( !super::init() )
        return false;

    generation = 1;
    
    array = initArray;
    array->retain();
    kernelTables = OSCollectionIterator::withCollection( array );

    gIOCatalogLock = IOLockAlloc();

    lock     = gIOCatalogLock;
#if __ppc__ || __i386__
    kld_lock = NULL;
#endif /* __ppc__ || __i386__ */

    kernelTables->reset();
    while( (dict = (OSDictionary *) kernelTables->getNextObject())) {
        UniqueProperties(dict);
        if( 0 == dict->getObject( gIOClassKey ))
            IOLog("Missing or bad \"%s\" key\n",
                    gIOClassKey->getCStringNoCopy());
    }

#if CATALOGTEST
    AbsoluteTime deadline;
    clock_interval_to_deadline( 1000, kMillisecondScale );
    thread_call_func_delayed( ping, this, deadline );
#endif

    return true;
}

/*********************************************************************
* Release all resources used by IOCatalogue and deallocate.
* This will probably never be called.
*********************************************************************/
void IOCatalogue::free( void )
{
    if ( array )
        array->release();

    if ( kernelTables )
        kernelTables->release();
    
    super::free();
}

/*********************************************************************
*********************************************************************/
#if CATALOGTEST

static int hackLimit;
enum { kDriversPerIter = 4 };

void
IOCatalogue::ping(thread_call_param_t arg, thread_call_param_t)
{
    IOCatalogue 	 * self = (IOCatalogue *) arg;
    OSOrderedSet         * set;
    OSDictionary         * table;
    int	                   newLimit;

    set = OSOrderedSet::withCapacity( 1 );

    IOLockLock( &self->lock );

    for( newLimit = 0; newLimit < kDriversPerIter; newLimit++) {
	table = (OSDictionary *) self->array->getObject(
					hackLimit + newLimit );
	if( table) {
	    set->setLastObject( table );

	    OSSymbol * sym = (OSSymbol *) table->getObject(gIOClassKey);
	    kprintf("enabling %s\n", sym->getCStringNoCopy());

	} else {
	    newLimit--;
	    break;
	}
    }

    IOService::catalogNewDrivers( set );

    hackLimit += newLimit;
    self->generation++;

    IOLockUnlock( &self->lock );

    if( kDriversPerIter == newLimit) {
        AbsoluteTime deadline;
        clock_interval_to_deadline(500, kMillisecondScale);
        thread_call_func_delayed(ping, this, deadline);
    }
}
#endif

/*********************************************************************
*********************************************************************/
OSOrderedSet *
IOCatalogue::findDrivers(
    IOService * service,
    SInt32 * generationCount)
{
    OSDictionary         * nextTable;
    OSOrderedSet         * set;
    OSString             * imports;

    set = OSOrderedSet::withCapacity( 1, IOServiceOrdering,
                                      (void *)gIOProbeScoreKey );
    if( !set )
	return( 0 );

    IOLockLock(lock);
    kernelTables->reset();

#if CATALOGTEST
    int hackIndex = 0;
#endif
    while( (nextTable = (OSDictionary *) kernelTables->getNextObject())) {
#if CATALOGTEST
	if( hackIndex++ > hackLimit)
	    break;
#endif
        imports = OSDynamicCast( OSString,
			nextTable->getObject( gIOProviderClassKey ));
	if( imports && service->metaCast( imports ))
            set->setObject( nextTable );
    }

    *generationCount = getGenerationCount();

    IOLockUnlock(lock);

    return( set );
}

/*********************************************************************
* Is personality already in the catalog?
*********************************************************************/
OSOrderedSet *
IOCatalogue::findDrivers(
    OSDictionary * matching,
    SInt32 * generationCount)
{
    OSDictionary         * dict;
    OSOrderedSet         * set;

    UniqueProperties(matching);

    set = OSOrderedSet::withCapacity( 1, IOServiceOrdering,
                                      (void *)gIOProbeScoreKey );

    IOLockLock(lock);
    kernelTables->reset();
    while ( (dict = (OSDictionary *) kernelTables->getNextObject()) ) {

       /* This comparison must be done with only the keys in the
        * "matching" dict to enable general searches.
        */
        if ( dict->isEqualTo(matching, matching) )
            set->setObject(dict);
    }
    *generationCount = getGenerationCount();
    IOLockUnlock(lock);

    return set;
}

/*********************************************************************
* Add driver config tables to catalog and start matching process.
*
* Important that existing personalities are kept (not replaced)
* if duplicates found. Personalities can come from OSKext objects
* or from userland kext library. We want to minimize distinct
* copies between OSKext & IOCatalogue.
*
* xxx - userlib used to refuse to send personalities with IOKitDebug
* xxx - during safe boot. That would be better implemented here.
*********************************************************************/
bool IOCatalogue::addDrivers(
    OSArray * drivers,
    bool doNubMatching)
{
    bool                   result = false;
    OSCollectionIterator * iter = NULL;       // must release
    OSOrderedSet         * set = NULL;        // must release
    OSDictionary         * dict = NULL;       // do not release
    OSArray              * persons = NULL;    // do not release

    persons = OSDynamicCast(OSArray, drivers);
    if (!persons) {
        goto finish;
    }
    
    set = OSOrderedSet::withCapacity( 10, IOServiceOrdering,
        (void *)gIOProbeScoreKey );
    if (!set) {
        goto finish;
    }

    iter = OSCollectionIterator::withCollection(persons);
    if (!iter) {
        goto finish;
    }

    result = true;

    IOLockLock(lock);
    while ( (dict = (OSDictionary *) iter->getNextObject()) ) {
    
        // xxx Deleted OSBundleModuleDemand check; will handle in other ways for SL

        SInt count;
        
        UniqueProperties(dict);
        
        // Add driver personality to catalogue.
        count = array->getCount();
        while (count--) {
            OSDictionary * driver;
            
            // Be sure not to double up on personalities.
            driver = (OSDictionary *)array->getObject(count);
            
           /* Unlike in other functions, this comparison must be exact!
            * The catalogue must be able to contain personalities that
            * are proper supersets of others.
            * Do not compare just the properties present in one driver
            * pesonality or the other.
            */
            if (dict->isEqualTo(driver)) {
                break;
            }
        }
        if (count >= 0) {
            // its a dup
            continue;
        }
        
        result = array->setObject(dict);
        if (!result) {
            break;
        }
        
        AddNewImports(set, dict);
    }
    // Start device matching.
    if (doNubMatching && (set->getCount() > 0)) {
        IOService::catalogNewDrivers(set);
        generation++;
    }
    IOLockUnlock(lock);

finish:
    if (set)  set->release();
    if (iter) iter->release();

    return result;
}

/*********************************************************************
* Remove drivers from the catalog which match the
* properties in the matching dictionary.
*********************************************************************/
bool
IOCatalogue::removeDrivers(
    OSDictionary * matching,
    bool doNubMatching)
{
    OSCollectionIterator * tables;
    OSDictionary         * dict;
    OSOrderedSet         * set;
    OSArray              * arrayCopy;

    if ( !matching )
        return false;

    set = OSOrderedSet::withCapacity(10,
                                     IOServiceOrdering,
                                     (void *)gIOProbeScoreKey);
    if ( !set )
        return false;

    arrayCopy = OSArray::withCapacity(100);
    if ( !arrayCopy ) {
        set->release();
        return false;
    }
    
    tables = OSCollectionIterator::withCollection(arrayCopy);
    arrayCopy->release();
    if ( !tables ) {
        set->release();
        return false;
    }

    UniqueProperties( matching );

    IOLockLock(lock);
    kernelTables->reset();
    arrayCopy->merge(array);
    array->flushCollection();
    tables->reset();
    while ( (dict = (OSDictionary *)tables->getNextObject()) ) {

       /* This comparison must be done with only the keys in the
        * "matching" dict to enable general searches.
        */
        if ( dict->isEqualTo(matching, matching) ) {
            AddNewImports( set, dict );
            continue;
        }

        array->setObject(dict);
    }
    // Start device matching.
    if ( doNubMatching && (set->getCount() > 0) ) {
        IOService::catalogNewDrivers(set);
        generation++;
    }
    IOLockUnlock(lock);
    
    set->release();
    tables->release();
    
    return true;
}

// Return the generation count.
SInt32 IOCatalogue::getGenerationCount(void) const
{
    return( generation );
}

bool IOCatalogue::isModuleLoaded(OSString * moduleName) const
{
    return isModuleLoaded(moduleName->getCStringNoCopy());
}

bool IOCatalogue::isModuleLoaded(const char * moduleName) const
{
    OSReturn ret;
    ret = OSKext::loadKextWithIdentifier(moduleName);
    if (kOSKextReturnDeferred == ret) {
        // a request has been queued but the module isn't necessarily 
        // loaded yet, so stall.
        return false;
    }
    // module is present or never will be 
    return true;
}

// Check to see if module has been loaded already.
bool IOCatalogue::isModuleLoaded(OSDictionary * driver) const
{
    OSString             * moduleName = NULL;
    OSString             * publisherName = NULL;

    if ( !driver )
        return false;

    /* The personalities of codeless kexts often contain the bundle ID of the
     * kext they reference, and not the bundle ID of the codeless kext itself.
     * The prelinked kernel needs to know the bundle ID of the codeless kext
     * so it can include these personalities, so OSKext stores that bundle ID
     * in the IOPersonalityPublisher key, and we record it as requested here.
     */
    publisherName = OSDynamicCast(OSString, 
        driver->getObject(kIOPersonalityPublisherKey));
    OSKext::recordIdentifierRequest(publisherName);

    moduleName = OSDynamicCast(OSString, driver->getObject(gIOModuleIdentifierKey));
    if ( moduleName )
        return isModuleLoaded(moduleName);

   /* If a personality doesn't hold the "CFBundleIdentifier" key
    * it is assumed to be an "in-kernel" driver.
    */
    return true;
}

/* This function is called after a module has been loaded.
 * Is invoked from user client call, ultimately from IOKitLib's
 * IOCatalogueModuleLoaded(). Sent from kextd.
 */
void IOCatalogue::moduleHasLoaded(OSString * moduleName)
{
    OSDictionary * dict;

    dict = OSDictionary::withCapacity(2);
    dict->setObject(gIOModuleIdentifierKey, moduleName);
    startMatching(dict);
    dict->release();

    (void) OSKext::setDeferredLoadSucceeded();
    (void) OSKext::considerRebuildOfPrelinkedKernel();
}

void IOCatalogue::moduleHasLoaded(const char * moduleName)
{
    OSString * name;

    name = OSString::withCString(moduleName);
    moduleHasLoaded(name);
    name->release();
}

// xxx - return is really OSReturn/kern_return_t
IOReturn IOCatalogue::unloadModule(OSString * moduleName) const
{
    return OSKext::removeKextWithIdentifier(moduleName->getCStringNoCopy());
}

static IOReturn _terminateDrivers(OSDictionary * matching)
{
    OSDictionary         * dict;
    OSIterator           * iter;
    IOService            * service;
    IOReturn               ret;

    if ( !matching )
        return kIOReturnBadArgument;

    ret = kIOReturnSuccess;
    dict = 0;
    iter = IORegistryIterator::iterateOver(gIOServicePlane,
                                kIORegistryIterateRecursively);
    if ( !iter )
        return kIOReturnNoMemory;

    UniqueProperties( matching );

    // terminate instances.
    do {
        iter->reset();
        while( (service = (IOService *)iter->getNextObject()) ) {
            dict = service->getPropertyTable();
            if ( !dict )
                continue;

           /* Terminate only for personalities that match the matching dictionary.
            * This comparison must be done with only the keys in the
            * "matching" dict to enable general matching.
            */
            if ( !dict->isEqualTo(matching, matching) )
                 continue;

            if ( !service->terminate(kIOServiceRequired|kIOServiceSynchronous) ) {
                ret = kIOReturnUnsupported;
                break;
            }
        }
    } while( !service && !iter->isValid());
    iter->release();

    return ret;
}

static IOReturn _removeDrivers( OSArray * array, OSDictionary * matching )
{
    OSCollectionIterator * tables;
    OSDictionary         * dict;
    OSArray              * arrayCopy;
    IOReturn               ret = kIOReturnSuccess;

    // remove configs from catalog.

    arrayCopy = OSArray::withCapacity(100);
    if ( !arrayCopy )
        return kIOReturnNoMemory;

    tables = OSCollectionIterator::withCollection(arrayCopy);
    arrayCopy->release();
    if ( !tables )
        return kIOReturnNoMemory;

    arrayCopy->merge(array);
    array->flushCollection();
    tables->reset();
    while ( (dict = (OSDictionary *)tables->getNextObject()) ) {

       /* Remove from the catalogue's array any personalities
        * that match the matching dictionary.
        * This comparison must be done with only the keys in the
        * "matching" dict to enable general matching.
        */
        if ( dict->isEqualTo(matching, matching) )
            continue;

        array->setObject(dict);
    }

    tables->release();

    return ret;
}

bool IOCatalogue::removePersonalities(OSArray * personalitiesToRemove)
{
    bool                   result           = true;
    OSArray              * arrayCopy        = NULL;  // do not release
    OSCollectionIterator * iterator         = NULL;  // must release
    OSDictionary         * personality      = NULL;  // do not release
    OSDictionary         * checkPersonality = NULL;  // do not release
    unsigned int           count, i;

    // remove configs from catalog.

    arrayCopy = OSArray::withArray(array);
    if (!arrayCopy) {
        result = false;
        goto finish;
    }

    iterator = OSCollectionIterator::withCollection(arrayCopy);
    arrayCopy->release();
    if (!iterator) {
        result = false;
        goto finish;
    }

    array->flushCollection();

    count = personalitiesToRemove->getCount();

   /* Go through the old catalog's list of personalities and add back any that
    * are *not* found in 'personalitiesToRemove'.
    */
    while ((personality = (OSDictionary *)iterator->getNextObject())) {
        bool found = false;

        for (i = 0; i < count; i++) {
            checkPersonality = OSDynamicCast(OSDictionary,
                personalitiesToRemove->getObject(i));

           /* Do isEqualTo() with the single-arg version to make an exact
            * comparison (unlike _removeDrivers() above).
            */
            if (personality->isEqualTo(checkPersonality)) {
                found = true;
                break;
            }
        }

        if (!found) {
            array->setObject(personality);
        }
    }

finish:

    OSSafeRelease(iterator);
    return result;
}

IOReturn IOCatalogue::terminateDrivers(OSDictionary * matching)
{
    IOReturn ret;

    ret = _terminateDrivers(matching);
    IOLockLock(lock);
    if (kIOReturnSuccess == ret)
	ret = _removeDrivers(array, matching);
    kernelTables->reset();
    IOLockUnlock(lock);

    return ret;
}

IOReturn IOCatalogue::terminateDriversForModule(
    OSString * moduleName,
    bool unload)
{
    IOReturn ret;
    OSDictionary * dict;
    bool isLoaded = false;

   /* Check first if the kext currently has any linkage dependents;
    * in such a case the unload would fail so let's not terminate any
    * IOServices (since doing so typically results in a panic when there
    * are loaded dependencies). Note that we aren't locking the kext here
    * so it might lose or gain dependents by the time we call unloadModule();
    * I think that's ok, our unload can fail if a kext comes in on top of
    * this one even after we've torn down IOService objects. Conversely,
    * if we fail the unload here and then lose a library, the autounload
    * thread will get us in short order.
    */
    if (OSKext::isKextWithIdentifierLoaded(moduleName->getCStringNoCopy())) {
    
        isLoaded = true;

        if (!OSKext::canUnloadKextWithIdentifier(moduleName,
            /* checkClasses */ false)) {
            ret = kOSKextReturnInUse;
            goto finish;
        }
    }
    dict = OSDictionary::withCapacity(1);
    if (!dict) {
        ret = kIOReturnNoMemory;
        goto finish;
    }

    dict->setObject(gIOModuleIdentifierKey, moduleName);

    ret = _terminateDrivers(dict);
    
   /* No goto between IOLock calls!
    */
    IOLockLock(lock);
    if (kIOReturnSuccess == ret) {
        ret = _removeDrivers(array, dict);
    }
    kernelTables->reset();

    // Unload the module itself.
    if (unload && isLoaded && ret == kIOReturnSuccess) {
        ret = unloadModule(moduleName);
    }

    IOLockUnlock(lock);

    dict->release();

finish:
    return ret;
}

IOReturn IOCatalogue::terminateDriversForModule(
    const char * moduleName,
    bool unload)
{
    OSString * name;
    IOReturn ret;

    name = OSString::withCString(moduleName);
    if ( !name )
        return kIOReturnNoMemory;

    ret = terminateDriversForModule(name, unload);
    name->release();

    return ret;
}

bool IOCatalogue::startMatching( OSDictionary * matching )
{
    OSDictionary         * dict;
    OSOrderedSet         * set;
    
    if ( !matching )
        return false;

    set = OSOrderedSet::withCapacity(10, IOServiceOrdering,
                                     (void *)gIOProbeScoreKey);
    if ( !set )
        return false;

    IOLockLock(lock);
    kernelTables->reset();

    while ( (dict = (OSDictionary *)kernelTables->getNextObject()) ) {

       /* This comparison must be done with only the keys in the
        * "matching" dict to enable general matching.
        */
        if ( dict->isEqualTo(matching, matching) )
            AddNewImports(set, dict);
    }
    // Start device matching.
    if ( set->getCount() > 0 ) {
        IOService::catalogNewDrivers(set);
        generation++;
    }

    IOLockUnlock(lock);

    set->release();

    return true;
}

void IOCatalogue::reset(void)
{
    IOLog("Resetting IOCatalogue.\n");
}

bool IOCatalogue::serialize(OSSerialize * s) const
{
    if ( !s )
        return false;

    return super::serialize(s);
}

bool IOCatalogue::serializeData(IOOptionBits kind, OSSerialize * s) const
{
    kern_return_t kr = kIOReturnSuccess;

    switch ( kind )
    {
        case kIOCatalogGetContents:
            if (!array->serialize(s))
                kr = kIOReturnNoMemory;
            break;

        case kIOCatalogGetModuleDemandList:
            kr = KERN_NOT_SUPPORTED;
            break;

        case kIOCatalogGetCacheMissList:
            kr = KERN_NOT_SUPPORTED;
            break;

        case kIOCatalogGetROMMkextList:
            kr = KERN_NOT_SUPPORTED;
            break;

        default:
            kr = kIOReturnBadArgument;
            break;
    }

    return kr;
}


#if PRAGMA_MARK
#pragma mark Obsolete Kext Loading Stuff
#endif
/*********************************************************************
**********************************************************************
***                  BINARY COMPATIBILITY SECTION                  ***
**********************************************************************
**********************************************************************
* These functions are no longer used are necessary for C++ binary
* compatibility on ppc/i386.
**********************************************************************/
#if __ppc__ || __i386__

bool IOCatalogue::recordStartupExtensions(void)
{  return false;  }

bool IOCatalogue::addExtensionsFromArchive(OSData * mkext)
{  return KERN_NOT_SUPPORTED;  }

kern_return_t IOCatalogue::removeKernelLinker(void)
{  return KERN_NOT_SUPPORTED;  }

#endif /* __ppc__ || __i386__ */
