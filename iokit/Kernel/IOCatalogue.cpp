/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IOCatalogue.h>
#include <libkern/c++/OSUnserialize.h>
extern "C" {
#include <machine/machine_routines.h>
#include <mach/kmod.h>
#include <mach-o/mach_header.h>
#include <kern/host.h>
};

#include <IOKit/IOLib.h>

#include <IOKit/assert.h>


extern "C" {
int IODTGetLoaderInfo( char *key, void **infoAddr, int *infoSize );
extern void IODTFreeLoaderInfo( char *key, void *infoAddr, int infoSize );
extern void OSRuntimeUnloadCPPForSegment(
    struct segment_command * segment);
};


/*****
 * At startup these function pointers are set to use the libsa in-kernel
 * linker for recording and loading kmods. Once the root filesystem
 * is available, the kmod_load_function pointer gets switched to point
 * at the kmod_load_extension() function built into the kernel, and the
 * others are set to zero. Those two functions must *always* be checked
 * before being invoked.
 */
extern "C" {
kern_return_t (*kmod_load_function)(char *extension_name) =
    &kmod_load_extension;
bool (*record_startup_extensions_function)(void) = 0;
bool (*add_from_mkext_function)(OSData * mkext) = 0;
void (*remove_startup_extension_function)(const char * name) = 0;
};


/*****
 * A few parts of IOCatalogue require knowledge of
 * whether the in-kernel linker is present. This
 * variable is set by libsa's bootstrap code.
 */
int kernelLinkerPresent = 0;


#define super OSObject
#define kModuleKey "CFBundleIdentifier"

OSDefineMetaClassAndStructors(IOCatalogue, OSObject)

#define CATALOGTEST 0

IOCatalogue                   * gIOCatalogue;
const OSSymbol                * gIOClassKey;
const OSSymbol                * gIOProbeScoreKey;

static void UniqueProperties( OSDictionary * dict )
{
    OSString             * data;

    data = OSDynamicCast( OSString, dict->getObject( gIOClassKey ));
    if( data) {
        const OSSymbol *classSymbol = OSSymbol::withString(data);

        dict->setObject( gIOClassKey, (OSSymbol *) classSymbol);
        classSymbol->release();
    }

    data = OSDynamicCast( OSString, dict->getObject( gIOMatchCategoryKey ));
    if( data) {
        const OSSymbol *classSymbol = OSSymbol::withString(data);

        dict->setObject( gIOMatchCategoryKey, (OSSymbol *) classSymbol);
        classSymbol->release();
    }
}

void IOCatalogue::initialize( void )
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

    gIOClassKey = OSSymbol::withCStringNoCopy( kIOClassKey );
    gIOProbeScoreKey = OSSymbol::withCStringNoCopy( kIOProbeScoreKey );
    assert( array && gIOClassKey && gIOProbeScoreKey);

    gIOCatalogue = new IOCatalogue;
    assert(gIOCatalogue);
    rc = gIOCatalogue->init(array);
    assert(rc);
    array->release();
}

// Initialize the IOCatalog object.
bool IOCatalogue::init(OSArray * initArray)
{
    IORegistryEntry      * entry;
    OSDictionary         * dict;
    
    if ( !super::init() )
        return false;

    generation = 1;
    
    array = initArray;
    array->retain();
    kernelTables = OSCollectionIterator::withCollection( array );

    lock = IOLockAlloc();
    kld_lock = IOLockAlloc();

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

    entry = IORegistryEntry::getRegistryRoot();
    if ( entry )
        entry->setProperty(kIOCatalogueKey, this);

    return true;
}

// Release all resources used by IOCatalogue and deallocate.
// This will probably never be called.
void IOCatalogue::free( void )
{
    if ( array )
        array->release();

    if ( kernelTables )
        kernelTables->release();
    
    super::free();
}

#if CATALOGTEST

static int hackLimit;

enum { kDriversPerIter = 4 };

void IOCatalogue::ping( thread_call_param_t arg, thread_call_param_t)
{
    IOCatalogue 	 * self = (IOCatalogue *) arg;
    OSOrderedSet         * set;
    OSDictionary         * table;
    int	                   newLimit;

    set = OSOrderedSet::withCapacity( 1 );

    IOTakeLock( &self->lock );

    for( newLimit = 0; newLimit < kDriversPerIter; newLimit++) {
	table = (OSDictionary *) self->array->getObject(
					hackLimit + newLimit );
	if( table) {
	    set->setLastObject( table );

	    OSSymbol * sym = (OSSymbol *) table->getObject( gIOClassKey );
	    kprintf("enabling %s\n", sym->getCStringNoCopy());

	} else {
	    newLimit--;
	    break;
	}
    }

    IOService::catalogNewDrivers( set );

    hackLimit += newLimit;
    self->generation++;

    IOUnlock( &self->lock );

    if( kDriversPerIter == newLimit) {
        AbsoluteTime deadline;
        clock_interval_to_deadline( 500, kMillisecondScale );
        thread_call_func_delayed( ping, this, deadline );
    }
}
#endif

OSOrderedSet * IOCatalogue::findDrivers( IOService * service,
					SInt32 * generationCount )
{
    OSDictionary         * nextTable;
    OSOrderedSet         * set;
    OSString             * imports;

    set = OSOrderedSet::withCapacity( 1, IOServiceOrdering,
                                      (void *)gIOProbeScoreKey );
    if( !set )
	return( 0 );

    IOTakeLock( lock );
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

    IOUnlock( lock );

    return( set );
}

// Is personality already in the catalog?
OSOrderedSet * IOCatalogue::findDrivers( OSDictionary * matching,
                                         SInt32 * generationCount)
{
    OSDictionary         * dict;
    OSOrderedSet         * set;

    UniqueProperties(matching);

    set = OSOrderedSet::withCapacity( 1, IOServiceOrdering,
                                      (void *)gIOProbeScoreKey );

    IOTakeLock( lock );
    kernelTables->reset();
    while ( (dict = (OSDictionary *) kernelTables->getNextObject()) ) {

       /* This comparison must be done with only the keys in the
        * "matching" dict to enable general searches.
        */
        if ( dict->isEqualTo(matching, matching) )
            set->setObject(dict);
    }
    *generationCount = getGenerationCount();
    IOUnlock( lock );

    return set;
}

// Add a new personality to the set if it has a unique IOResourceMatchKey value.
// XXX -- svail: This should be optimized.
// esb - There doesn't seem like any reason to do this - it causes problems
// esb - when there are more than one loadable driver matching on the same provider class
static void AddNewImports( OSOrderedSet * set, OSDictionary * dict )
{
    set->setObject(dict);
}

// Add driver config tables to catalog and start matching process.
bool IOCatalogue::addDrivers(OSArray * drivers,
                              bool doNubMatching = true )
{
    OSCollectionIterator * iter;
    OSDictionary         * dict;
    OSOrderedSet         * set;
    OSArray              * persons;
    bool                   ret;

    ret = true;
    persons = OSDynamicCast(OSArray, drivers);
    if ( !persons )
        return false;

    iter = OSCollectionIterator::withCollection( persons );
    if (!iter )
        return false;
    
    set = OSOrderedSet::withCapacity( 10, IOServiceOrdering,
                                      (void *)gIOProbeScoreKey );
    if ( !set ) {
        iter->release();
        return false;
    }

    IOTakeLock( lock );
    while ( (dict = (OSDictionary *) iter->getNextObject()) ) {
        UInt count;
        
        UniqueProperties( dict );

        // Add driver personality to catalogue.
        count = array->getCount();
        while ( count-- ) {
            OSDictionary         * driver;

            // Be sure not to double up on personalities.
            driver = (OSDictionary *)array->getObject(count);

           /* Unlike in other functions, this comparison must be exact!
            * The catalogue must be able to contain personalities that
            * are proper supersets of others.
            * Do not compare just the properties present in one driver
            * pesonality or the other.
            */
            if ( dict->isEqualTo(driver) ) {
                array->removeObject(count);
                break;
            }
        }
        
        ret = array->setObject( dict );
        if ( !ret )
            break;

        AddNewImports( set, dict );
    }
    // Start device matching.
    if ( doNubMatching && (set->getCount() > 0) ) {
        IOService::catalogNewDrivers( set );
        generation++;
    }
    IOUnlock( lock );

    set->release();
    iter->release();
    
    return ret;
}

// Remove drivers from the catalog which match the
// properties in the matching dictionary.
bool IOCatalogue::removeDrivers( OSDictionary * matching,
                                 bool doNubMatching = true)
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

    IOTakeLock( lock );
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
    IOUnlock( lock );
    
    set->release();
    tables->release();
    
    return true;
}

// Return the generation count.
SInt32 IOCatalogue::getGenerationCount( void ) const
{
    return( generation );
}

bool IOCatalogue::isModuleLoaded( OSString * moduleName ) const
{
    return isModuleLoaded(moduleName->getCStringNoCopy());
}

bool IOCatalogue::isModuleLoaded( const char * moduleName ) const
{
    kmod_info_t          * k_info;

    if ( !moduleName )
        return false;

    // Is the module already loaded?
    k_info = kmod_lookupbyname_locked((char *)moduleName);
    if ( !k_info ) {
        kern_return_t            ret;

       /* To make sure this operation completes even if a bad extension needs
        * to be removed, take the kld lock for this whole block, spanning the
        * kmod_load_function() and remove_startup_extension_function() calls.
        */
        IOLockLock(kld_lock);

        // If the module hasn't been loaded, then load it.
        if (kmod_load_function != 0) {

            ret = kmod_load_function((char *)moduleName);

            if  ( ret != kIOReturnSuccess ) {
                IOLog("IOCatalogue: %s cannot be loaded.\n", moduleName);

               /* If the extension couldn't be loaded this time,
                * make it unavailable so that no more requests are
                * made in vain. This also enables other matching
                * extensions to have a chance.
                */
                if (kernelLinkerPresent && remove_startup_extension_function) {
                    (*remove_startup_extension_function)(moduleName);
                }
                IOLockUnlock(kld_lock);
                return false;
            } else if (kernelLinkerPresent) {
                // If kern linker is here, the driver is actually loaded,
                // so return true.
                IOLockUnlock(kld_lock);
                return true;
            } else {
                // kern linker isn't here, a request has been queued
                // but the module isn't necessarily loaded yet, so stall.
                IOLockUnlock(kld_lock);
                return false;
            }
        } else {
            IOLog("IOCatalogue: %s cannot be loaded "
                "(kmod load function not set).\n",
                moduleName);
        }

        IOLockUnlock(kld_lock);
        return false;
    }

    if (k_info) {
        kfree(k_info, sizeof(kmod_info_t));
    }

    /* Lock wasn't taken if we get here. */
    return true;
}

// Check to see if module has been loaded already.
bool IOCatalogue::isModuleLoaded( OSDictionary * driver ) const
{
    OSString             * moduleName = NULL;

    if ( !driver )
        return false;

    moduleName = OSDynamicCast(OSString, driver->getObject(kModuleKey));
    if ( moduleName )
        return isModuleLoaded(moduleName);

   /* If a personality doesn't hold the "CFBundleIdentifier" key
    * it is assumed to be an "in-kernel" driver.
    */
    return true;
}

// This function is called after a module has been loaded.
void IOCatalogue::moduleHasLoaded( OSString * moduleName )
{
    OSDictionary         * dict;

    dict = OSDictionary::withCapacity(2);
    dict->setObject(kModuleKey, moduleName);
    startMatching(dict);
    dict->release();
}

void IOCatalogue::moduleHasLoaded( const char * moduleName )
{
    OSString             * name;

    name = OSString::withCString(moduleName);
    moduleHasLoaded(name);
    name->release();
}

IOReturn IOCatalogue::unloadModule( OSString * moduleName ) const
{
    kmod_info_t          * k_info = 0;
    kern_return_t          ret;
    const char           * name;

    ret = kIOReturnBadArgument;
    if ( moduleName ) {
        name = moduleName->getCStringNoCopy();
        k_info = kmod_lookupbyname_locked((char *)name);
        if ( k_info && (k_info->reference_count < 1) ) {
            if ( k_info->stop &&
                 !((ret = k_info->stop(k_info, 0)) == kIOReturnSuccess) ) {

                kfree(k_info, sizeof(kmod_info_t));
                return ret;
           }
            
           ret = kmod_destroy(host_priv_self(), k_info->id);
        }
    }
 
    if (k_info) {
        kfree(k_info, sizeof(kmod_info_t));
    }

    return ret;
}

static IOReturn _terminateDrivers( OSArray * array, OSDictionary * matching )
{
    OSCollectionIterator * tables;
    OSDictionary         * dict;
    OSIterator           * iter;
    OSArray              * arrayCopy;
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

    // remove configs from catalog.
    if ( ret != kIOReturnSuccess ) 
        return ret;

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

IOReturn IOCatalogue::terminateDrivers( OSDictionary * matching )
{
    IOReturn ret;

    ret = kIOReturnSuccess;
    IOTakeLock( lock );
    ret = _terminateDrivers(array, matching);
    kernelTables->reset();
    IOUnlock( lock );

    return ret;
}

IOReturn IOCatalogue::terminateDriversForModule(
                                      OSString * moduleName,
                                      bool unload )
{
    IOReturn ret;
    OSDictionary * dict;

    dict = OSDictionary::withCapacity(1);
    if ( !dict )
        return kIOReturnNoMemory;

    dict->setObject(kModuleKey, moduleName);

    IOTakeLock( lock );

    ret = _terminateDrivers(array, dict);
    kernelTables->reset();

    // Unload the module itself.
    if ( unload && ret == kIOReturnSuccess ) {
        // Do kmod stop first.
        ret = unloadModule(moduleName);
    }

    IOUnlock( lock );

    dict->release();

    return ret;
}

IOReturn IOCatalogue::terminateDriversForModule(
                                      const char * moduleName,
                                      bool unload )
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

    IOTakeLock( lock );
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

    IOUnlock( lock );

    set->release();

    return true;
}

void IOCatalogue::reset(void)
{
    OSArray              * tables;
    OSDictionary         * entry;
    unsigned int           count;

    IOLog("Resetting IOCatalogue.\n");
    
    IOTakeLock( lock );
    tables = OSArray::withArray(array);
    array->flushCollection();
    
    count = tables->getCount();
    while ( count-- ) {
        entry = (OSDictionary *)tables->getObject(count);
        if ( entry && !entry->getObject(kModuleKey) ) {
            array->setObject(entry);
        }
    }
    
    kernelTables->reset();
    IOUnlock( lock );
    
    tables->release();
}

bool IOCatalogue::serialize(OSSerialize * s) const
{
    bool                   ret;
    
    if ( !s )
        return false;

    IOTakeLock( lock );
    ret = array->serialize(s);
    IOUnlock( lock );

    return ret;
}


bool IOCatalogue::recordStartupExtensions(void) {
    bool result = false;

    IOLockLock(kld_lock);
    if (kernelLinkerPresent && record_startup_extensions_function) {
        result = (*record_startup_extensions_function)();
    } else {
        IOLog("Can't record startup extensions; "
            "kernel linker is not present.\n");
        result = false;
    }
    IOLockUnlock(kld_lock);

    return result;
}


/*********************************************************************
*********************************************************************/
bool IOCatalogue::addExtensionsFromArchive(OSData * mkext) {
    bool result = false;

    IOLockLock(kld_lock);
    if (kernelLinkerPresent && add_from_mkext_function) {
        result = (*add_from_mkext_function)(mkext);
    } else {
        IOLog("Can't add startup extensions from archive; "
            "kernel linker is not present.\n");
        result = false;
    }
    IOLockUnlock(kld_lock);

    return result;
}


/*********************************************************************
* This function clears out all references to the in-kernel linker,
* frees the list of startup extensions in extensionDict, and
* deallocates the kernel's __KLD segment to reclaim that memory.
*********************************************************************/
kern_return_t IOCatalogue::removeKernelLinker(void) {
    kern_return_t result = KERN_SUCCESS;
    extern struct mach_header _mh_execute_header;
    struct segment_command * segment;
    char * dt_segment_name;
    void * segment_paddress;
    int    segment_size;

   /* This must be the very first thing done by this function.
    */
    IOLockLock(kld_lock);


   /* If the kernel linker isn't here, that's automatically
    * a success.
    */
    if (!kernelLinkerPresent) {
        result = KERN_SUCCESS;
        goto finish;
    }

    IOLog("Jettisoning kernel linker.\n");

    kernelLinkerPresent = 0;

   /* Set the kmod_load_extension function as the means for loading
    * a kernel extension.
    */
    kmod_load_function = &kmod_load_extension;

    record_startup_extensions_function = 0;
    add_from_mkext_function = 0;
    remove_startup_extension_function = 0;


   /* Invoke destructors for the __KLD and __LINKEDIT segments.
    * Do this for all segments before actually freeing their
    * memory so that any cross-dependencies (not that there
    * should be any) are handled.
    */
    segment = getsegbynamefromheader(
        &_mh_execute_header, "__KLD");
    if (!segment) {
        IOLog("error removing kernel linker: can't find __KLD segment\n");
        result = KERN_FAILURE;
        goto finish;
    }
    OSRuntimeUnloadCPPForSegment(segment);

    segment = getsegbynamefromheader(
        &_mh_execute_header, "__LINKEDIT");
    if (!segment) {
        IOLog("error removing kernel linker: can't find __LINKEDIT segment\n");
        result = KERN_FAILURE;
        goto finish;
    }
    OSRuntimeUnloadCPPForSegment(segment);


   /* Free the memory that was set up by bootx.
    */
    dt_segment_name = "Kernel-__KLD";
    if (0 == IODTGetLoaderInfo(dt_segment_name, &segment_paddress, &segment_size)) {
        IODTFreeLoaderInfo(dt_segment_name, (void *)segment_paddress,
            (int)segment_size);
    }

    dt_segment_name = "Kernel-__LINKEDIT";
    if (0 == IODTGetLoaderInfo(dt_segment_name, &segment_paddress, &segment_size)) {
        IODTFreeLoaderInfo(dt_segment_name, (void *)segment_paddress,
            (int)segment_size);
    }


finish:

   /* This must be the very last thing done before returning.
    */
    IOLockUnlock(kld_lock);

    return result;
}
