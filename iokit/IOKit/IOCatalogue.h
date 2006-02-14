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


#ifndef _IOKIT_IOCATALOGUE_H
#define _IOKIT_IOCATALOGUE_H

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <IOKit/IOLocks.h>
#include <sys/cdefs.h>

#include <IOKit/IOKitServer.h>

class IOService;

/*!
    @class IOCatalogue
    @abstract In-kernel database for IOKit driver personalities.
    @discussion The IOCatalogue is a database which contains all IOKit driver personalities.  IOService uses this resource when matching devices to their associated drivers.
*/
class IOCatalogue : public OSObject
{
    OSDeclareDefaultStructors(IOCatalogue)
    
private:
    OSCollectionIterator   * kernelTables;
    OSArray                * array;
    IOLock *                 lock;
    SInt32                   generation;

    IOLock *                 kld_lock;

public:
    /*!
        @function initialize
        @abstract Creates and initializes the database object and poputates it with in-kernel driver personalities.
    */
    static void initialize( void );
    
    /*!
        @function init
        @abstract Initializes the database object.
        @param initArray  The initial array of driver personalities to populate the database.
    */
    bool init( OSArray * initArray );
    
    /*!
        @function free
        @abstract Cleans up the database and deallocates memory allocated at initialization.  This is never called in normal operation of the system.
    */
    void free( void );
    
    /*!
        @function findDrivers
        @abstract This is the primary entry point for IOService.
        @param service
        @param generationCount  Returns a reference to the generation count of the database. The generation count increases only when personalities are added to the database *and* IOService matching has been initiated.
        @result Returns an ordered set of driver personalities ranked on probe-scores.  The ordered set must be released by the receiver.
    */
    OSOrderedSet * findDrivers( IOService * service, SInt32 * generationCount );
    
    /*!
        @function findDrivers
        @abstract A more general purpose interface which allows one to retreive driver personalities based the intersection of the 'matching' dictionary and the personality's own property list.
        @param matching  A dictionary containing only keys and values which are to be used for matching. For example, a matching dictionary containing 'IOProviderClass'='IOPCIDevice' will return all personalities with an IOProviderClass key and a value of IOPCIDevice.
        @param generationCount  Returns a reference to the current generation of the database. The generation count increases only when personalities are added to the database *and* IOService matching has been initiated.
        @result Returns an ordered set of driver personalities ranked on probe-scores. The ordered set must be released by the receiver.
    */
    OSOrderedSet * findDrivers( OSDictionary * matching, SInt32 * generationCount );
    
    /*!
        @function addDrivers
        @abstract Adds an array of driver personalities to the database.
        @param array Array of driver personalities to be added to the database.
        @param doNubMatchng Start matching process after personalities have been added.
        @result Returns true if driver personality was added to the database successfully. Failure is due to a memory allocation failure.
    */
    bool addDrivers( OSArray * array, bool doNubMatching = true );
    
    /*!
        @function removeDrivers
        @abstract Remove driver personalities from the database based on matching information provided.
        @param matching  A dictionary whose keys and values are used for matching personalities in the database.  For example, a matching dictionary containing a 'IOProviderClass' key with the value 'IOPCIDevice' will remove all personalities which have the key 'IOProviderClass' equal to 'IOPCIDevice'.
        @param doNubMatchng Start matching process after personalities have been removed.  Matching criteria is based on IOProviderClass of those personalities which were removed.  This is to allow drivers which haven't been matched to match against NUB's which were blocked by the previous personalities. 
        @result Returns true if personality was removed successfully. Failure is due to a memory allocation failure.
    */
    bool removeDrivers( OSDictionary * matching, bool doNubMatching = true );
    
    /*!
        @function getGenerationCount
        @abstract Get the current generation count of the database.
    */
    SInt32 getGenerationCount( void ) const;

    /*!
        @function isModuleLoaded
        @abstract Reports if a kernel module has been loaded.
        @param moduleName  Name of the module.
        @result Returns true if the associated kernel module has been loaded into the kernel.
    */
    bool isModuleLoaded( OSString * moduleName ) const;

    /*!
        @function isModuleLoaded
        @abstract Reports if a kernel module has been loaded.
        @param moduleName  Name of the module.
        @result Returns true if the associated kernel module has been loaded into the kernel.
    */
    bool isModuleLoaded( const char * moduleName ) const;
    
    /*!
        @function isModuleLoaded
        @abstract Reports if a kernel module has been loaded for a particular personality.
        @param driver  A driver personality's property list.
        @result Returns true if the associated kernel module has been loaded into the kernel for a particular driver personality on which it depends.
    */
    bool isModuleLoaded( OSDictionary * driver ) const;
    
    /*!
        @function moduleHasLoaded
        @abstract Callback function called after a IOKit dependent kernel module is loaded.
        @param name  Name of the kernel module.
    */
    void moduleHasLoaded( OSString * name );
    
    /*!
        @function moduleHasLoaded
        @abstract Callback function called after a IOKit dependent kernel module is loaded.
        @param name  Name of the kernel module.
    */
    void moduleHasLoaded( const char * name );

    /*!
        @function terminateDrivers
        @abstract Terminates all instances of a driver which match the contents of the matching dictionary. Does not unload module.
        @param matching  A dictionary whose keys and values are used for matching personalities in the database.  For example, a matching dictionary containing a 'IOProviderClass' key with the value 'IOPCIDevice' will cause termination for all instances whose personalities have the key 'IOProviderClass' equal to 'IOPCIDevice'.
     */
    IOReturn terminateDrivers( OSDictionary * matching );

    /*!
        @function terminateDriversForModule
        @abstract Terminates all instances of a driver which depends on a particular module and unloads the module.
        @param moduleName Name of the module which is used to determine which driver instances to terminate and unload.
        @param unload Flag to cause the actual unloading of the module.
     */
    IOReturn terminateDriversForModule( OSString * moduleName, bool unload = true);

    /*!
        @function terminateDriversForModule
        @abstract Terminates all instances of a driver which depends on a particular module and unloads the module.
        @param moduleName Name of the module which is used to determine which driver instances to terminate and unload.
        @param unload Flag to cause the actual unloading of the module.
     */
    IOReturn terminateDriversForModule( const char * moduleName, bool unload = true);

    /*!
        @function startMatching
        @abstract Starts an IOService matching thread where matching keys and values are provided by the matching dictionary.
        @param matching  A dictionary whose keys and values are used for matching personalities in the database.  For example, a matching dictionary containing a 'IOProviderClass' key with the value 'IOPCIDevice' will start matching for all personalities which have the key 'IOProviderClass' equal to 'IOPCIDevice'.
     */
    bool startMatching( OSDictionary * matching );

    /*!
        @function reset
        @abstract Return the Catalogue to its initial state.
    */
    void reset(void);

    /*!
        @function serialize
        @abstract Serializes the catalog for transport to the user.
        @param s The serializer object.
        @result Returns false if unable to serialize database, most likely due to memory shortage.
     */
    virtual bool serialize(OSSerialize * s) const;

    bool serializeData(IOOptionBits kind, OSSerialize * s) const;

    /*!
        @function recordStartupExtensions
        @abstract Records extensions made available by the primary booter.
            <p>
            This function is for internal use by the kernel startup linker.
            Kernel extensions should never call it.
        @result Returns true if startup extensions were successfully recorded,
            false if not.
    */
    virtual bool recordStartupExtensions(void);

    /*!
        @function addExtensionsFromArchive()
        @abstract Records an archive of extensions, as from device ROM.
            <p>
            This function is currently for internal use.
            Kernel extensions should never call it.
        @param mkext An OSData object containing a multikext archive.
        @result Returns true if mkext was properly unserialized and its
                contents recorded, false if not.
    */
    virtual bool addExtensionsFromArchive(OSData * mkext);


    /*!
        @function removeKernelLinker
        @abstract Removes from memory all code and data related to
            boot-time loading of kernel extensions. kextd triggers
            this when it first starts in order to pass responsibility
            for loading extensions from the kernel itself to kextd.
        @result Returns KERN_SUCCESS if the kernel linker is successfully
            removed or wasn't present, KERN_FAILURE otherwise.
    */
    virtual kern_return_t removeKernelLinker(void);

    static void disableExternalLinker(void);

private:

    /*!
        @function unloadModule
        @abstract Unloads the reqested module if no driver instances are currently depending on it.
        @param moduleName An OSString containing the name of the module to unload.
     */
    IOReturn unloadModule( OSString * moduleName ) const;
};

__BEGIN_DECLS
/*!
    @function IOKitRelocStart
    @abstract Deprecated API.
*/
kmod_start_func_t IOKitRelocStart;
/*!
    @function IOKitRelocStop
    @abstract Deprecated API.
*/
kmod_stop_func_t IOKitRelocStop;
__END_DECLS

extern const OSSymbol *		gIOClassKey;
extern const OSSymbol *		gIOProbeScoreKey;
extern IOCatalogue *            gIOCatalogue;

#endif /* ! _IOKIT_IOCATALOGUE_H */
