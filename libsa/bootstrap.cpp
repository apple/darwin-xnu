/*
 * Copyright (c) 2000 Apple Inc. All rights reserved.
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
extern "C" {
#include <mach/kmod.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/prelink.h>
}

#include <libkern/version.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/c++/OSKext.h>
#include <IOKit/IOLib.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOCatalogue.h>

#if PRAGMA_MARK
#pragma mark Bootstrap Declarations
#endif
/*********************************************************************
* Bootstrap Declarations
*
* The ENTIRE point of the libsa/KLD segment is to isolate bootstrap
* code from other parts of the kernel, so function symbols are not
* exported; rather pointers to those functions are exported.
*
* xxx - need to think about locking for handling the 'weak' refs.
* xxx - do export a non-KLD function that says you've called a
* xxx - bootstrap function that has been removed.
*
* ALL call-ins to this segment of the kernel must be done through
* exported pointers. The symbols themselves are private and not to
* be linked against.
*********************************************************************/
extern "C" {
    extern void (*record_startup_extensions_function)(void);
    extern void (*load_security_extensions_function)(void);
};

static void bootstrapRecordStartupExtensions(void);
static void bootstrapLoadSecurityExtensions(void);

#if PRAGMA_MARK
#pragma mark Macros
#endif
/*********************************************************************
* Macros
*********************************************************************/
#define CONST_STRLEN(str) (sizeof(str) - 1)

#if PRAGMA_MARK
#pragma mark Kernel Component Kext Identifiers
#endif
/*********************************************************************
* Kernel Component Kext Identifiers
*
* We could have each kernel resource kext automatically "load" as
* it's created, but it's nicer to have them listed in kextstat in
* the order of this list. We'll walk through this after setting up
* all the boot kexts and have them load up.
*********************************************************************/
static const char * sKernelComponentNames[] = {
   // The kexts for these IDs must have a version matching 'osrelease'.
   "com.apple.kernel",
   "com.apple.kpi.bsd",
   "com.apple.kpi.dsep",
   "com.apple.kpi.iokit",
   "com.apple.kpi.libkern",
   "com.apple.kpi.mach",
   "com.apple.kpi.private",
   "com.apple.kpi.unsupported",
   "com.apple.iokit.IONVRAMFamily",
   "com.apple.driver.AppleNMI",
   "com.apple.iokit.IOSystemManagementFamily",
   "com.apple.iokit.ApplePlatformFamily",
   
#if defined(__ppc__) || defined(__i386__) || defined(__arm__)
   /* These ones are not supported on x86_64 or any newer platforms.
    * They must be version 7.9.9; check by "com.apple.kernel.", with
    * the trailing period; "com.apple.kernel" always represents the
    * current kernel version.
    */
    "com.apple.kernel.6.0",
    "com.apple.kernel.bsd",
    "com.apple.kernel.iokit",
    "com.apple.kernel.libkern",
    "com.apple.kernel.mach",
#endif

   NULL
};

#if PRAGMA_MARK
#pragma mark KLDBootstrap Class
#endif
/*********************************************************************
* KLDBootstrap Class
*
* We use a C++ class here so that it can be a friend of OSKext and
* get at private stuff. We can't hide the class itself, but we can
* hide the instance through which we invoke the functions.
*********************************************************************/
class KLDBootstrap {
    friend void bootstrapRecordStartupExtensions(void);
    friend void bootstrapLoadSecurityExtensions(void);

private:
    void readStartupExtensions(void);

    void readPrelinkedExtensions(
        kernel_section_t * prelinkInfoSect);
    void readBooterExtensions(void);
    OSReturn readMkextExtensions(
        OSString * deviceTreeName,
        OSData   * deviceTreeData);
    
    OSReturn loadKernelComponentKexts(void);
    void     readBuiltinPersonalities(void);

    void     loadSecurityExtensions(void);
    
public:
    KLDBootstrap(void);
    ~KLDBootstrap(void);
};

static KLDBootstrap sBootstrapObject;

/*********************************************************************
* Set the function pointers for the entry points into the bootstrap
* segment upon C++ static constructor invocation.
*********************************************************************/
KLDBootstrap::KLDBootstrap(void)
{
    if (this != &sBootstrapObject) {
        panic("Attempt to access bootstrap segment.");
    }
    record_startup_extensions_function = &bootstrapRecordStartupExtensions;
    load_security_extensions_function = &bootstrapLoadSecurityExtensions;
    OSKext::initialize();
}

/*********************************************************************
* Clear the function pointers for the entry points into the bootstrap
* segment upon C++ static destructor invocation.
*********************************************************************/
KLDBootstrap::~KLDBootstrap(void)
{
    if (this != &sBootstrapObject) {
        panic("Attempt to access bootstrap segment.");
    }
    record_startup_extensions_function = 0;
    load_security_extensions_function = 0;
}

/*********************************************************************
*********************************************************************/
void
KLDBootstrap::readStartupExtensions(void)
{
    kernel_section_t * prelinkInfoSect = NULL;  // do not free

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogGeneralFlag | kOSKextLogDirectoryScanFlag |
        kOSKextLogKextBookkeepingFlag,
        "Reading startup extensions.");
    
   /* If the prelink info segment has a nonzero size, we are prelinked
    * and won't have any individual kexts or mkexts to read.
    * Otherwise, we need to read kexts or the mkext from what the booter
    * has handed us.
    */
    prelinkInfoSect = getsectbyname(kPrelinkInfoSegment, kPrelinkInfoSection);
    if (prelinkInfoSect->size) {
        readPrelinkedExtensions(prelinkInfoSect);
    } else {
        readBooterExtensions();
    }

    loadKernelComponentKexts();
    readBuiltinPersonalities();
    OSKext::sendAllKextPersonalitiesToCatalog();

    return;
}

/*********************************************************************
*********************************************************************/
void
KLDBootstrap::readPrelinkedExtensions(
    kernel_section_t * prelinkInfoSect)
{
    OSArray                   * infoDictArray           = NULL;  // do not release
    OSArray                   * personalitiesArray      = NULL;  // do not release
    OSObject                  * parsedXML       = NULL;  // must release
    OSDictionary              * prelinkInfoDict         = NULL;  // do not release
    OSString                  * errorString             = NULL;  // must release
    OSKext                    * theKernel               = NULL;  // must release

#if CONFIG_KXLD
    kernel_section_t          * kernelLinkStateSection  = NULL;  // see code
#endif
    kernel_segment_command_t  * prelinkLinkStateSegment = NULL;  // see code
    kernel_segment_command_t  * prelinkTextSegment      = NULL;  // see code
    kernel_segment_command_t  * prelinkInfoSegment      = NULL;  // see code

   /* We make some copies of data, but if anything fails we're basically
    * going to fail the boot, so these won't be cleaned up on error.
    */
    void                      * prelinkData             = NULL;  // see code
    void                      * prelinkCopy             = NULL;  // see code
    vm_size_t                   prelinkLength           = 0;
#if !__LP64__ && !defined(__arm__)
    vm_map_offset_t             prelinkDataMapOffset    = 0;
#endif

    kern_return_t               mem_result              = KERN_SUCCESS;

    OSDictionary              * infoDict                = NULL;  // do not release

    IORegistryEntry           * registryRoot            = NULL;  // do not release
    OSNumber                  * prelinkCountObj         = NULL;  // must release

    u_int                       i = 0;

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
        "Starting from prelinked kernel.");

   /*****
    * Wrap the kernel link state in-place in an OSData.
    * This is unnecessary (and the link state may not be present) if the kernel
    * does not have kxld support because this information is only used for
    * runtime linking.
    */
#if CONFIG_KXLD
    kernelLinkStateSection = getsectbyname(kPrelinkLinkStateSegment,
        kPrelinkKernelLinkStateSection);
    if (!kernelLinkStateSection) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Can't find prelinked kernel link state.");
        goto finish;
    }

    theKernel = OSKext::lookupKextWithIdentifier(kOSKextKernelIdentifier);
    if (!theKernel) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Can't find kernel kext object in prelinked kernel.");
        goto finish;
    }

    prelinkData = (void *) kernelLinkStateSection->addr;
    prelinkLength = kernelLinkStateSection->size;

    mem_result = kmem_alloc_pageable(kernel_map,
        (vm_offset_t *) &prelinkCopy, prelinkLength);
    if (mem_result != KERN_SUCCESS) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
            "Can't copy prelinked kernel link state.");
        goto finish;
    }
    memcpy(prelinkCopy, prelinkData, prelinkLength);

    theKernel->linkState = OSData::withBytesNoCopy(prelinkCopy, prelinkLength);
    if (!theKernel->linkState) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
            "Can't create prelinked kernel link state wrapper.");
        goto finish;
    }
    theKernel->linkState->setDeallocFunction(osdata_kmem_free);
#endif

    prelinkTextSegment = getsegbyname(kPrelinkTextSegment);
    if (!prelinkTextSegment) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
            "Can't find prelinked kexts' text segment.");
        goto finish;
    }

    prelinkData = (void *) prelinkTextSegment->vmaddr;
    prelinkLength = prelinkTextSegment->vmsize;

#if !__LP64__
    /* To enable paging and write/execute protections on the kext
     * executables, we need to copy them out of the booter-created
     * memory, reallocate that space with VM, then prelinkCopy them back in.
     * This isn't necessary on LP64 because kexts have their own VM
     * region on that architecture model.
     */

    mem_result = kmem_alloc(kernel_map, (vm_offset_t *)&prelinkCopy,
        prelinkLength);
    if (mem_result != KERN_SUCCESS) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
            "Can't copy prelinked kexts' text for VM reassign.");
        goto finish;
    }

   /* Copy it out.
    */
    memcpy(prelinkCopy, prelinkData, prelinkLength);
    
   /* Dump the booter memory.
    */
    ml_static_mfree((vm_offset_t)prelinkData, prelinkLength);

   /* Set up the VM region.
    */
    prelinkDataMapOffset = (vm_map_offset_t)(uintptr_t)prelinkData;
    mem_result = vm_map_enter_mem_object(
        kernel_map,
        &prelinkDataMapOffset,
        prelinkLength, /* mask */ 0, 
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 
        (ipc_port_t)NULL,
        (vm_object_offset_t) 0,
        /* copy */ FALSE,
        /* cur_protection */ VM_PROT_ALL,
        /* max_protection */ VM_PROT_ALL,
        /* inheritance */ VM_INHERIT_DEFAULT);
    if ((mem_result != KERN_SUCCESS) || 
        (prelinkTextSegment->vmaddr != prelinkDataMapOffset)) 
    {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
            "Can't create kexts' text VM entry at 0x%llx, length 0x%x (error 0x%x).",
            (unsigned long long) prelinkDataMapOffset, prelinkLength, mem_result);
        goto finish;
    }
    prelinkData = (void *)(uintptr_t)prelinkDataMapOffset;

   /* And copy it back.
    */
    memcpy(prelinkData, prelinkCopy, prelinkLength);

    kmem_free(kernel_map, (vm_offset_t)prelinkCopy, prelinkLength);
#endif /* !__LP64__ */

   /* Unserialize the info dictionary from the prelink info section.
    */
    parsedXML = OSUnserializeXML((const char *)prelinkInfoSect->addr,
        &errorString);
    if (parsedXML) {
        prelinkInfoDict = OSDynamicCast(OSDictionary, parsedXML);
    }
    if (!prelinkInfoDict) {
        const char * errorCString = "(unknown error)";
        
        if (errorString && errorString->getCStringNoCopy()) {
            errorCString = errorString->getCStringNoCopy();
        } else if (parsedXML) {
            errorCString = "not a dictionary";
        }
        OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
            "Error unserializing prelink plist: %s.", errorCString);
        goto finish;
    }

    infoDictArray = OSDynamicCast(OSArray, 
        prelinkInfoDict->getObject(kPrelinkInfoDictionaryKey));
    if (!infoDictArray) {
        OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
            "The prelinked kernel has no kext info dictionaries");
        goto finish;
    }

   /* Create OSKext objects for each info dictionary.
    */
    for (i = 0; i < infoDictArray->getCount(); ++i) {
        infoDict = OSDynamicCast(OSDictionary, infoDictArray->getObject(i));
        if (!infoDict) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
                "Can't find info dictionary for prelinked kext #%d.", i);
            continue;
        }

       /* Create the kext for the entry, then release it, because the
        * kext system keeps them around until explicitly removed.
        * Any creation/registration failures are already logged for us.
        */
        OSKext * newKext = OSKext::withPrelinkedInfoDict(infoDict);
        OSSafeReleaseNULL(newKext);
    }
    
    /* Get all of the personalities for kexts that were not prelinked and
     * add them to the catalogue.
     */
    personalitiesArray = OSDynamicCast(OSArray,
        prelinkInfoDict->getObject(kPrelinkPersonalitiesKey));
    if (!personalitiesArray) {
        OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
            "The prelinked kernel has no personalities array");
        goto finish;
    }

    if (personalitiesArray->getCount()) {
        gIOCatalogue->addDrivers(personalitiesArray);
    }

   /* Store the number of prelinked kexts in the registry so we can tell
    * when the system has been started from a prelinked kernel.
    */
    registryRoot = IORegistryEntry::getRegistryRoot();
    assert(registryRoot);

    prelinkCountObj = OSNumber::withNumber(
        (unsigned long long)infoDictArray->getCount(),
        8 * sizeof(uint32_t));
    assert(prelinkCountObj);
    if (prelinkCountObj) {
        registryRoot->setProperty(kOSPrelinkKextCountKey, prelinkCountObj);
    }

    OSSafeReleaseNULL(prelinkCountObj);
    prelinkCountObj = OSNumber::withNumber(
        (unsigned long long)personalitiesArray->getCount(),
        8 * sizeof(uint32_t));
    assert(prelinkCountObj);
    if (prelinkCountObj) {
        registryRoot->setProperty(kOSPrelinkPersonalityCountKey, prelinkCountObj);
    }

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogGeneralFlag | kOSKextLogKextBookkeepingFlag |
        kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
        "%u prelinked kexts, and %u additional personalities.", 
        infoDictArray->getCount(), personalitiesArray->getCount());

#if __LP64__
        /* On LP64 systems, kexts are copied to their own special VM region
         * during OSKext init time, so we can free the whole segment now.
         */
        ml_static_mfree((vm_offset_t) prelinkData, prelinkLength);
#endif /* __LP64__ */

   /* Free the link state segment, kexts have copied out what they need.
    */
    prelinkLinkStateSegment = getsegbyname(kPrelinkLinkStateSegment);
    if (prelinkLinkStateSegment) {
        ml_static_mfree((vm_offset_t)prelinkLinkStateSegment->vmaddr,
            (vm_size_t)prelinkLinkStateSegment->vmsize);
    }

   /* Free the prelink info segment, we're done with it.
    */
    prelinkInfoSegment = getsegbyname(kPrelinkInfoSegment);
    if (prelinkInfoSegment) {
        ml_static_mfree((vm_offset_t)prelinkInfoSegment->vmaddr,
            (vm_size_t)prelinkInfoSegment->vmsize);
    }

finish:
    OSSafeRelease(errorString);
    OSSafeRelease(parsedXML);
    OSSafeRelease(theKernel);
    OSSafeRelease(prelinkCountObj);
    return;
}

/*********************************************************************
*********************************************************************/
#define BOOTER_KEXT_PREFIX   "Driver-"
#define BOOTER_MKEXT_PREFIX  "DriversPackage-"

typedef struct _DeviceTreeBuffer {
    uint32_t paddr;
    uint32_t length;
} _DeviceTreeBuffer;

void
KLDBootstrap::readBooterExtensions(void)
{
    IORegistryEntry           * booterMemoryMap         = NULL;  // must release
    OSDictionary              * propertyDict            = NULL;  // must release
    OSCollectionIterator      * keyIterator             = NULL;  // must release
    OSString                  * deviceTreeName          = NULL;  // do not release
    
    const _DeviceTreeBuffer   * deviceTreeBuffer        = NULL;  // do not free
    char                      * booterDataPtr           = NULL;  // do not free
    OSData                    * booterData              = NULL;  // must release

    OSKext                    * aKext                   = NULL;  // must release

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogDirectoryScanFlag | kOSKextLogKextBookkeepingFlag,
        "Reading startup extensions/mkexts from booter memory.");
    
    booterMemoryMap = IORegistryEntry::fromPath( "/chosen/memory-map", gIODTPlane);

    if (!booterMemoryMap) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag | kOSKextLogDirectoryScanFlag,
            "Can't read booter memory map.");
        goto finish;
    }

    propertyDict = booterMemoryMap->dictionaryWithProperties();
    if (!propertyDict) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogDirectoryScanFlag,
            "Can't get property dictionary from memory map.");
        goto finish;
    }

    keyIterator = OSCollectionIterator::withCollection(propertyDict);
    if (!keyIterator) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag,
            "Can't allocate iterator for driver images.");
        goto finish;
    }

    while ( ( deviceTreeName =
        OSDynamicCast(OSString, keyIterator->getNextObject() ))) {

        boolean_t isMkext = FALSE;
        const char * devTreeNameCString = deviceTreeName->getCStringNoCopy();
        OSData * deviceTreeEntry = OSDynamicCast(OSData,
            propertyDict->getObject(deviceTreeName));

       /* Clear out the booterData from the prior iteration.
        */
        OSSafeReleaseNULL(booterData);

        /* If there is no entry for the name, we can't do much with it. */
        if (!deviceTreeEntry) {
            continue;
        }

        /* Make sure it is either a kext or an mkext */
        if (!strncmp(devTreeNameCString, BOOTER_KEXT_PREFIX,
            CONST_STRLEN(BOOTER_KEXT_PREFIX))) {

            isMkext = FALSE;

        } else if (!strncmp(devTreeNameCString, BOOTER_MKEXT_PREFIX,
            CONST_STRLEN(BOOTER_MKEXT_PREFIX))) {

            isMkext = TRUE;

        } else {
            continue;
        }

        deviceTreeBuffer = (const _DeviceTreeBuffer *)
            deviceTreeEntry->getBytesNoCopy(0, sizeof(deviceTreeBuffer));
        if (!deviceTreeBuffer) {
           /* We can't get to the data, so we can't do anything,
            * not even free it from physical memory (if it's there).
            */
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogDirectoryScanFlag,
                "Device tree entry %s has NULL pointer.",
                devTreeNameCString);
            goto finish;  // xxx - continue, panic?
        }

        booterDataPtr = (char *)ml_static_ptovirt(deviceTreeBuffer->paddr);
        if (!booterDataPtr) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogDirectoryScanFlag,
                "Can't get virtual address for device tree mkext entry %s.",
                devTreeNameCString);
            goto finish;
        }

       /* Wrap the booter data buffer in an OSData and set a dealloc function
        * so it will take care of the physical memory when freed. Kexts will
        * retain the booterData for as long as they need it. Remove the entry
        * from the booter memory map after this is done.
        */
        booterData = OSData::withBytesNoCopy(booterDataPtr,
            deviceTreeBuffer->length);
        if (!booterData) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag,
                "Error - Can't allocate OSData wrapper for device tree entry %s.",
                devTreeNameCString);
            goto finish;
        }
        booterData->setDeallocFunction(osdata_phys_free);

        if (isMkext) {
            readMkextExtensions(deviceTreeName, booterData);
        } else {
           /* Create the kext for the entry, then release it, because the
            * kext system keeps them around until explicitly removed.
            * Any creation/registration failures are already logged for us.
            */
            OSKext * newKext = OSKext::withBooterData(deviceTreeName, booterData);
            OSSafeRelease(newKext);
        }

        booterMemoryMap->removeProperty(deviceTreeName);

    } /* while ( (deviceTreeName = OSDynamicCast(OSString, ...) ) ) */

finish:

    OSSafeRelease(booterMemoryMap);
    OSSafeRelease(propertyDict);
    OSSafeRelease(keyIterator);
    OSSafeRelease(booterData);
    OSSafeRelease(aKext);
    return;
}

/*********************************************************************
*********************************************************************/
OSReturn
KLDBootstrap::readMkextExtensions(
    OSString   * deviceTreeName,
    OSData     * booterData)
{
    OSReturn result = kOSReturnError;

    uint32_t          checksum;
    IORegistryEntry * registryRoot = NULL;  // do not release
    OSData          * checksumObj  = NULL;   // must release

    OSKextLog(/* kext */ NULL,
        kOSKextLogStepLevel |
        kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
        "Reading startup mkext archive from device tree entry %s.",
        deviceTreeName->getCStringNoCopy());

   /* If we successfully read the archive,
    * then save the mkext's checksum in the IORegistry.
    * assumes we'll only ever have one mkext to boot
    */
    result = OSKext::readMkextArchive(booterData, &checksum);
    if (result == kOSReturnSuccess) {

        OSKextLog(/* kext */ NULL,
            kOSKextLogProgressLevel |
            kOSKextLogArchiveFlag,
            "Startup mkext archive has checksum 0x%x.", (int)checksum);

        registryRoot = IORegistryEntry::getRegistryRoot();
        assert(registryRoot);
        checksumObj = OSData::withBytes((void *)&checksum, sizeof(checksum));
        assert(checksumObj);
        if (checksumObj) {
            registryRoot->setProperty(kOSStartupMkextCRC, checksumObj);
        }
    }
    
    return result;
}

/*********************************************************************
*********************************************************************/
#define COM_APPLE  "com.apple."

void
KLDBootstrap::loadSecurityExtensions(void)
{
    OSDictionary         * extensionsDict = NULL;  // must release
    OSCollectionIterator * keyIterator    = NULL;  // must release
    OSString             * bundleID       = NULL;  // don't release
    OSKext               * theKext        = NULL;  // don't release
    OSBoolean            * isSecurityKext = NULL;  // don't release

    OSKextLog(/* kext */ NULL,
        kOSKextLogStepLevel |
        kOSKextLogLoadFlag,
        "Loading security extensions.");

    extensionsDict = OSKext::copyKexts();
    if (!extensionsDict) {
        return;
    }

    keyIterator = OSCollectionIterator::withCollection(extensionsDict);
    if (!keyIterator) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag,
            "Failed to allocate iterator for security extensions.");
        goto finish;
    }

    while ((bundleID = OSDynamicCast(OSString, keyIterator->getNextObject()))) {

        const char * bundle_id = bundleID->getCStringNoCopy();
        
       /* Skip extensions whose bundle IDs don't start with "com.apple.".
        */
        if (!bundle_id ||
            (strncmp(bundle_id, COM_APPLE, CONST_STRLEN(COM_APPLE)) != 0)) {

            continue;
        }

        theKext = OSDynamicCast(OSKext, extensionsDict->getObject(bundleID));
        if (!theKext) {
            continue;
        }

        isSecurityKext = OSDynamicCast(OSBoolean,
            theKext->getPropertyForHostArch("AppleSecurityExtension"));
        if (isSecurityKext && isSecurityKext->isTrue()) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogStepLevel |
                kOSKextLogLoadFlag,
                "Loading security extension %s.", bundleID->getCStringNoCopy());
            OSKext::loadKextWithIdentifier(bundleID->getCStringNoCopy(),
                /* allowDefer */ false);
        }
    }

finish:
    OSSafeRelease(keyIterator);
    OSSafeRelease(extensionsDict);

    return;
}

/*********************************************************************
* We used to require that all listed kernel components load, but
* nowadays we can get them from userland so we only try to load the
* ones we have. If an error occurs later, such is life.
*
* Note that we look the kexts up first, so we can avoid spurious
* (in this context, anyhow) log messages about kexts not being found.
*
* xxx - do we even need to do this any more? Check if the kernel
* xxx - compoonents just load in the regular paths
*********************************************************************/
OSReturn
KLDBootstrap::loadKernelComponentKexts(void)
{
    OSReturn      result      = kOSReturnSuccess;  // optimistic
    OSKext      * theKext     = NULL;              // must release
    const char ** kextIDPtr   = NULL;              // do not release

    for (kextIDPtr = &sKernelComponentNames[0]; *kextIDPtr; kextIDPtr++) {
        
        OSSafeReleaseNULL(theKext);
        theKext = OSKext::lookupKextWithIdentifier(*kextIDPtr);

        if (theKext) {
            if (kOSReturnSuccess != OSKext::loadKextWithIdentifier(
                *kextIDPtr, /* allowDefer */ false)) {

                // xxx - check KextBookkeeping, might be redundant
                OSKextLog(/* kext */ NULL,
                    kOSKextLogErrorLevel |
                    kOSKextLogDirectoryScanFlag | kOSKextLogKextBookkeepingFlag,
                    "Failed to initialize kernel component %s.", *kextIDPtr);
                result = kOSReturnError;
            }
        }
    }

    OSSafeRelease(theKext);
    return result;
}

/*********************************************************************
 *********************************************************************/
void
KLDBootstrap::readBuiltinPersonalities(void)
{
    OSObject              * parsedXML             = NULL;  // must release
    OSArray               * builtinExtensions     = NULL;  // do not release
    OSArray               * allPersonalities      = NULL;  // must release
    OSString              * errorString           = NULL;  // must release
    kernel_section_t      * infosect              = NULL;  // do not free
    OSCollectionIterator  * personalitiesIterator = NULL;  // must release
    unsigned int            count, i;
    
    OSKextLog(/* kext */ NULL,
        kOSKextLogStepLevel |
        kOSKextLogLoadFlag,
        "Reading built-in kernel personalities for I/O Kit drivers.");

   /* Look in the __BUILTIN __info segment for an array of Info.plist
    * entries. For each one, extract the personalities dictionary, add
    * it to our array, then push them all (without matching) to
    * the IOCatalogue. This can be used to augment the personalities
    * in gIOKernelConfigTables, especially when linking entire kexts into
    * the mach_kernel image.
    */
    infosect   = getsectbyname("__BUILTIN", "__info");
    if (!infosect) {
        // this isn't fatal
        goto finish;
    }
        
    parsedXML = OSUnserializeXML((const char *) (uintptr_t)infosect->addr,
        &errorString);
    if (parsedXML) {
        builtinExtensions = OSDynamicCast(OSArray, parsedXML);
    }
    if (!builtinExtensions) {
        const char * errorCString = "(unknown error)";
        
        if (errorString && errorString->getCStringNoCopy()) {
            errorCString = errorString->getCStringNoCopy();
        } else if (parsedXML) {
            errorCString = "not an array";
        }
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Error unserializing built-in personalities: %s.", errorCString);
        goto finish;
    }
            
    // estimate 3 personalities per Info.plist/kext
    count = builtinExtensions->getCount();
    allPersonalities = OSArray::withCapacity(count * 3);
            
    for (i = 0; i < count; i++) {
        OSDictionary            * infoDict = NULL;      // do not release
        OSString                * moduleName = NULL;    // do not release
        OSDictionary            * personalities;        // do not release
        OSString                * personalityName;      // do not release    
        
        OSSafeReleaseNULL(personalitiesIterator);

        infoDict = OSDynamicCast(OSDictionary,
            builtinExtensions->getObject(i));
        if (!infoDict) {
            continue;
        }
        
        moduleName = OSDynamicCast(OSString,
            infoDict->getObject(kCFBundleIdentifierKey));
        if (!moduleName) {
            continue;
        }
        
        OSKextLog(/* kext */ NULL,
            kOSKextLogStepLevel |
            kOSKextLogLoadFlag,
            "Adding personalities for built-in driver %s:",
            moduleName->getCStringNoCopy());
        
        personalities = OSDynamicCast(OSDictionary,
            infoDict->getObject("IOKitPersonalities"));
        if (!personalities) {
            continue;
        }
        
        personalitiesIterator = OSCollectionIterator::withCollection(personalities);
        if (!personalitiesIterator) {
            continue;  // xxx - well really, what can we do? should we panic?
        }
        
        while ((personalityName = OSDynamicCast(OSString,
            personalitiesIterator->getNextObject()))) {
            
            OSDictionary * personality = OSDynamicCast(OSDictionary,
                personalities->getObject(personalityName));

            OSKextLog(/* kext */ NULL,
                kOSKextLogDetailLevel |
                kOSKextLogLoadFlag,
                "Adding built-in driver personality %s.",
                personalityName->getCStringNoCopy());
        
			if (personality && !personality->getObject(kCFBundleIdentifierKey)) {
				personality->setObject(kCFBundleIdentifierKey, moduleName);
			}
            allPersonalities->setObject(personality);
        }
    }
    
    gIOCatalogue->addDrivers(allPersonalities, false);

finish:
    OSSafeRelease(parsedXML);
    OSSafeRelease(allPersonalities);
    OSSafeRelease(errorString);
    OSSafeRelease(personalitiesIterator);
    return;
}

#if PRAGMA_MARK
#pragma mark Bootstrap Functions
#endif
/*********************************************************************
* Bootstrap Functions
*********************************************************************/
static void bootstrapRecordStartupExtensions(void)
{
    sBootstrapObject.readStartupExtensions();
    return;
}

static void bootstrapLoadSecurityExtensions(void)
{
    sBootstrapObject.loadSecurityExtensions();
    return;
}
