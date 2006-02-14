/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <libkern/c++/OSContainers.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOCatalogue.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/OSByteOrder.h>
#include <libsa/catalogue.h>

extern "C" {
#include <machine/machine_routines.h>
#include <mach/host_info.h>
#include <mach/kmod.h>
#include <libsa/mkext.h>
#include <libsa/vers_rsrc.h>
#include <mach-o/loader.h>
};

#include <IOKit/IOLib.h>

#include <IOKit/assert.h>

extern "C" {
extern void IODTFreeLoaderInfo( char *key, void *infoAddr, int infoSize );
// extern kern_return_t host_info(host_t host,
//     host_flavor_t flavor,
//     host_info_t info,
//     mach_msg_type_number_t  *count);
extern int grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype);
// Return the address of the named Mach-O segment from the currently
// executing 32 bit kernel, or NULL.
extern struct segment_command *getsegbyname(char *seg_name);
// Return the address of the named section from the named Mach-O segment
// from the currently executing 32 bit kernel, or NULL.
extern struct section *getsectbyname(char *segname, char *sectname);
};

#define LOG_DELAY()

#if 0
#define VTYELLOW   "\033[33m"
#define VTRESET    "\033[0m"
#else
#define VTYELLOW   ""
#define VTRESET    ""
#endif

/*********************************************************************
*********************************************************************/
static OSDictionary * gStartupExtensions = 0;
static OSArray * gBootLoaderObjects = 0;
extern OSArray * gIOPrelinkedModules;

OSDictionary * getStartupExtensions(void) {
    if (gStartupExtensions) {
        return gStartupExtensions;
    }
    gStartupExtensions = OSDictionary::withCapacity(1);
    assert (gStartupExtensions);

    return gStartupExtensions;
}

/* This array holds objects that are needed to be held around during
 * boot before kextd starts up. Currently it contains OSData objects
 * copied from OF entries for mkext archives in device ROMs. Because
 * the Device Tree support code dumps these after initially handing
 * them to us, we have to be able to clean them up later.
 */
OSArray * getBootLoaderObjects(void) {
    if (gBootLoaderObjects) {
        return gBootLoaderObjects;
    }
    gBootLoaderObjects = OSArray::withCapacity(1);
    assert (gBootLoaderObjects);

    return gBootLoaderObjects;
}

/*********************************************************************
* This function checks that a driver dict has all the required
* entries and does a little bit of value checking too.
*
* index is nonnegative if the index of an entry from an mkext
* archive.
*********************************************************************/
bool validateExtensionDict(OSDictionary * extension, int index) {

    bool result = true;
    bool not_a_dict = false;
    bool id_missing = false;
    bool is_kernel_resource = false;
    bool has_executable = false;
    OSString * bundleIdentifier = NULL;    // do not release
    OSObject * rawValue = NULL;            // do not release
    OSString * stringValue = NULL;         // do not release
    OSBoolean * booleanValue = NULL;       // do not release
    OSDictionary * personalities = NULL;   // do not release
    OSDictionary * libraries = NULL;       // do not release
    OSCollectionIterator * keyIterator = NULL;  // must release
    OSString * key = NULL;                 // do not release
    VERS_version vers;
    VERS_version compatible_vers;

    // Info dict is a dictionary
    if (!OSDynamicCast(OSDictionary, extension)) {
        not_a_dict = true;
        result = false;
        goto finish;
    }

    // CFBundleIdentifier is a string - REQUIRED
    bundleIdentifier = OSDynamicCast(OSString,
        extension->getObject("CFBundleIdentifier"));
    if (!bundleIdentifier) {
        id_missing = true;
        result = false;
        goto finish;
    }

    // Length of CFBundleIdentifier is not >= KMOD_MAX_NAME
    if (bundleIdentifier->getLength() >= KMOD_MAX_NAME) {
        result = false;
        goto finish;
    }

    // CFBundlePackageType is "KEXT" - REQUIRED
    stringValue = OSDynamicCast(OSString,
        extension->getObject("CFBundlePackageType"));
    if (!stringValue) {
        result = false;
        goto finish;
    }
    if (!stringValue->isEqualTo("KEXT")) {
        result = false;
        goto finish;
    }

    // CFBundleVersion is a string - REQUIRED
    stringValue = OSDynamicCast(OSString,
        extension->getObject("CFBundleVersion"));
    if (!stringValue) {
        result = false;
        goto finish;
    }
    // CFBundleVersion is of valid form
    vers = VERS_parse_string(stringValue->getCStringNoCopy());
    if (vers < 0) {
        result = false;
        goto finish;
    }

    // OSBundleCompatibleVersion is a string - OPTIONAL
    rawValue = extension->getObject("OSBundleCompatibleVersion");
    if (rawValue) {
        stringValue = OSDynamicCast(OSString, rawValue);
        if (!stringValue) {
            result = false;
            goto finish;
        }

        // OSBundleCompatibleVersion is of valid form
        compatible_vers = VERS_parse_string(stringValue->getCStringNoCopy());
        if (compatible_vers < 0) {
            result = false;
            goto finish;
        }

        // OSBundleCompatibleVersion <= CFBundleVersion
        if (compatible_vers > vers) {
            result = false;
            goto finish;
        }
    }

    // CFBundleExecutable is a string - OPTIONAL
    rawValue = extension->getObject("CFBundleExecutable");
    if (rawValue) {
        stringValue = OSDynamicCast(OSString, rawValue);
        if (!stringValue || stringValue->getLength() == 0) {
            result = false;
            goto finish;
        }
        has_executable = true;
    }

    // OSKernelResource is a boolean value - OPTIONAL
    rawValue = extension->getObject("OSKernelResource");
    if (rawValue) {
        booleanValue = OSDynamicCast(OSBoolean, rawValue);
        if (!booleanValue) {
            result = false;
            goto finish;
        }
        is_kernel_resource = booleanValue->isTrue();
    }

    // IOKitPersonalities is a dictionary - OPTIONAL
    rawValue = extension->getObject("IOKitPersonalities");
    if (rawValue) {
        personalities = OSDynamicCast(OSDictionary, rawValue);
        if (!personalities) {
            result = false;
            goto finish;
        }

        keyIterator = OSCollectionIterator::withCollection(personalities);
        if (!keyIterator) {
            IOLog("Error: Failed to allocate iterator for personalities.\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }

        while ((key = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
            OSDictionary * personality = NULL;  // do not release

            // Each personality is a dictionary
            personality = OSDynamicCast(OSDictionary,
                personalities->getObject(key));
            if (!personality) {
                result = false;
                goto finish;
            }

            //   IOClass exists as a string - REQUIRED
            if (!OSDynamicCast(OSString, personality->getObject("IOClass"))) {
                result = false;
                goto finish;
            }

            //   IOProviderClass exists as a string - REQUIRED
            if (!OSDynamicCast(OSString,
                personality->getObject("IOProviderClass"))) {

                result = false;
                goto finish;
            }

            // CFBundleIdentifier is a string - OPTIONAL - INSERT IF ABSENT!
            rawValue = personality->getObject("CFBundleIdentifier");
            if (!rawValue) {
                personality->setObject("CFBundleIdentifier", bundleIdentifier);
            } else {
                OSString * personalityID = NULL;    // do not release
                personalityID = OSDynamicCast(OSString, rawValue);
                if (!personalityID) {
                    result = false;
                    goto finish;
                } else {
                    // Length of CFBundleIdentifier is not >= KMOD_MAX_NAME
                    if (personalityID->getLength() >= KMOD_MAX_NAME) {
                        result = false;
                        goto finish;
                    }
                }
            }

            // IOKitDebug is a number - OPTIONAL
            rawValue = personality->getObject("IOKitDebug");
            if (rawValue && !OSDynamicCast(OSNumber, rawValue)) {
                result = false;
                goto finish;
            }
        }

        keyIterator->release();
        keyIterator = NULL;
    }


    // OSBundleLibraries is a dictionary - REQUIRED if
    // not kernel resource & has executable
    //
    rawValue = extension->getObject("OSBundleLibraries");
    if (!rawValue && !is_kernel_resource && has_executable) {
        result = false;
        goto finish;
    }

    if (rawValue) {
        libraries = OSDynamicCast(OSDictionary, rawValue);
        if (!libraries) {
            result = false;
            goto finish;
        }

        keyIterator = OSCollectionIterator::withCollection(libraries);
        if (!keyIterator) {
            IOLog("Error: Failed to allocate iterator for libraries.\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }

        while ((key = OSDynamicCast(OSString,
            keyIterator->getNextObject()))) {

            OSString * libraryVersion = NULL;  // do not release

            // Each key's length is not >= KMOD_MAX_NAME
            if (key->getLength() >= KMOD_MAX_NAME) {
                result = false;
                goto finish;
            }

            libraryVersion = OSDynamicCast(OSString,
                libraries->getObject(key));
            if (!libraryVersion) {
                result = false;
                goto finish;
            }

            // Each value is a valid version string
            vers = VERS_parse_string(libraryVersion->getCStringNoCopy());
            if (vers < 0) {
                result = false;
                goto finish;
            }
        }

        keyIterator->release();
        keyIterator = NULL;
    }

    // OSBundleRequired is a legal value - *not* required at boot time
    // so we can do install CDs and the like with mkext files containing
    // all normally-used drivers.
    rawValue = extension->getObject("OSBundleRequired");
    if (rawValue) {
        stringValue = OSDynamicCast(OSString, rawValue);
        if (!stringValue) {
            result = false;
            goto finish;
        }
        if (!stringValue->isEqualTo("Root") &&
            !stringValue->isEqualTo("Local-Root") &&
            !stringValue->isEqualTo("Network-Root") &&
            !stringValue->isEqualTo("Safe Boot") &&
            !stringValue->isEqualTo("Console")) {

            result = false;
            goto finish;
        }

    }


finish:
    if (keyIterator)   keyIterator->release();

    if (!result) {
        if (not_a_dict) {
            if (index > -1) {
                IOLog(VTYELLOW "mkext entry %d:." VTRESET, index);
            } else {
                IOLog(VTYELLOW "kernel extension" VTRESET);
            }
            IOLog(VTYELLOW "info dictionary isn't a dictionary\n"
                VTRESET);
        } else if (id_missing) {
            if (index > -1) {
                IOLog(VTYELLOW "mkext entry %d:." VTRESET, index);
            } else {
                IOLog(VTYELLOW "kernel extension" VTRESET);
            }
            IOLog(VTYELLOW "\"CFBundleIdentifier\" property is "
                "missing or not a string\n"
                VTRESET);
        } else {
            IOLog(VTYELLOW "kernel extension \"%s\": info dictionary is invalid\n"
                VTRESET, bundleIdentifier->getCStringNoCopy());
        }
        LOG_DELAY();
    }

    return result;
}


/*********************************************************************
*********************************************************************/
OSDictionary * compareExtensionVersions(
    OSDictionary * incumbent,
    OSDictionary * candidate) {

    OSDictionary * winner = NULL;

    OSDictionary * incumbentPlist = NULL;
    OSDictionary * candidatePlist = NULL;
    OSString * incumbentName = NULL;
    OSString * candidateName = NULL;
    OSString * incumbentVersionString = NULL;
    OSString * candidateVersionString = NULL;
    VERS_version incumbent_vers = 0;
    VERS_version candidate_vers = 0;

    incumbentPlist = OSDynamicCast(OSDictionary,
        incumbent->getObject("plist"));
    candidatePlist = OSDynamicCast(OSDictionary,
        candidate->getObject("plist"));

    if (!incumbentPlist || !candidatePlist) {
        IOLog("compareExtensionVersions() called with invalid "
            "extension dictionaries.\n");
        LOG_DELAY();
        winner = NULL;
        goto finish;
    }

    incumbentName = OSDynamicCast(OSString,
        incumbentPlist->getObject("CFBundleIdentifier"));
    candidateName = OSDynamicCast(OSString,
        candidatePlist->getObject("CFBundleIdentifier"));
    incumbentVersionString = OSDynamicCast(OSString,
        incumbentPlist->getObject("CFBundleVersion"));
    candidateVersionString = OSDynamicCast(OSString,
        candidatePlist->getObject("CFBundleVersion"));

    if (!incumbentName || !candidateName ||
        !incumbentVersionString || !candidateVersionString) {

        IOLog("compareExtensionVersions() called with invalid "
            "extension dictionaries.\n");
        LOG_DELAY();
        winner = NULL;
        goto finish;
    }

    if (strcmp(incumbentName->getCStringNoCopy(),
               candidateName->getCStringNoCopy())) {

        IOLog("compareExtensionVersions() called with different "
            "extension names (%s and %s).\n",
            incumbentName->getCStringNoCopy(),
            candidateName->getCStringNoCopy());
        LOG_DELAY();
        winner = NULL;
        goto finish;
    }

    incumbent_vers = VERS_parse_string(incumbentVersionString->getCStringNoCopy());
    if (incumbent_vers < 0) {

        IOLog(VTYELLOW "Error parsing version string for extension %s (%s)\n"
            VTRESET,
            incumbentName->getCStringNoCopy(),
            incumbentVersionString->getCStringNoCopy());
        LOG_DELAY();
        winner = NULL;
        goto finish;
    }

    candidate_vers = VERS_parse_string(candidateVersionString->getCStringNoCopy());
    if (candidate_vers < 0) {

        IOLog(VTYELLOW "Error parsing version string for extension %s (%s)\n"
            VTRESET,
            candidateName->getCStringNoCopy(),
            candidateVersionString->getCStringNoCopy());
        LOG_DELAY();
        winner = NULL;
        goto finish;
     }
  
    if (candidate_vers > incumbent_vers) {
        IOLog(VTYELLOW "Replacing extension \"%s\" with newer version "
            "(%s -> %s).\n" VTRESET,
            incumbentName->getCStringNoCopy(),
            incumbentVersionString->getCStringNoCopy(),
            candidateVersionString->getCStringNoCopy());
        LOG_DELAY();
        winner = candidate;
        goto finish;
    } else {
        IOLog(VTYELLOW "Skipping duplicate extension \"%s\" with older/same "
            " version (%s -> %s).\n" VTRESET,
            candidateName->getCStringNoCopy(),
            candidateVersionString->getCStringNoCopy(),
            incumbentVersionString->getCStringNoCopy());
        LOG_DELAY();
        winner = incumbent;
        goto finish;
    }

finish:

    // no cleanup, how nice
    return winner;
}


/*********************************************************************
* This function merges entries in the mergeFrom dictionary into the
* mergeInto dictionary. If it returns false, the two dictionaries are
* not altered. If it returns true, then mergeInto may have new
* entries; any keys that were already present in mergeInto are
* removed from mergeFrom, so that the caller can see what was
* actually merged.
*********************************************************************/
bool mergeExtensionDictionaries(OSDictionary * mergeInto,
    OSDictionary * mergeFrom) {

    bool result = true;
    OSDictionary * mergeIntoCopy = NULL;       // must release
    OSDictionary * mergeFromCopy = NULL;       // must release
    OSCollectionIterator * keyIterator = NULL; // must release
    OSString * key;                            // don't release

   /* Add 1 to count to guarantee copy can grow (grr).
    */
    mergeIntoCopy = OSDictionary::withDictionary(mergeInto,
        mergeInto->getCount() + 1);
    if (!mergeIntoCopy) {
        IOLog("Error: Failed to copy 'into' extensions dictionary "
            "for merge.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

   /* Add 1 to count to guarantee copy can grow (grr).
    */
    mergeFromCopy = OSDictionary::withDictionary(mergeFrom,
        mergeFrom->getCount() + 1);
    if (!mergeFromCopy) {
        IOLog("Error: Failed to copy 'from' extensions dictionary "
            "for merge.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    keyIterator = OSCollectionIterator::withCollection(mergeFrom);
    if (!keyIterator) {
        IOLog("Error: Failed to allocate iterator for extensions.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }


   /*****
    * Loop through "from" dictionary, checking if the identifier already
    * exists in the "into" dictionary and checking versions if it does.
    */
    while ((key = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
        OSDictionary * incumbentExt = OSDynamicCast(OSDictionary,
            mergeIntoCopy->getObject(key));
        OSDictionary * candidateExt = OSDynamicCast(OSDictionary,
            mergeFrom->getObject(key));

        if (!incumbentExt) {
            if (!mergeIntoCopy->setObject(key, candidateExt)) {

               /* This is a fatal error, so bail.
                */
                IOLog("mergeExtensionDictionaries(): Failed to add "
                    "identifier %s\n",
                    key->getCStringNoCopy());
                LOG_DELAY();
                result = false;
                goto finish;
            }
        } else {
            OSDictionary * mostRecentExtension =
                compareExtensionVersions(incumbentExt, candidateExt);

            if (mostRecentExtension == incumbentExt) {
                mergeFromCopy->removeObject(key);
            } else if (mostRecentExtension == candidateExt) {

                if (!mergeIntoCopy->setObject(key, candidateExt)) {

                   /* This is a fatal error, so bail.
                    */
                    IOLog("mergeExtensionDictionaries(): Failed to add "
                        "identifier %s\n",
                        key->getCStringNoCopy());
                    LOG_DELAY();
                    result = false;
                    goto finish;
                }
            } else /* should be NULL */ {
    
               /* This is a nonfatal error, so continue doing others.
                */
                IOLog("mergeExtensionDictionaries(): Error comparing "
                    "versions of duplicate extensions %s.\n",
                    key->getCStringNoCopy());
                LOG_DELAY();
                continue;
            }
        }
    }

finish:

   /* If successful, replace the contents of the original
    * dictionaries with those of the modified copies.
    */
    if (result) {
        mergeInto->flushCollection();
        mergeInto->merge(mergeIntoCopy);
        mergeFrom->flushCollection();
        mergeFrom->merge(mergeFromCopy);
    }

    if (mergeIntoCopy) mergeIntoCopy->release();
    if (mergeFromCopy) mergeFromCopy->release();
    if (keyIterator)   keyIterator->release();

    return result;
}


/****
 * These bits are used to parse data made available by bootx.
 */
#define BOOTX_KEXT_PREFIX       "Driver-"
#define BOOTX_MULTIKEXT_PREFIX  "DriversPackage-"

typedef struct MemoryMapFileInfo {
    UInt32 paddr;
    UInt32 length;
} MemoryMapFileInfo;

typedef struct BootxDriverInfo {
    char *plistAddr;
    long  plistLength;
    void *moduleAddr;
    long  moduleLength;
} BootxDriverInfo;

typedef struct MkextEntryInfo {
    vm_address_t  base_address;
    mkext_file  * fileinfo;
} MkextEntryInfo;


/*********************************************************************
* This private function reads the data for a single extension from
* the bootx memory-map's propery dict, returning a dictionary with
* keys "plist" for the extension's Info.plist as a parsed OSDictionary
* and "code" for the extension's executable code as an OSData.
*********************************************************************/
OSDictionary * readExtension(OSDictionary * propertyDict,
    const char * memory_map_name) {

    int error = 0;
    OSData               * bootxDriverDataObject = NULL;
    OSDictionary         * driverPlist = NULL;
    OSString             * driverName = NULL;
    OSData               * driverCode = NULL;
    OSString             * errorString = NULL;
    OSDictionary         * driverDict = NULL;

    MemoryMapFileInfo * driverInfo = 0;
    BootxDriverInfo * dataBuffer;

    kmod_info_t          * loaded_kmod = NULL;

    bootxDriverDataObject = OSDynamicCast(OSData,
        propertyDict->getObject(memory_map_name));
    // don't release bootxDriverDataObject

    if (!bootxDriverDataObject) {
        IOLog("Error: No driver data object "
            "for device tree entry \"%s\".\n",
            memory_map_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

    driverDict = OSDictionary::withCapacity(2);
    if (!driverDict) {
        IOLog("Error: Couldn't allocate dictionary "
            "for device tree entry \"%s\".\n", memory_map_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

    driverInfo = (MemoryMapFileInfo *)
        bootxDriverDataObject->getBytesNoCopy(0,
        sizeof(MemoryMapFileInfo));
#if defined (__ppc__)
    dataBuffer = (BootxDriverInfo *)ml_static_ptovirt(
      driverInfo->paddr);
#elif defined (__i386__)
    dataBuffer = (BootxDriverInfo *)driverInfo->paddr;
    dataBuffer->plistAddr = ml_static_ptovirt(dataBuffer->plistAddr);
    if (dataBuffer->moduleAddr)
      dataBuffer->moduleAddr = ml_static_ptovirt(dataBuffer->moduleAddr);
#else
#error unsupported architecture
#endif
    if (!dataBuffer) {
        IOLog("Error: No data buffer "
        "for device tree entry \"%s\".\n", memory_map_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

    driverPlist = OSDynamicCast(OSDictionary,
        OSUnserializeXML(dataBuffer->plistAddr, &errorString));
    if (!driverPlist) {
        IOLog("Error: Couldn't read XML property list "
            "for device tree entry \"%s\".\n", memory_map_name);
        LOG_DELAY();
        if (errorString) {
            IOLog("XML parse error: %s.\n",
                errorString->getCStringNoCopy());
            LOG_DELAY();
        }
        error = 1;
        goto finish;
    }


    driverName = OSDynamicCast(OSString,
        driverPlist->getObject("CFBundleIdentifier"));  // do not release
    if (!driverName) {
        IOLog("Error: Device tree entry \"%s\" has "
            "no \"CFBundleIdentifier\" property.\n", memory_map_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

   /* Check if kmod is already loaded and is a real loadable one (has
    * an address).
    */
    loaded_kmod = kmod_lookupbyname_locked(driverName->getCStringNoCopy());
    if (loaded_kmod && loaded_kmod->address) {
        IOLog("Skipping new extension \"%s\"; an extension named "
            "\"%s\" is already loaded.\n",
            driverName->getCStringNoCopy(),
            loaded_kmod->name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

    if (!validateExtensionDict(driverPlist, -1)) {
        // validateExtensionsDict() logs an error
        error = 1;
        goto finish;
    }

    driverDict->setObject("plist", driverPlist);

   /* It's perfectly okay for a KEXT to have no executable.
    * Check that moduleAddr is nonzero before attempting to
    * get one.
    *
    * NOTE: The driverCode object is created "no-copy", so
    * it doesn't own that memory. The memory must be freed
    * separately from the OSData object (see
    * clearStartupExtensionsAndLoaderInfo() at the end of this file).
    */
    if (dataBuffer->moduleAddr && dataBuffer->moduleLength) {
        driverCode = OSData::withBytesNoCopy(dataBuffer->moduleAddr,
            dataBuffer->moduleLength);
        if (!driverCode) {
            IOLog("Error: Couldn't allocate data object "
                "to hold code for device tree entry \"%s\".\n",
                memory_map_name);
            LOG_DELAY();
            error = 1;
            goto finish;
        }

        if (driverCode) {
            driverDict->setObject("code", driverCode);
        }
    }

finish:

    if (loaded_kmod) {
        kfree((unsigned int)loaded_kmod, sizeof(kmod_info_t));
    }

    // do not release bootxDriverDataObject
    // do not release driverName

    if (driverPlist) {
        driverPlist->release();
    }
    if (errorString) {
        errorString->release();
    }
    if (driverCode) {
        driverCode->release();
    }
    if (error) {
        if (driverDict) {
            driverDict->release();
            driverDict = NULL;
        }
    }
    return driverDict;
}


/*********************************************************************
* Used to uncompress a single file entry in an mkext archive.
*
* The OSData returned does not own its memory! You must deallocate
* that memory using kmem_free() before releasing the OSData().
*********************************************************************/
static bool uncompressFile(u_int8_t *base_address, mkext_file * fileinfo,
		           /* out */ OSData ** file) {

    bool result = true;
    kern_return_t kern_result;
    u_int8_t * uncompressed_file = 0; // kmem_free() on error
    OSData * uncompressedFile = 0;    // returned
    size_t uncompressed_size = 0;

    size_t offset = OSSwapBigToHostInt32(fileinfo->offset);
    size_t compsize = OSSwapBigToHostInt32(fileinfo->compsize);
    size_t realsize = OSSwapBigToHostInt32(fileinfo->realsize);
    time_t modifiedsecs = OSSwapBigToHostInt32(fileinfo->modifiedsecs);

    *file = 0;

   /* If these four fields are zero there's no file, but that isn't
    * an error.
    */
    if (offset == 0 && compsize == 0 &&
        realsize == 0 && modifiedsecs == 0) {
        goto finish;
    }

    // Add 1 for '\0' to terminate XML string!
    kern_result = kmem_alloc(kernel_map, (vm_offset_t *)&uncompressed_file,
        realsize + 1);
    if (kern_result != KERN_SUCCESS) {
        IOLog("Error: Couldn't allocate data buffer "
              "to uncompress file.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    uncompressedFile = OSData::withBytesNoCopy(uncompressed_file,
        realsize + 1);
    if (!uncompressedFile) {
        IOLog("Error: Couldn't allocate data object "
              "to uncompress file.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    if (compsize != 0) {
        uncompressed_size = decompress_lzss(uncompressed_file,
            base_address + offset,
            compsize);
        if (uncompressed_size != realsize) {
            IOLog("Error: Uncompressed file is not the length "
                  "recorded.\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }
        uncompressed_file[uncompressed_size] = '\0';
    } else {
        bcopy(base_address + offset, uncompressed_file,
            realsize);
        uncompressed_file[realsize] = '\0';
    }

    *file = uncompressedFile;

finish:
    if (!result) {
        if (uncompressed_file) {
            kmem_free(kernel_map, (vm_address_t)uncompressed_file,
                realsize + 1);
        }
        if (uncompressedFile) {
            uncompressedFile->release();
            *file = 0;
        }
    }
    return result;
}

bool uncompressModule(OSData *compData, /* out */ OSData ** file) {

    MkextEntryInfo *info = (MkextEntryInfo *) compData->getBytesNoCopy();

    return uncompressFile((u_int8_t *) info->base_address, 
			  info->fileinfo, file);
}


/*********************************************************************
* Does the work of pulling extensions out of an mkext archive located
* in memory.
*********************************************************************/
bool extractExtensionsFromArchive(MemoryMapFileInfo * mkext_file_info,
    OSDictionary * extensions) {

    bool result = true;

    u_int8_t     * crc_address = 0;
    u_int32_t      checksum;
    mkext_header * mkext_data = 0;   // don't free
    mkext_kext   * onekext_data = 0; // don't free
    mkext_file   * plist_file = 0;   // don't free
    mkext_file   * module_file = 0;  // don't free
    kmod_info_t  * loaded_kmod = 0;  // must free

    OSData       * driverPlistDataObject = 0; // must release
    OSDictionary * driverPlist = 0;  // must release
    OSData       * driverCode = 0;   // must release
    OSDictionary * driverDict = 0;   // must release
    OSString     * moduleName = 0;   // don't release
    OSString     * errorString = NULL;  // must release

    OSData         * moduleInfo = 0;  // must release
    MkextEntryInfo   module_info;


#if defined (__ppc__)
    mkext_data = (mkext_header *)mkext_file_info->paddr;
#elif defined (__i386__)
    mkext_data = (mkext_header *)ml_static_ptovirt(mkext_file_info->paddr);
#else
#error unsupported architecture
#endif
    if (OSSwapBigToHostInt32(mkext_data->magic) != MKEXT_MAGIC ||
        OSSwapBigToHostInt32(mkext_data->signature) != MKEXT_SIGN) {
        IOLog("Error: Extension archive has invalid magic or signature.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    if (OSSwapBigToHostInt32(mkext_data->length) != mkext_file_info->length) {
        IOLog("Error: Mismatch between extension archive & "
            "recorded length.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    crc_address = (u_int8_t *)&mkext_data->version;
    checksum = adler32(crc_address,
        (unsigned int)mkext_data +
        OSSwapBigToHostInt32(mkext_data->length) - (unsigned int)crc_address);

    if (OSSwapBigToHostInt32(mkext_data->adler32) != checksum) {
        IOLog("Error: Extension archive has a bad checksum.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

   /* If the MKEXT archive isn't fat, check that the CPU type & subtype
    * match that of the running kernel.
    */
    if (OSSwapBigToHostInt32(mkext_data->cputype) != (UInt32)CPU_TYPE_ANY) {
        kern_return_t          kresult = KERN_FAILURE;
        host_basic_info_data_t hostinfo;
        host_info_t            hostinfo_ptr = (host_info_t)&hostinfo;
        mach_msg_type_number_t count = sizeof(hostinfo)/sizeof(integer_t);

        kresult = host_info((host_t)1, HOST_BASIC_INFO,
            hostinfo_ptr, &count);
        if (kresult != KERN_SUCCESS) {
            IOLog("Error: Couldn't get current host info.\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }
        if ((UInt32)hostinfo.cpu_type !=
            OSSwapBigToHostInt32(mkext_data->cputype)) {

            IOLog("Error: Extension archive doesn't contain software "
                "for this computer's CPU type.\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }
        if (!grade_binary(OSSwapBigToHostInt32(mkext_data->cputype),
			  OSSwapBigToHostInt32(mkext_data->cpusubtype))) {
            IOLog("Error: Extension archive doesn't contain software "
                "for this computer's CPU subtype.\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }
    }

    for (unsigned int i = 0;
         i < OSSwapBigToHostInt32(mkext_data->numkexts);
         i++) {

        if (loaded_kmod) {
            kfree((unsigned int)loaded_kmod, sizeof(kmod_info_t));
            loaded_kmod = 0;
        }

        if (driverPlistDataObject) {
            kmem_free(kernel_map,
                (unsigned int)driverPlistDataObject->getBytesNoCopy(),
                driverPlistDataObject->getLength());

            driverPlistDataObject->release();
            driverPlistDataObject = NULL;
        }
        if (driverPlist) {
            driverPlist->release();
            driverPlist = NULL;
        }
        if (driverCode) {
            driverCode->release();
            driverCode = NULL;
        }
        if (driverDict) {
            driverDict->release();
            driverDict = NULL;
        }
        if (errorString) {
            errorString->release();
            errorString = NULL;
        }

        onekext_data = &mkext_data->kext[i];
        plist_file = &onekext_data->plist;
        module_file = &onekext_data->module;

        if (!uncompressFile((u_int8_t *)mkext_data, plist_file,
            &driverPlistDataObject)) {

            IOLog("Error: couldn't uncompress plist file "
                "from multikext archive entry %d.\n", i);
            LOG_DELAY();
            continue;
        }

        if (!driverPlistDataObject) {
            IOLog("Error: No property list present "
                "for multikext archive entry %d.\n", i);
            LOG_DELAY();
            continue;
        } else {
            driverPlist = OSDynamicCast(OSDictionary,
                OSUnserializeXML(
                    (char *)driverPlistDataObject->getBytesNoCopy(),
                    &errorString));
            if (!driverPlist) {
                IOLog("Error: Couldn't read XML property list "
                      "for multikext archive entry %d.\n", i);
                LOG_DELAY();
                if (errorString) {
                    IOLog("XML parse error: %s.\n",
                        errorString->getCStringNoCopy());
                    LOG_DELAY();
                }
                continue;
            }

            if (!validateExtensionDict(driverPlist, i)) {
                // validateExtensionsDict() logs an error
                continue;
            }

        }

       /* Get the extension's module name. This is used to record
        * the extension.
        */
        moduleName = OSDynamicCast(OSString,
            driverPlist->getObject("CFBundleIdentifier"));  // do not release
        if (!moduleName) {
            IOLog("Error: Multikext archive entry %d has "
                "no \"CFBundleIdentifier\" property.\n", i);
            LOG_DELAY();
            continue; // assume a kext config error & continue
        }

       /* Check if kmod is already loaded and is a real loadable one (has
        * an address).
        */
        loaded_kmod = kmod_lookupbyname_locked(moduleName->getCStringNoCopy());
        if (loaded_kmod && loaded_kmod->address) {
            IOLog("Skipping new extension \"%s\"; an extension named "
                "\"%s\" is already loaded.\n",
                moduleName->getCStringNoCopy(),
                loaded_kmod->name);
            continue;
        }


        driverDict = OSDictionary::withCapacity(2);
        if (!driverDict) {
            IOLog("Error: Couldn't allocate dictionary "
                  "for multikext archive entry %d.\n", i);
            LOG_DELAY();
            result = false;
            goto finish;
        }

        driverDict->setObject("plist", driverPlist);

       /*****
        * Prepare an entry to hold the mkext entry info for the
        * compressed binary module, if there is one. If all four fields
        * of the module entry are zero, there isn't one.
        */
        if (!(loaded_kmod && loaded_kmod->address) && (OSSwapBigToHostInt32(module_file->offset) ||
            OSSwapBigToHostInt32(module_file->compsize) ||
            OSSwapBigToHostInt32(module_file->realsize) ||
            OSSwapBigToHostInt32(module_file->modifiedsecs))) {

            moduleInfo = OSData::withCapacity(sizeof(MkextEntryInfo));
            if (!moduleInfo) {
                IOLog("Error: Couldn't allocate data object "
                      "for multikext archive entry %d.\n", i);
                LOG_DELAY();
                result = false;
                goto finish;
            }

            module_info.base_address = (vm_address_t)mkext_data;
            module_info.fileinfo = module_file;

            if (!moduleInfo->appendBytes(&module_info, sizeof(module_info))) {
                IOLog("Error: Couldn't record info "
                      "for multikext archive entry %d.\n", i);
                LOG_DELAY();
                result = false;
                goto finish;
            }

            driverDict->setObject("compressedCode", moduleInfo);
        }

        OSDictionary * incumbentExt = OSDynamicCast(OSDictionary,
            extensions->getObject(moduleName));

        if (!incumbentExt) {
            extensions->setObject(moduleName, driverDict);
        } else {
            OSDictionary * mostRecentExtension =
                compareExtensionVersions(incumbentExt, driverDict);

            if (mostRecentExtension == incumbentExt) {
                /* Do nothing, we've got the most recent. */
            } else if (mostRecentExtension == driverDict) {
                if (!extensions->setObject(moduleName, driverDict)) {

                   /* This is a fatal error, so bail.
                    */
                    IOLog("extractExtensionsFromArchive(): Failed to add "
                        "identifier %s\n",
                        moduleName->getCStringNoCopy());
                    LOG_DELAY();
                    result = false;
                    goto finish;
                }
            } else /* should be NULL */ {

               /* This is a nonfatal error, so continue.
                */
                IOLog("extractExtensionsFromArchive(): Error comparing "
                    "versions of duplicate extensions %s.\n",
                    moduleName->getCStringNoCopy());
                LOG_DELAY();
                continue;
            }
        }
    }

finish:

    if (loaded_kmod) kfree((unsigned int)loaded_kmod, sizeof(kmod_info_t));
    if (driverPlistDataObject) {
        kmem_free(kernel_map,
            (unsigned int)driverPlistDataObject->getBytesNoCopy(),
            driverPlistDataObject->getLength());
        driverPlistDataObject->release();
    }
    if (driverPlist) driverPlist->release();
    if (driverCode)  driverCode->release();
    if (moduleInfo)  moduleInfo->release();
    if (driverDict)  driverDict->release();
    if (errorString) errorString->release();

    return result;
}

/*********************************************************************
*
*********************************************************************/
bool readExtensions(OSDictionary * propertyDict,
    const char * memory_map_name,
    OSDictionary * extensions) {

    bool result = true;
    OSData * mkextDataObject = 0;      // don't release
    MemoryMapFileInfo * mkext_file_info = 0; // don't free

    mkextDataObject = OSDynamicCast(OSData,
        propertyDict->getObject(memory_map_name));
    // don't release mkextDataObject

    if (!mkextDataObject) {
        IOLog("Error: No mkext data object "
            "for device tree entry \"%s\".\n",
            memory_map_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    mkext_file_info = (MemoryMapFileInfo *)mkextDataObject->getBytesNoCopy();
    if (!mkext_file_info) {
        result = false;
        goto finish;
    }

    result = extractExtensionsFromArchive(mkext_file_info, extensions);

finish:

    if (!result && extensions) {
        extensions->flushCollection();
    }

    return result;
}


/*********************************************************************
* Adds the personalities for an extensions dictionary to the global
* IOCatalogue.
*********************************************************************/
bool addPersonalities(OSDictionary * extensions) {
    bool result = true;
    OSCollectionIterator * keyIterator = NULL;  // must release
    OSString             * key;          // don't release
    OSDictionary * driverDict = NULL;    // don't release
    OSDictionary * driverPlist = NULL;   // don't release
    OSDictionary * thisDriverPersonalities = NULL;  // don't release
    OSArray      * allDriverPersonalities = NULL;   // must release

    allDriverPersonalities = OSArray::withCapacity(1);
    if (!allDriverPersonalities) {
        IOLog("Error: Couldn't allocate personality dictionary.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

   /* Record all personalities found so that they can be
    * added to the catalogue.
    * Note: Not all extensions have personalities.
    */

    keyIterator = OSCollectionIterator::withCollection(extensions);
    if (!keyIterator) {
        IOLog("Error: Couldn't allocate iterator to record personalities.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    while ( ( key = OSDynamicCast(OSString,
              keyIterator->getNextObject() ))) {

        driverDict = OSDynamicCast(OSDictionary,
            extensions->getObject(key));
        driverPlist = OSDynamicCast(OSDictionary,
            driverDict->getObject("plist"));
        thisDriverPersonalities = OSDynamicCast(OSDictionary,
            driverPlist->getObject("IOKitPersonalities"));

        if (thisDriverPersonalities) {
            OSCollectionIterator * pIterator;
            OSString * locakKey;
            pIterator = OSCollectionIterator::withCollection(
                thisDriverPersonalities);
            if (!pIterator) {
                IOLog("Error: Couldn't allocate iterator "
                    "to record extension personalities.\n");
                LOG_DELAY();
                continue;
            }
            while ( (locakKey = OSDynamicCast(OSString,
                     pIterator->getNextObject())) ) {

                OSDictionary * personality = OSDynamicCast(
                    OSDictionary,
                    thisDriverPersonalities->getObject(locakKey));
                if (personality) {
                    allDriverPersonalities->setObject(personality);
                }
            }
            pIterator->release();
        }
    } /* extract personalities */


   /* Add all personalities found to the IOCatalogue,
    * but don't start matching.
    */
    gIOCatalogue->addDrivers(allDriverPersonalities, false);

finish:

    if (allDriverPersonalities) allDriverPersonalities->release();
    if (keyIterator) keyIterator->release();

    return result;
}


/*********************************************************************
* Called from IOCatalogue to add extensions from an mkext archive.
* This function makes a copy of the mkext object passed in because
* the device tree support code dumps it after calling us (indirectly
* through the IOCatalogue).
*********************************************************************/
bool addExtensionsFromArchive(OSData * mkextDataObject) {
    bool result = true;

    OSDictionary * startupExtensions = NULL;  // don't release
    OSArray      * bootLoaderObjects = NULL;  // don't release
    OSDictionary * extensions = NULL;         // must release
    MemoryMapFileInfo mkext_file_info;
    OSCollectionIterator * keyIterator = NULL;   // must release
    OSString             * key = NULL;           // don't release

    startupExtensions = getStartupExtensions();
    if (!startupExtensions) {
        IOLog("Can't record extension archive; there is no"
            " extensions dictionary.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    bootLoaderObjects = getBootLoaderObjects();
    if (! bootLoaderObjects) {
        IOLog("Error: Couldn't allocate array to hold temporary objects.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    extensions = OSDictionary::withCapacity(2);
    if (!extensions) {
        IOLog("Error: Couldn't allocate dictionary to unpack "
            "extension archive.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    mkext_file_info.paddr = (UInt32)mkextDataObject->getBytesNoCopy();
    mkext_file_info.length = mkextDataObject->getLength();

   /* Save the local mkext data object so that we can deallocate it later.
    */
    bootLoaderObjects->setObject(mkextDataObject);

    result = extractExtensionsFromArchive(&mkext_file_info, extensions);
    if (!result) {
        IOLog("Error: Failed to extract extensions from archive.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    result = mergeExtensionDictionaries(startupExtensions, extensions);
    if (!result) {
        IOLog("Error: Failed to merge new extensions into existing set.\n");
        LOG_DELAY();
        goto finish;
    }

    result = addPersonalities(extensions);
    if (!result) {
        IOLog("Error: Failed to add personalities for extensions extracted "
            "from archive.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

finish:

    if (!result) {
        IOLog("Error: Failed to record extensions from archive.\n");
        LOG_DELAY();
    } else {
        keyIterator = OSCollectionIterator::withCollection(
            extensions);

        if (keyIterator) {
            while ( (key = OSDynamicCast(OSString,
                     keyIterator->getNextObject())) ) {

                IOLog("Added extension \"%s\" from archive.\n",
                    key->getCStringNoCopy());
                LOG_DELAY();
            }
            keyIterator->release();
        }
    }

    if (extensions) extensions->release();

    return result;
}


/*********************************************************************
* This function builds dictionaries for the startup extensions
* put into memory by bootx, recording each in the startup extensions
* dictionary. The dictionary format is this:
*
* {
*     "plist" = (the extension's Info.plist as an OSDictionary)
*     "code"  = (an OSData containing the executable file)
* }
*
* This function returns true if any extensions were found and
* recorded successfully, or if there are no start extensions,
* and false if an unrecoverable error occurred. An error reading
* a single extension is not considered fatal, and this function
* will simply skip the problematic extension to try the next one.
*********************************************************************/

bool recordStartupExtensions(void) {
    bool result = true;
    OSDictionary         * startupExtensions = NULL; // must release
    OSDictionary         * existingExtensions = NULL; // don't release
    OSDictionary         * mkextExtensions = NULL;   // must release
    IORegistryEntry      * bootxMemoryMap = NULL;    // must release
    OSDictionary         * propertyDict = NULL;      // must release
    OSCollectionIterator * keyIterator = NULL;       // must release
    OSString             * key = NULL;               // don't release

    OSDictionary * newDriverDict = NULL;  // must release
    OSDictionary * driverPlist = NULL; // don't release

    struct section * infosect;
    struct section * symsect;
    unsigned int     prelinkedCount = 0;

    existingExtensions = getStartupExtensions();
    if (!existingExtensions) {
        IOLog("Error: There is no dictionary for startup extensions.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    startupExtensions = OSDictionary::withCapacity(1);
    if (!startupExtensions) {
        IOLog("Error: Couldn't allocate dictionary "
            "to record startup extensions.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    // --
    // add any prelinked modules as startup extensions

    infosect   = getsectbyname("__PRELINK", "__info");
    symsect    = getsectbyname("__PRELINK", "__symtab");
    if (infosect && infosect->addr && infosect->size 
     && symsect && symsect->addr && symsect->size) do
    {
	gIOPrelinkedModules = OSDynamicCast(OSArray,
	    OSUnserializeXML((const char *) infosect->addr, NULL));

	if (!gIOPrelinkedModules)
	    break;
	for( unsigned int idx = 0; 
		(propertyDict = OSDynamicCast(OSDictionary, gIOPrelinkedModules->getObject(idx)));
		idx++)
	{
	    enum { kPrelinkReservedCount = 4 };

           /* Get the extension's module name. This is used to record
            * the extension. Do *not* release the moduleName.
            */
            OSString * moduleName = OSDynamicCast(OSString,
                propertyDict->getObject("CFBundleIdentifier"));
            if (!moduleName) {
                IOLog("Error: Prelinked module entry has "
                    "no \"CFBundleIdentifier\" property.\n");
                LOG_DELAY();
                continue;
            }

           /* Add the kext, & its plist.
            */
	    newDriverDict = OSDictionary::withCapacity(4);
	    assert(newDriverDict);
	    newDriverDict->setObject("plist", propertyDict);
	    startupExtensions->setObject(moduleName, newDriverDict);
	    newDriverDict->release();

           /* Add the code if present.
            */
	    OSData * data = OSDynamicCast(OSData, propertyDict->getObject("OSBundlePrelink"));
            if (data) {
		if (data->getLength() < (kPrelinkReservedCount * sizeof(UInt32))) {
		    IOLog("Error: Prelinked module entry has "
			"invalid \"OSBundlePrelink\" property.\n");
		    LOG_DELAY();
		    continue;
		}
		UInt32 * prelink;
		prelink = (UInt32 *) data->getBytesNoCopy();
		kmod_info_t * kmod_info = (kmod_info_t *) OSReadBigInt32(prelink, 0);
		// end of "file" is end of symbol sect
		data = OSData::withBytesNoCopy((void *) kmod_info->address,
			    symsect->addr + symsect->size - kmod_info->address);
		newDriverDict->setObject("code", data);
		data->release();
		prelinkedCount++;
                continue;
            }
           /* Add the symbols if present.
            */
	    OSNumber * num = OSDynamicCast(OSNumber, propertyDict->getObject("OSBundlePrelinkSymbols"));
            if (num) {
		UInt32 offset = num->unsigned32BitValue();
		data = OSData::withBytesNoCopy((void *) (symsect->addr + offset), symsect->size - offset);
		newDriverDict->setObject("code", data);
		data->release();
		prelinkedCount++;
                continue;
	    }
	} 
	if (gIOPrelinkedModules)
	    IOLog("%d prelinked modules\n", prelinkedCount);

	// free __info
	vm_offset_t
	virt = ml_static_ptovirt(infosect->addr);
	if( virt) {
	    ml_static_mfree(virt, infosect->size);
	}
	newDriverDict = NULL;
    }
    while (false);
    // --

    bootxMemoryMap =
        IORegistryEntry::fromPath(
            "/chosen/memory-map", // path
            gIODTPlane            // plane
            );
    // return value is retained so be sure to release it

    if (!bootxMemoryMap) {
        IOLog("Error: Couldn't read booter memory map.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    propertyDict = bootxMemoryMap->dictionaryWithProperties();
    if (!propertyDict) {
        IOLog("Error: Couldn't get property dictionary "
            "from memory map.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    keyIterator = OSCollectionIterator::withCollection(propertyDict);
    if (!keyIterator) {
        IOLog("Error: Couldn't allocate iterator for driver images.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    while ( (key = OSDynamicCast(OSString,
             keyIterator->getNextObject())) ) {
       /* Clear newDriverDict & mkextExtensions upon entry to the loop,
        * handling both successful and unsuccessful iterations.
        */
        if (newDriverDict) {
            newDriverDict->release();
            newDriverDict = NULL;
        }
        if (mkextExtensions) {
            mkextExtensions->release();
            mkextExtensions = NULL;
        }

        const char * keyValue = key->getCStringNoCopy();

        if ( !strncmp(keyValue, BOOTX_KEXT_PREFIX,
              strlen(BOOTX_KEXT_PREFIX)) ) {

           /* Read the extension from the bootx-supplied memory.
            */
            newDriverDict = readExtension(propertyDict, keyValue);
            if (!newDriverDict) {
                IOLog("Error: Couldn't read data "
                    "for device tree entry \"%s\".\n", keyValue);
                LOG_DELAY();
                continue;
            }


           /* Preprare to record the extension by getting its info plist.
            */
            driverPlist = OSDynamicCast(OSDictionary,
                newDriverDict->getObject("plist"));
            if (!driverPlist) {
                IOLog("Error: Extension in device tree entry \"%s\" "
                    "has no property list.\n", keyValue);
                LOG_DELAY();
                continue;
            }


           /* Get the extension's module name. This is used to record
            * the extension. Do *not* release the moduleName.
            */
            OSString * moduleName = OSDynamicCast(OSString,
                driverPlist->getObject("CFBundleIdentifier"));
            if (!moduleName) {
                IOLog("Error: Device tree entry \"%s\" has "
                    "no \"CFBundleIdentifier\" property.\n", keyValue);
                LOG_DELAY();
                continue;
            }


           /* All has gone well so far, so record the extension under
            * its module name, checking for an existing duplicate.
            *
            * Do not release moduleName, as it's part of the extension's
            * plist.
            */
            OSDictionary * incumbentExt = OSDynamicCast(OSDictionary,
                startupExtensions->getObject(moduleName));

            if (!incumbentExt) {
                startupExtensions->setObject(moduleName, newDriverDict);
            } else {
                OSDictionary * mostRecentExtension =
                    compareExtensionVersions(incumbentExt, newDriverDict);

                if (mostRecentExtension == incumbentExt) {
                    /* Do nothing, we've got the most recent. */
                } else if (mostRecentExtension == newDriverDict) {
                    if (!startupExtensions->setObject(moduleName,
                         newDriverDict)) {

                       /* This is a fatal error, so bail.
                        */
                        IOLog("recordStartupExtensions(): Failed to add "
                            "identifier %s\n",
                            moduleName->getCStringNoCopy());
                        LOG_DELAY();
                        result = false;
                        goto finish;
                    }
                } else /* should be NULL */ {

                   /* This is a nonfatal error, so continue.
                    */
                    IOLog("recordStartupExtensions(): Error comparing "
                        "versions of duplicate extensions %s.\n",
                        moduleName->getCStringNoCopy());
                    LOG_DELAY();
                    continue;
                }
            }


        } else if ( !strncmp(keyValue, BOOTX_MULTIKEXT_PREFIX,
              strlen(BOOTX_MULTIKEXT_PREFIX)) ) {

            mkextExtensions = OSDictionary::withCapacity(10);
            if (!mkextExtensions) {
                IOLog("Error: Couldn't allocate dictionary to unpack "
                    "multi-extension archive.\n");
                LOG_DELAY();
                result = false;
                goto finish;  // allocation failure is fatal for this routine
            }
            if (!readExtensions(propertyDict, keyValue, mkextExtensions)) {
                IOLog("Error: Couldn't unpack multi-extension archive.\n");
                LOG_DELAY();
                continue;
            } else {
                if (!mergeExtensionDictionaries(startupExtensions,
                     mkextExtensions)) {

                    IOLog("Error: Failed to merge new extensions into "
                        "existing set.\n");
                    LOG_DELAY();
                    result = false;
                    goto finish;  // merge error is fatal for this routine
                }
            }
        }

        // Do not release key.

    } /* while ( (key = OSDynamicCast(OSString, ...) ) ) */

    if (!mergeExtensionDictionaries(existingExtensions, startupExtensions)) {
        IOLog("Error: Failed to merge new extensions into existing set.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    } 

    result = addPersonalities(startupExtensions);
    if (!result) {
        IOLog("Error: Failed to add personalities for extensions extracted "
            "from archive.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

finish:

    // reused so clear first!
    if (keyIterator) {
        keyIterator->release();
        keyIterator = 0;
    }

    if (!result) {
        IOLog("Error: Failed to record startup extensions.\n");
        LOG_DELAY();
    } else {
#if DEBUG
        keyIterator = OSCollectionIterator::withCollection(
            startupExtensions);

        if (keyIterator) {
            while ( (key = OSDynamicCast(OSString,
                     keyIterator->getNextObject())) ) {

                IOLog("Found extension \"%s\".\n",
                    key->getCStringNoCopy());
                LOG_DELAY();
            }
            keyIterator->release();
            keyIterator = 0;
        }
#endif /* DEBUG */
    }

    if (newDriverDict)     newDriverDict->release();
    if (propertyDict)      propertyDict->release();
    if (bootxMemoryMap)    bootxMemoryMap->release();
    if (mkextExtensions)   mkextExtensions->release();
    if (startupExtensions) startupExtensions->release();

    return result;
}


/*********************************************************************
* This function removes an entry from the dictionary of startup
* extensions. It's used when an extension can't be loaded, for
* whatever reason. For drivers, this allows another matching driver
* to be loaded, so that, for example, a driver for the root device
* can be found.
*********************************************************************/
void removeStartupExtension(const char * extensionName) {
    OSDictionary * startupExtensions = NULL;      // don't release
    OSDictionary * extensionDict = NULL;          // don't release
    OSDictionary * extensionPlist = NULL;         // don't release
    OSDictionary * extensionPersonalities = NULL; // don't release
    OSDictionary * personality = NULL;            // don't release
    OSCollectionIterator * keyIterator = NULL;    // must release
    OSString     * key = NULL;                    // don't release

    startupExtensions = getStartupExtensions();
    if (!startupExtensions) goto finish;


   /* Find the extension's entry in the dictionary of
    * startup extensions.
    */
    extensionDict = OSDynamicCast(OSDictionary,
        startupExtensions->getObject(extensionName));
    if (!extensionDict) goto finish;

    extensionPlist = OSDynamicCast(OSDictionary,
        extensionDict->getObject("plist"));
    if (!extensionPlist) goto finish;

    extensionPersonalities = OSDynamicCast(OSDictionary,
        extensionPlist->getObject("IOKitPersonalities"));
    if (!extensionPersonalities) goto finish;

   /* If it was there, remove it from the catalogue proper
    * by calling removeDrivers(). Pass true for the second
    * argument to trigger a new round of matching, and
    * then remove the extension from the dictionary of startup
    * extensions.
    */
    keyIterator = OSCollectionIterator::withCollection(
        extensionPersonalities);
    if (!keyIterator) {
        IOLog("Error: Couldn't allocate iterator to scan"
            " personalities for %s.\n", extensionName);
        LOG_DELAY();
    }

    while ((key = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
        personality = OSDynamicCast(OSDictionary,
            extensionPersonalities->getObject(key));


        if (personality) {
            gIOCatalogue->removeDrivers(personality, true);
        }
    }

    startupExtensions->removeObject(extensionName);

finish:

    if (keyIterator) keyIterator->release();
    return;
}

/*********************************************************************
* FIXME: This function invalidates the globals gStartupExtensions and
* FIXME: ...gBootLoaderObjects without setting them to NULL. Since
* FIXME: ...the code itself is immediately unloaded, there may not be
* FIXME: ...any reason to worry about that!
*********************************************************************/
void clearStartupExtensionsAndLoaderInfo(void)
{
    OSDictionary * startupExtensions = NULL;  // must release
    OSArray      * bootLoaderObjects = NULL;  // must release

    IORegistryEntry      * bootxMemoryMap = NULL;    // must release
    OSDictionary         * propertyDict = NULL;      // must release
    OSCollectionIterator * keyIterator = NULL;       // must release
    OSString             * key = NULL;               // don't release

   /*****
    * Drop any temporarily held data objects.
    */
    bootLoaderObjects = getBootLoaderObjects();
    if (bootLoaderObjects) {
        bootLoaderObjects->release();
    }

   /****
    * If any "code" entries in driver dictionaries are accompanied
    * by "compressedCode" entries, then those data objects were
    * created based of of kmem_alloc()'ed memory, which must be
    * freed specially.
    */
    startupExtensions = getStartupExtensions();
    if (startupExtensions) {
        keyIterator =
            OSCollectionIterator::withCollection(startupExtensions);
        if (!keyIterator) {
            IOLog("Error: Couldn't allocate iterator for startup "
                "extensions.\n");
            LOG_DELAY();
            goto memory_map;  // bail to the memory_map label
        }

        while ( (key = OSDynamicCast(OSString,
                 keyIterator->getNextObject())) ) {

            OSDictionary * driverDict = 0;
            OSData * codeData = 0;

            driverDict = OSDynamicCast(OSDictionary,
                startupExtensions->getObject(key));
            if (driverDict) {
                codeData = OSDynamicCast(OSData,
                    driverDict->getObject("code"));

                if (codeData &&
                    driverDict->getObject("compressedCode")) {

                    kmem_free(kernel_map,
                       (unsigned int)codeData->getBytesNoCopy(),
                        codeData->getLength());
                }
            }
        }

        keyIterator->release();
        startupExtensions->release();
    }

memory_map:

   /****
    * Go through the device tree's memory map and remove any driver
    * data entries.
    */
    bootxMemoryMap =
        IORegistryEntry::fromPath(
            "/chosen/memory-map", // path
            gIODTPlane            // plane
            );
    // return value is retained so be sure to release it

    if (!bootxMemoryMap) {
        IOLog("Error: Couldn't read booter memory map.\n");
        LOG_DELAY();
        goto finish;
    }

    propertyDict = bootxMemoryMap->dictionaryWithProperties();
    if (!propertyDict) {
        IOLog("Error: Couldn't get property dictionary "
            "from memory map.\n");
        LOG_DELAY();
        goto finish;
    }

    keyIterator = OSCollectionIterator::withCollection(propertyDict);
    if (!keyIterator) {
        IOLog("Error: Couldn't allocate iterator for driver images.\n");
        LOG_DELAY();
        goto finish;
    }

    while ( (key = OSDynamicCast(OSString,
             keyIterator->getNextObject())) ) {

        const char * keyValue = key->getCStringNoCopy();

        if ( !strncmp(keyValue, BOOTX_KEXT_PREFIX,
                  strlen(BOOTX_KEXT_PREFIX)) ||
             !strncmp(keyValue, BOOTX_MULTIKEXT_PREFIX,
                  strlen(BOOTX_MULTIKEXT_PREFIX)) ) {

            OSData            * bootxDriverDataObject = NULL;
            MemoryMapFileInfo * driverInfo = 0;

            bootxDriverDataObject = OSDynamicCast(OSData,
                propertyDict->getObject(keyValue));
            // don't release bootxDriverDataObject

            if (!bootxDriverDataObject) {
                continue;
            }
            driverInfo = (MemoryMapFileInfo *)
                bootxDriverDataObject->getBytesNoCopy(0,
                sizeof(MemoryMapFileInfo));
            IODTFreeLoaderInfo((char *)keyValue,
                (void *)driverInfo->paddr,
                (int)driverInfo->length);
        }
    }

finish:
    if (bootxMemoryMap) bootxMemoryMap->release();
    if (propertyDict)   propertyDict->release();
    if (keyIterator)    keyIterator->release();

    return;
}
