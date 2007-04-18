/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <libsa/kmod.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOLib.h>
#include <libsa/kmod.h>
#include <libsa/catalogue.h>

extern "C" {
#include <mach-o/kld.h>
#include <libsa/vers_rsrc.h>
#include <libsa/stdlib.h>
#include <mach/kmod.h>
#include <vm/vm_kern.h>
#include <mach/kern_return.h>
#include <mach-o/fat.h>
#include <mach_loader.h>
};

#include "kld_patch.h"


extern "C" {
extern kern_return_t
kmod_create_internal(
            kmod_info_t *info,
            kmod_t *id);

extern kern_return_t
kmod_destroy_internal(kmod_t id);

extern kern_return_t
kmod_start_or_stop(
    kmod_t id,
    int start,
    kmod_args_t *data,
    mach_msg_type_number_t *dataCount);

extern kern_return_t kmod_retain(kmod_t id);
extern kern_return_t kmod_release(kmod_t id);

extern void flush_dcache64(addr64_t addr, unsigned cnt, int phys);
extern void invalidate_icache64(addr64_t addr, unsigned cnt, int phys);
};


#define LOG_DELAY()

#define VTYELLOW	"\033[33m"
#define VTRESET		"\033[0m"




/*********************************************************************
*
*********************************************************************/
bool verifyCompatibility(OSString * extName, OSString * requiredVersion)
{
    OSDictionary * extensionsDict;   // don't release
    OSDictionary * extDict;          // don't release
    OSDictionary * extPlist;         // don't release
    OSString     * extVersion;       // don't release
    OSString     * extCompatVersion; // don't release
    UInt32 ext_version;
    UInt32 ext_compat_version;
    UInt32 required_version;

   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("verifyCompatibility(): No extensions dictionary.\n");
        return false;
    }

   /* Get the requested extension's dictionary entry and its property
    * list, containing module dependencies.
    */
    extDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(extName));

    if (!extDict) {
        IOLog("verifyCompatibility(): "
           "Extension \"%s\" cannot be found.\n",
           extName->getCStringNoCopy());
        return false;
    }

    extPlist = OSDynamicCast(OSDictionary, extDict->getObject("plist"));
    if (!extPlist) {
        IOLog("verifyCompatibility(): "
            "Extension \"%s\" has no property list.\n",
            extName->getCStringNoCopy());
        return false;
    }


    extVersion = OSDynamicCast(OSString,
        extPlist->getObject("CFBundleVersion"));
    if (!extVersion) {
        IOLog("verifyCompatibility(): "
            "Extension \"%s\" has no \"CFBundleVersion\" property.\n",
            extName->getCStringNoCopy());
        return false;
    }

    extCompatVersion = OSDynamicCast(OSString,
        extPlist->getObject("OSBundleCompatibleVersion"));
    if (!extCompatVersion) {
        IOLog("verifyCompatibility(): "
            "Extension \"%s\" has no \"OSBundleCompatibleVersion\" property.\n",
            extName->getCStringNoCopy());
        return false;
    }

    if (!VERS_parse_string(requiredVersion->getCStringNoCopy(),
         &required_version)) {
        IOLog("verifyCompatibility(): "
            "Can't parse required version \"%s\" of dependency %s.\n",
            requiredVersion->getCStringNoCopy(),
            extName->getCStringNoCopy());
        return false;
    }
    if (!VERS_parse_string(extVersion->getCStringNoCopy(),
         &ext_version)) {
        IOLog("verifyCompatibility(): "
            "Can't parse version \"%s\" of dependency %s.\n",
            extVersion->getCStringNoCopy(),
            extName->getCStringNoCopy());
        return false;
    }
    if (!VERS_parse_string(extCompatVersion->getCStringNoCopy(),
         &ext_compat_version)) {
        IOLog("verifyCompatibility(): "
            "Can't parse compatible version \"%s\" of dependency %s.\n",
            extCompatVersion->getCStringNoCopy(),
            extName->getCStringNoCopy());
        return false;
    }

    if (required_version > ext_version || required_version < ext_compat_version) {
        return false;
    }

    return true;
}

/*********************************************************************
*********************************************************************/
static
Boolean kextIsADependency(OSString * name) {
    Boolean result = true;
    OSDictionary * extensionsDict = 0;    // don't release
    OSDictionary * extDict = 0;           // don't release
    OSDictionary * extPlist = 0;          // don't release
    OSBoolean * isKernelResourceObj = 0;  // don't release
    OSData * driverCode = 0;              // don't release
    OSData * compressedCode = 0;          // don't release

    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("kextIsADependency(): No extensions dictionary.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }
    

    extDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(name));
    if (!extDict) {
        IOLog("kextIsADependency(): "
           "Extension \"%s\" cannot be found.\n",
           name->getCStringNoCopy());
        LOG_DELAY();
        result = false;
        goto finish;
    }

    extPlist = OSDynamicCast(OSDictionary, extDict->getObject("plist"));
    if (!extPlist) {
        IOLog("getDependencyListForKmod(): "
            "Extension \"%s\" has no property list.\n",
            name->getCStringNoCopy());
        LOG_DELAY();
        result = false;
        goto finish;
    }

   /* A kext that is a kernel component is still a dependency, as there
    * are fake kmod entries for them.
    */
    isKernelResourceObj = OSDynamicCast(OSBoolean,
        extPlist->getObject("OSKernelResource"));
    if (isKernelResourceObj && isKernelResourceObj->isTrue()) {
        result = true;
        goto finish;
    }

    driverCode = OSDynamicCast(OSData, extDict->getObject("code"));
    compressedCode = OSDynamicCast(OSData,
        extDict->getObject("compressedCode"));

    if (!driverCode && !compressedCode) {
        result = false;
        goto finish;
    }

finish:

    return result;
}

/*********************************************************************
* This function builds a uniqued, in-order list of modules that need
* to be loaded in order for kmod_name to be successfully loaded. This
* list ends with kmod_name itself.
*********************************************************************/
static
OSArray * getDependencyListForKmod(const char * kmod_name) {

    int error = 0;

    OSDictionary * extensionsDict; // don't release
    OSDictionary * extDict;        // don't release
    OSDictionary * extPlist;       // don't release
    OSString     * extName;        // don't release
    OSArray      * dependencyList = NULL; // return value, caller releases
    unsigned int   i;

   /* These are used to remove duplicates from the dependency list.
    */
    OSArray      * originalList = NULL;     // must be released
    OSDictionary * encounteredNames = NULL; // must be release


   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("getDependencyListForKmod(): No extensions dictionary.\n");
        LOG_DELAY();
        error = 1;
        goto finish;
    }
    

   /* Get the requested extension's dictionary entry and its property
    * list, containing module dependencies.
    */
    extDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(kmod_name));

    if (!extDict) {
        IOLog("getDependencyListForKmod(): "
           "Extension \"%s\" cannot be found.\n",
           kmod_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

    extPlist = OSDynamicCast(OSDictionary, extDict->getObject("plist"));
    if (!extPlist) {
        IOLog("getDependencyListForKmod(): "
            "Extension \"%s\" has no property list.\n",
            kmod_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }


   /* Verify that the retrieved entry's "CFBundleIdentifier" property exists.
    * This will be added to the dependency list.
    */
    extName = OSDynamicCast(OSString,
        extPlist->getObject("CFBundleIdentifier"));
    if (!extName) {
        IOLog("getDependencyListForKmod(): "
            "Extension \"%s\" has no \"CFBundleIdentifier\" property.\n",
            kmod_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }

    dependencyList = OSArray::withCapacity(10);
    if (!dependencyList) {
        IOLog("getDependencyListForKmod(): "
            "Couldn't allocate dependency array for extension \"%s\".\n",
            kmod_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }


   /* Okay, let's get started.
    */
    dependencyList->setObject(extName);


   /* Here's a slightly tricky bit. This loop iterates through
    * the dependency list until it runs off the end. Each time
    * through, however, any number of dependencies can be added
    * to the end of the list. Eventually some extensions won't
    * have any more dependencies, no more names will be added
    * to the list, and this loop will terminate.
    */
    for (i = 0; i < dependencyList->getCount(); i++) {

        // None of these needs to be released, as they're all from plists.
        OSString     * curName;
        OSDictionary * curExtDict;
        OSDictionary * curExtDepDict;
        OSDictionary * curExtPlist;
        OSString     * curDepName;


       /* An arbitrary limit to prevent infinite loops.
        */
        if (i > 255) {
            IOLog("getDependencyListForKmod(): "
                "max dependency list length exceeded for "
                "extension \"%s\".\n",
                kmod_name);
            LOG_DELAY();
            error = 1;
            goto finish;
        }

        curName = OSDynamicCast(OSString, dependencyList->getObject(i));

        curExtDict = OSDynamicCast(OSDictionary,
            extensionsDict->getObject(curName));
        if (!curExtDict) {
            IOLog("getDependencyListForKmod(): "
                "Extension \"%s\", required for extension \"%s\", "
                "is not available.\n",
                curName->getCStringNoCopy(), kmod_name);
            LOG_DELAY();
            error = 1;
            goto finish;
        }

        curExtPlist = OSDynamicCast(OSDictionary,
            curExtDict->getObject("plist"));
        if (!curExtPlist) {
            IOLog("getDependencyListForKmod(): "
                "Extension \"%s\", required for extension \"%s\", "
                "has no property list.\n",
                curName->getCStringNoCopy(), kmod_name);
            LOG_DELAY();
            error = 1;
            goto finish;
        }

        curExtDepDict = OSDynamicCast(OSDictionary,
              curExtPlist->getObject("OSBundleLibraries"));
        if (curExtDepDict) {
            OSCollectionIterator * keyIterator =
                OSCollectionIterator::withCollection(curExtDepDict);

            if (!keyIterator) {
                IOLog("getDependencyListForKmod(): "
                    "Couldn't allocate iterator for extension "
                    "\"%s\".\n", kmod_name);
                LOG_DELAY();
                error = 1;
                goto finish;
            }
            while ( (curDepName =
                     OSDynamicCast(OSString,
                         keyIterator->getNextObject())) ) {

                OSString * requiredVersion = OSDynamicCast(OSString,
                    curExtDepDict->getObject(curDepName));

                if (!verifyCompatibility(curDepName, requiredVersion)) {
                    IOLog("getDependencyListForKmod(): "
                        "Dependency %s of %s is not compatible or is unavailable.\n",
                        curDepName->getCStringNoCopy(),
                        curName->getCStringNoCopy());
                    LOG_DELAY();
                    error = 1;
                    goto finish;
                }

                dependencyList->setObject(curDepName);
            }

            keyIterator->release();
        }
    }


   /*****
    * The dependency list now exists in the reverse order of required loads,
    * and may have duplicates. Now we turn the list around and remove
    * duplicates.
    */
    originalList = dependencyList;
    dependencyList = OSArray::withCapacity(originalList->getCount());
    if (!dependencyList) {
        IOLog("getDependenciesForKmod(): "
              "Couldn't allocate reversal dependency list for extension "
              "\"%s\".\n", kmod_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }
    encounteredNames = OSDictionary::withCapacity(originalList->getCount());
    if (!encounteredNames) {
        IOLog("getDependenciesForKmod(): "
              "Couldn't allocate list of encountered names for extension "
              "\"%s\".\n", kmod_name);
        LOG_DELAY();
        error = 1;
        goto finish;
    }


   /* Go backward through the original list, using the encounteredNames
    * dictionary to check for duplicates. We put originalList in as the
    * value because we need some non-NULL value. Here we also drop any
    * extensions that aren't proper dependencies (that is, any that are
    * nonkernel kexts without code).
    */
    i = originalList->getCount();

    if (i > 0) {
        do {
            i--;

            OSString * item = OSDynamicCast(OSString,
                originalList->getObject(i));

            if ( (!encounteredNames->getObject(item)) &&
                 kextIsADependency(item)) {

                encounteredNames->setObject(item, originalList);
                dependencyList->setObject(item);
            }
        } while (i > 0);
    }


finish:

    if (originalList) {
        originalList->release();
    }
    if (encounteredNames) {
        encounteredNames->release();
    }
    if (error) {
        if (dependencyList) {
            dependencyList->release();
            dependencyList = NULL;
        }
    }

    return dependencyList;
}


/*********************************************************************
*********************************************************************/
/* Used in address_for_loaded_kmod.
 */
static kmod_info_t * g_current_kmod_info = NULL;
static const char * g_current_kmod_name = NULL;

/* Globals to pass link buffer info from
 * address_for_loaded_kmod() and alloc_for_kmod()
 * to load_kmod().
 *
 * link_load_address is the address used to lay
 * down the linked code. It gets adjusted by the
 * pad between the headers size and a full page
 * multiple. If an error occurs this gets set to
 * zero so that the kld client code can detect
 * an address or allocation error even if kld
 * returns success.
 *
 * link_load_size is the size of the image as
 * created by kld_load_from_memory(). link_buffer_size
 * is the size of the buffer allocated for the final
 * laid-down image, and is adjusted by rounding the
 * load size and header size up to full-page multiples.
 *
 * link_buffer_address is set only by alloc_for_kmod();
 * its value is used as a check if kld_load_from_memory()
 * fails so that the buffer can be deallocated. 
 */
static unsigned long link_load_address = 0;
static unsigned long link_load_size = 0;
static unsigned long link_buffer_size = 0;
static unsigned long link_header_size = 0;
static unsigned long link_buffer_address = 0;


/*********************************************************************
* This function is registered before kmod_load_from_memory() is
* invoked to build symbol table entries for an already-loaded
* kmod. This function just checks the g_current_kmod_info variable
* to gets its load address, and futzes it by the header offset (pad).
* See lower comments for more info on load address futzing.
*********************************************************************/
static
unsigned long address_for_loaded_kmod(
    unsigned long size,
    unsigned long headers_size) {

    unsigned long round_headers_size;
    unsigned long headers_pad;

    if (!g_current_kmod_info) {
        IOLog("address_for_loaded_kmod(): No current kmod.\n");
        LOG_DELAY();
        link_load_address = 0;  // error sentinel for kld client
        return 0;
    }

    round_headers_size = round_page_32(headers_size);
    headers_pad = round_headers_size - headers_size;

    link_load_address = (unsigned long)g_current_kmod_info->address +
        headers_pad;

    return link_load_address;
}


/*********************************************************************
* This function is registered before kmod_load_from_memory() is
* invoked to actually load a new kmod. It rounds up the header and
* total sizes and vm_allocates a buffer for the kmod. Now, KLD doesn't
* enforce any alignment of headers or segments, and we want to make
* sure that the executable code of the kmod lies on a page boundary.
* to do so, this function figures the pad between the actual header
* size and the page-rounded header size, and returns that offset into
* the allocated buffer. After kmod_load_from_memory() returns, its
* caller will move the mach_header struct back to the beginning of the
* allocated buffer so that the kmod_info_t structure contains the
* correct address.
*********************************************************************/
static
unsigned long alloc_for_kmod(
    unsigned long size,
    unsigned long headers_size) {

    vm_address_t  buffer = 0;
    kern_return_t k_result;

    unsigned long round_headers_size;
    unsigned long round_segments_size;
    unsigned long round_size;
    unsigned long headers_pad;

    round_headers_size  = round_page_32(headers_size);
    round_segments_size = round_page_32(size - headers_size);
    round_size  = round_headers_size + round_segments_size;
    headers_pad = round_headers_size - headers_size;

    k_result = vm_allocate(kernel_map, (vm_offset_t *)&buffer,
        round_size, VM_FLAGS_ANYWHERE);
    if (k_result != KERN_SUCCESS) {
        IOLog("alloc_for_kmod(): Can't allocate memory.\n");
        LOG_DELAY();
        link_buffer_address = 0;  // make sure it's clear
        link_load_address = 0;    // error sentinel for kld client
        return 0;
    }

    link_load_size = size;

    link_buffer_address = buffer;
    link_buffer_size = round_size;
    link_header_size = headers_size; // NOT rounded!

    link_load_address = link_buffer_address + headers_pad;

    return link_load_address;
}

/*********************************************************************
* This function reads the startup extensions dictionary to get the
* address and length of the executable data for the requested kmod.
*********************************************************************/
static
int map_and_patch(const char * kmod_name) {

    char *address;

    // Does the kld system already know about this kmod?
    address = (char *) kld_file_getaddr(kmod_name, NULL);
    if (address)
	return 1;

    // None of these needs to be released.
    OSDictionary * extensionsDict;
    OSDictionary * kmodDict;
    OSData * compressedCode = 0;

    // Driver Code may need to be released
    OSData * driverCode;

   /* Get the requested kmod's info dictionary from the global
    * startup extensions dictionary.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("map_and_patch(): No extensions dictionary.\n");
        LOG_DELAY();
        return 0;
    }
    
    kmodDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(kmod_name));
    if (!kmodDict) {
        IOLog("map_and_patch(): "
            "Extension \"%s\" cannot be found.\n", kmod_name);
        LOG_DELAY();
        return 0;
    }

    Boolean ret = false;

    driverCode = OSDynamicCast(OSData, kmodDict->getObject("code"));
    if (driverCode) {
	ret =  kld_file_map(kmod_name,
			    (unsigned char *) driverCode->getBytesNoCopy(),
			    (size_t) driverCode->getLength(),
			    /* isKmem */ false);
    }
    else {	// May be an compressed extension

	// If we have a compressed segment the uncompressModule
	// will return a new OSData object that points to the kmem_alloced
	// memory.  Note we don't take a reference to driverCode so later
	// when we release it we will actually free this driver.  Ownership
	// of the kmem has been handed of to kld_file.
	compressedCode = OSDynamicCast(OSData,
	    kmodDict->getObject("compressedCode"));
	if (!compressedCode) {
	    IOLog("map_and_patch(): "
		 "Extension \"%s\" has no \"code\" property.\n", kmod_name);
	    LOG_DELAY();
	    return 0;
	}
	if (!uncompressModule(compressedCode, &driverCode)) {
	    IOLog("map_and_patch(): "
		 "Extension \"%s\" Couldn't uncompress code.\n", kmod_name);
	    LOG_DELAY();
	    return 0;
	}

	unsigned char *driver = (unsigned char *) driverCode->getBytesNoCopy();
	size_t driverSize = driverCode->getLength();

	ret =  kld_file_map(kmod_name, driver, driverSize, /* isKmem */ true);
	driverCode->release();
	if (!ret)
	    kmem_free(kernel_map, (vm_address_t) driver, driverSize);
    }

    if (!ret) {
        IOLog("map_and_patch(): "
              "Extension \"%s\" Didn't successfully load.\n", kmod_name);
        LOG_DELAY();
	return 0;
    }

    ret = TRUE;
    if (!kld_file_patch_OSObjects(kmod_name)) {
        IOLog("map_and_patch(): "
              "Extension \"%s\" Error binding OSObjects.\n", kmod_name);
        LOG_DELAY();
        
        // RY: Instead of returning here, set the return value.
        // We still need to call kld_file_prepare_for_link because
        // we might have patched files outside of the driver.  Don't
        // worry, it will know to ignore the damaged file
        ret = FALSE;
    }

    // Now repair any damage that the kld patcher may have done to the image
    kld_file_prepare_for_link();

    return ret;
}

/*********************************************************************
*********************************************************************/
bool stamp_kmod(const char * kmod_name, kmod_info_t * kmod_info) {
    bool result = false;
    OSDictionary * extensionsDict = NULL;  // don't release
    OSDictionary * kmodDict = NULL;        // don't release
    OSDictionary * plist = NULL;           // don't release
    OSString     * versionString = NULL;   // don't release
    const char   * plist_version = NULL;   // don't free

    if (strlen(kmod_name) + 1 > KMOD_MAX_NAME) {
        IOLog("stamp_kmod(): Kext identifier \"%s\" is too long.\n",
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    strcpy(kmod_info->name, kmod_name);

   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("stamp_kmod(): No extensions dictionary.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    kmodDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(kmod_name));
    if (!kmodDict) {
        IOLog("stamp_kmod(): Can't find record for kmod \"%s\".\n",
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    plist = OSDynamicCast(OSDictionary,
        kmodDict->getObject("plist"));
    if (!kmodDict) {
        IOLog("stamp_kmod(): Kmod \"%s\" has no property list.\n",
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

   /*****
    * Get the kext's version and stuff it into the kmod. This used
    * to be a check that the kext & kmod had the same version, but
    * now we just overwrite the kmod's version.
    */

    versionString = OSDynamicCast(OSString,
        plist->getObject("CFBundleVersion"));
    if (!versionString) {
        IOLog("stamp_kmod(): Kmod \"%s\" has no \"CFBundleVersion\" "
            "property.\n",
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    plist_version = versionString->getCStringNoCopy();
    if (!plist_version) {
        IOLog("stamp_kmod(): Can't get C string for kext version.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    if (strlen(plist_version) + 1 > KMOD_MAX_NAME) {
        IOLog("stamp_kmod(): Version \"%s\" of kext \"%s\" is too long.\n",
            plist_version, kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    strcpy(kmod_info->version, plist_version);

    result = true;

finish:

    return result;
}


/*********************************************************************
* This function takes a dependency list containing a series of
* already-loaded module names, followed by a single name for a module
* that hasn't yet been loaded. It invokes kld_load_from_memory() to
* build symbol info for the already-loaded modules, and then finally
* loads the actually requested module.
*********************************************************************/
static
kern_return_t load_kmod(OSArray * dependencyList) {
    kern_return_t result = KERN_SUCCESS;

    unsigned int  num_dependencies = 0;
    kmod_info_t ** kmod_dependencies = NULL;
    unsigned int  i;
    OSString    * requestedKmodName;   // don't release
    const char  * requested_kmod_name;
    OSString    * currentKmodName;     // don't release
    char        * kmod_address;
    unsigned long kmod_size;
    struct mach_header * kmod_header;
    unsigned long kld_result;
    int           do_kld_unload = 0;
    kmod_info_t * kmod_info_freeme = 0;
    kmod_info_t * kmod_info = 0;
    kmod_t        kmod_id;


   /* Separate the requested kmod from its dependencies.
    */
    i = dependencyList->getCount();
    if (i == 0) {
        IOLog("load_kmod(): Called with empty list.\n");
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    } else {
        i--;  // make i be the index of the last entry
    }

    requestedKmodName = OSDynamicCast(OSString, dependencyList->getObject(i));
    if (!requestedKmodName) {
        IOLog("load_kmod(): Called with invalid list of kmod names.\n");
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }
    requested_kmod_name = requestedKmodName->getCStringNoCopy();
    dependencyList->removeObject(i);

   /* If the requested kmod is already loaded, there's no work to do.
    */
    kmod_info_freeme = kmod_lookupbyname_locked(requested_kmod_name);
    if (kmod_info_freeme) {
        // FIXME: Need to check for version mismatch if already loaded.
        result = KERN_SUCCESS;
        goto finish;
    }


   /* Do the KLD loads for the already-loaded modules in order to get
    * their symbols.
    */
    kld_address_func(&address_for_loaded_kmod);

    num_dependencies = dependencyList->getCount();
    kmod_dependencies = (kmod_info_t **)kalloc(num_dependencies *
        sizeof(kmod_info_t *));
    if (!kmod_dependencies) {
        IOLog("load_kmod(): Failed to allocate memory for dependency array "
            "during load of kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }

    bzero(kmod_dependencies, num_dependencies *
        sizeof(kmod_info_t *));

    for (i = 0; i < num_dependencies; i++) {

        currentKmodName = OSDynamicCast(OSString,
            dependencyList->getObject(i));

        if (!currentKmodName) {
            IOLog("load_kmod(): Invalid dependency name at index %d for "
                "kmod \"%s\".\n", i, requested_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        }

        const char * current_kmod_name = currentKmodName->getCStringNoCopy();

        // These globals are needed by the kld_address functions
        g_current_kmod_info = kmod_lookupbyname_locked(current_kmod_name);
        g_current_kmod_name = current_kmod_name;

        if (!g_current_kmod_info) {
            IOLog("load_kmod(): Missing dependency \"%s\".\n",
                current_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        }

       /* Record the current kmod as a dependency of the requested
        * one. This will be used in building references after the
        * load is complete.
        */
        kmod_dependencies[i] = g_current_kmod_info;

        /* If the current kmod's size is zero it means that we have a
         * fake in-kernel dependency.  If so then don't have to arrange
         * for its symbol table to be reloaded as it is
         * part of the kernel's symbol table..
         */ 
        if (!g_current_kmod_info->size)
            continue;

	if (!kld_file_merge_OSObjects(current_kmod_name)) {
            IOLog("load_kmod(): Can't merge OSObjects \"%s\".\n",
		current_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        }

	kmod_address = (char *)
	    kld_file_getaddr(current_kmod_name, (long *) &kmod_size);
        if (!kmod_address) {

            IOLog("load_kmod() failed for dependency kmod "
                "\"%s\".\n", current_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        }

        kld_result = kld_load_from_memory(&kmod_header,
            current_kmod_name, kmod_address, kmod_size);

        if (kld_result) {
            do_kld_unload = 1;
        }

        if (!kld_result || !link_load_address) {
            IOLog("kld_load_from_memory() failed for dependency kmod "
                "\"%s\".\n", current_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        }

        kld_forget_symbol("_kmod_info");
    }

   /*****
    * Now that we've done all the dependencies, which should have already
    * been loaded, we do the last requested module, which should not have
    * already been loaded.
    */
    kld_address_func(&alloc_for_kmod);

    g_current_kmod_name = requested_kmod_name;
    g_current_kmod_info = 0;  // there is no kmod yet

    if (!map_and_patch(requested_kmod_name)) {
	IOLog("load_kmod: map_and_patch() failed for "
	    "kmod \"%s\".\n", requested_kmod_name);
	LOG_DELAY();
	result = KERN_FAILURE;
	goto finish;
    }

    kmod_address = (char *)
	kld_file_getaddr(requested_kmod_name, (long *) &kmod_size);
    if (!kmod_address) {
        IOLog("load_kmod: kld_file_getaddr()  failed internal error "
            "on \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }

    kld_result = kld_load_from_memory(&kmod_header,
			    requested_kmod_name, kmod_address, kmod_size);

    if (kld_result) {
        do_kld_unload = 1;
    }

    if (!kld_result || !link_load_address) {
        IOLog("load_kmod(): kld_load_from_memory() failed for "
            "kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }


   /* Copy the linked header and image into the vm_allocated buffer.
    * Move each onto the appropriate page-aligned boundary as given
    * by the global link_... variables.
    */
    bzero((char *)link_buffer_address, link_buffer_size);
    // bcopy() is (from, to, length)
    bcopy((char *)kmod_header, (char *)link_buffer_address, link_header_size);
    bcopy((char *)kmod_header + link_header_size,
        (char *)link_buffer_address + round_page_32(link_header_size),
        link_load_size - link_header_size);


   /* Get the kmod_info struct for the newly-loaded kmod.
    */
    if (!kld_lookup("_kmod_info", (unsigned long *)&kmod_info)) {
        IOLog("kld_lookup() of \"_kmod_info\" failed for "
            "kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }


    if (!stamp_kmod(requested_kmod_name, kmod_info)) {
        // stamp_kmod() logs a meaningful message
        result = KERN_FAILURE;
        goto finish;
    }


   /* kld_lookup of _kmod_info yielded the actual linked address,
    * so now that we've copied the data into its real place,
    * we can set this stuff.
    */
    kmod_info->address = link_buffer_address;
    kmod_info->size = link_buffer_size;
    kmod_info->hdr_size = round_page_32(link_header_size);

   /* We've written data and instructions, so *flush* the data cache
    * and *invalidate* the instruction cache.
    */
    flush_dcache64((addr64_t)link_buffer_address, link_buffer_size, false);
    invalidate_icache64((addr64_t)link_buffer_address, link_buffer_size, false);


   /* Register the new kmod with the kernel proper.
    */
    if (kmod_create_internal(kmod_info, &kmod_id) != KERN_SUCCESS) {
        IOLog("load_kmod(): kmod_create() failed for "
            "kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }

#if DEBUG
    IOLog("kmod id %d successfully created at 0x%lx, size %ld.\n",
        (unsigned int)kmod_id, link_buffer_address, link_buffer_size);
    LOG_DELAY();
#endif /* DEBUG */

   /* Record dependencies for the newly-loaded kmod.
    */
    for (i = 0; i < num_dependencies; i++) {
        kmod_info_t * cur_dependency_info;
        kmod_t packed_id;
        cur_dependency_info = kmod_dependencies[i];
        packed_id = KMOD_PACK_IDS(kmod_id, cur_dependency_info->id);
        if (kmod_retain(packed_id) != KERN_SUCCESS) {
            IOLog("load_kmod(): kmod_retain() failed for "
                "kmod \"%s\".\n", requested_kmod_name);
            LOG_DELAY();
            kmod_destroy_internal(kmod_id);
            result = KERN_FAILURE;
            goto finish;
        }
    }

   /* Start the kmod (which invokes constructors for I/O Kit
    * drivers.
    */
    // kmod_start_or_stop(id, start?, user data, datalen)
    if (kmod_start_or_stop(kmod_id, 1, 0, 0) != KERN_SUCCESS) {
        IOLog("load_kmod(): kmod_start_or_stop() failed for "
            "kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        kmod_destroy_internal(kmod_id);
        result = KERN_FAILURE;
        goto finish;
    }

finish:

    if (kmod_info_freeme) {
        kfree((unsigned int)kmod_info_freeme, sizeof(kmod_info_t));
    }

   /* Only do a kld_unload_all() if at least one load happened.
    */
    if (do_kld_unload) {
        kld_unload_all(/* deallocate sets */ 1);
    }

   /* If the link failed, blow away the allocated link buffer.
    */
    if (result != KERN_SUCCESS && link_buffer_address) {
        vm_deallocate(kernel_map, link_buffer_address, link_buffer_size);
    }

    if (kmod_dependencies) {
        for (i = 0; i < num_dependencies; i++) {
            if (kmod_dependencies[i]) {
                kfree((unsigned int)kmod_dependencies[i], sizeof(kmod_info_t));
            }
        }
        kfree((unsigned int)kmod_dependencies,
            num_dependencies * sizeof(kmod_info_t *));
    }

   /* Reset these static global variables for the next call.
    */
    g_current_kmod_name = NULL;
    g_current_kmod_info = NULL;
    link_buffer_address = 0;
    link_load_address = 0;
    link_load_size = 0;
    link_buffer_size = 0;
    link_header_size = 0;

    return result;
}


/*********************************************************************
* This is the function that IOCatalogue calls in order to load a kmod.
* It first checks whether the kmod is already loaded. If the kmod
* isn't loaded, this function builds a dependency list and calls
* load_kmod() repeatedly to guarantee that each dependency is in fact
* loaded.
*********************************************************************/
__private_extern__
kern_return_t load_kernel_extension(char * kmod_name) {
    kern_return_t result = KERN_SUCCESS;
    kmod_info_t * kmod_info = 0;  // must free
    OSArray * dependencyList = NULL;     // must release
    OSArray * curDependencyList = NULL;  // must release

   /* See if the kmod is already loaded.
    */
    kmod_info = kmod_lookupbyname_locked(kmod_name);
    if (kmod_info) {  // NOT checked
        result = KERN_SUCCESS;
        goto finish;
    }

   /* It isn't loaded; build a dependency list and
    * load those.
    */
    unsigned int count;
    unsigned int i;
    dependencyList = getDependencyListForKmod(kmod_name);
    if (!dependencyList) {
        IOLog("load_kernel_extension(): "
            "Can't get dependencies for kernel extension \"%s\".\n",
            kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }

    count = dependencyList->getCount();
    for (i = 0; i < count; i++) {
        kern_return_t load_result;
        OSString * curKmodName;  // don't release
        const char * cur_kmod_name;

        curKmodName = OSDynamicCast(OSString,
            dependencyList->getObject(i));
        cur_kmod_name = curKmodName->getCStringNoCopy();
        curDependencyList = getDependencyListForKmod(cur_kmod_name);
        if (!curDependencyList) {
            IOLog("load_kernel_extension(): "
                "Can't get dependencies for kernel extension \"%s\".\n",
                cur_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        } else {
            load_result = load_kmod(curDependencyList);
            if (load_result != KERN_SUCCESS) {
                IOLog("load_kernel_extension(): "
                    "load_kmod() failed for kmod \"%s\".\n",
                    cur_kmod_name);
                LOG_DELAY();
                result = load_result;
                goto finish;
            }
            curDependencyList->release();
            curDependencyList = NULL;
        }
    }


finish:

    if (kmod_info) {
        kfree((unsigned int)kmod_info, sizeof(kmod_info_t));
    }

    if (dependencyList) {
        dependencyList->release();
        dependencyList = NULL;
    }
    if (curDependencyList) {
        curDependencyList->release();
        curDependencyList = NULL;
    }

    return result;
}
