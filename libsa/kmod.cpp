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


extern "C" {
extern load_return_t fatfile_getarch(
    void            * vp,       // normally a (struct vnode *)
    vm_offset_t       data_ptr,
    struct fat_arch * archret);

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

extern void flush_dcache(vm_offset_t addr, unsigned cnt, int phys);
extern void invalidate_icache(vm_offset_t addr, unsigned cnt, int phys);
};


IOLock * kld_lock;


#define LOG_DELAY()

#define VTYELLOW   "\033[33m"
#define VTRESET    "\033[0m"


/*********************************************************************
* This function builds a uniqued, in-order list of modules that need
* to be loaded in order for kmod_name to be successfully loaded. This
* list ends with kmod_name itself.
*********************************************************************/
static
OSArray * getDependencyListForKmod(char * kmod_name) {

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
    * value because we need some non-NULL value.
    */
    i = originalList->getCount();

    if (i > 0) {
        do {
            i--;

            OSString * item = OSDynamicCast(OSString,
                originalList->getObject(i));

            if ( ! encounteredNames->getObject(item) ) {
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
static bool verifyCompatibleVersions(OSArray * dependencyList) {
    bool result = true;

    OSString * requestedModuleName = NULL;

    OSDictionary * extensionsDict = NULL;
    int count, i;
    OSString * curName = NULL;
    OSDictionary * curExt = NULL;
    OSDictionary * curExtPlist = NULL;

    OSBoolean * isKernelResource = NULL;

    OSDictionary * dependencies = NULL;
    OSCollectionIterator * dependencyIterator = NULL; // must release
    OSString * dependencyName = NULL;
    OSString * curExtDependencyVersion = NULL;
    UInt32 cur_ext_required_dependency_vers;

    OSDictionary * dependency = NULL;
    OSDictionary * dependencyPlist = NULL;

    OSString * dependencyVersion = NULL;
    OSString * dependencyCompatibleVersion = NULL;
    UInt32 dependency_vers;
    UInt32 dependency_compat_vers;


   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("verifyCompatibleVersions(): No extensions dictionary.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }
    

    count = dependencyList->getCount();
    if (!count) {
        IOLog("verifyCompatibleVersions(): "
            "Invoked with no dependency list.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    requestedModuleName = OSDynamicCast(OSString,
        dependencyList->getObject(count - 1));

    for (i = count - 1; i >= 0; i--) {

        if (dependencyIterator) {
            dependencyIterator->release();
            dependencyIterator = NULL;
        }

        curName = OSDynamicCast(OSString, dependencyList->getObject(i));
        if (!curName) {
            IOLog("verifyCompatibleVersions(): Internal error (1).\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }

        curExt = OSDynamicCast(OSDictionary,
            extensionsDict->getObject(curName));
        if (!curExt) {
            IOLog("verifyCompatibleVersions(): Internal error (2).\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }

        curExtPlist = OSDynamicCast(OSDictionary,
            curExt->getObject("plist"));
        if (!curExtPlist) {
            IOLog("verifyCompatibleVersions(): Internal error (3).\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }


       /* In-kernel extensions don't need to check dependencies.
        */
        isKernelResource = OSDynamicCast(OSBoolean,
            curExtPlist->getObject("OSKernelResource"));
        if (isKernelResource && isKernelResource->isTrue()) {
            continue;
        }

        dependencies = OSDynamicCast(OSDictionary,
            curExtPlist->getObject("OSBundleLibraries"));
        if (!dependencies || dependencies->getCount() < 1) {
            IOLog(VTYELLOW "verifyCompatibleVersions(): Extension \"%s\" "
                "declares no dependencies.\n" VTRESET,
                curName->getCStringNoCopy());
            LOG_DELAY();
            result = false;
            goto finish;
        }

        dependencyIterator =
            OSCollectionIterator::withCollection(dependencies);
        if (!curExtPlist) {
            IOLog("verifyCompatibleVersions(): Internal error (4).\n");
            LOG_DELAY();
            result = false;
            goto finish;
        }

        while ((dependencyName = OSDynamicCast(OSString,
            dependencyIterator->getNextObject()))) {

            curExtDependencyVersion = OSDynamicCast(OSString,
                dependencies->getObject(dependencyName));
            if (!curExtDependencyVersion) {
                IOLog("verifyCompatibleVersions(): Internal error (5).\n");
                LOG_DELAY();
                result = false;
                goto finish;
            }

            dependency = OSDynamicCast(OSDictionary,
                extensionsDict->getObject(dependencyName));
            if (!dependency) {
                IOLog("verifyCompatibleVersions(): Internal error (6).\n");
                LOG_DELAY();
                result = false;
                goto finish;
            }

            dependencyPlist = OSDynamicCast(OSDictionary,
                dependency->getObject("plist"));
            if (!dependencyPlist) {
                IOLog("verifyCompatibleVersions(): Internal error (7).\n");
                LOG_DELAY();
                result = false;
                goto finish;
            }

            dependencyVersion = OSDynamicCast(OSString,
                dependencyPlist->getObject("CFBundleVersion"));
            if (!curExtDependencyVersion) {
                IOLog(VTYELLOW "Dependency extension \"%s\" doesn't declare a "
                    "version.\n" VTRESET,
                    dependencyName->getCStringNoCopy());
                LOG_DELAY();
                result = false;
                goto finish;
            }

            dependencyCompatibleVersion = OSDynamicCast(OSString,
                dependencyPlist->getObject("OSBundleCompatibleVersion"));
            if (!dependencyCompatibleVersion) {
                IOLog(VTYELLOW "Dependency extension \"%s\" doesn't declare a "
                    "compatible version.\n" VTRESET,
                    dependencyName->getCStringNoCopy());
                LOG_DELAY();
                result = false;
                goto finish;
            }

IOLog("\033[33m    %s (needs %s, compat-current is %s-%s).\n" VTRESET, 
    dependencyName->getCStringNoCopy(),
    curExtDependencyVersion->getCStringNoCopy(),
    dependencyCompatibleVersion->getCStringNoCopy(),
    dependencyVersion->getCStringNoCopy());
LOG_DELAY();

            if (!VERS_parse_string(curExtDependencyVersion->getCStringNoCopy(),
                 &cur_ext_required_dependency_vers)) {
            }
            if (!VERS_parse_string(dependencyVersion->getCStringNoCopy(),
                 &dependency_vers)) {
            }
            if (!VERS_parse_string(dependencyCompatibleVersion->getCStringNoCopy(),
                 &dependency_compat_vers)) {
            }

            if (cur_ext_required_dependency_vers > dependency_vers ||
                cur_ext_required_dependency_vers < dependency_compat_vers) {

                IOLog(VTYELLOW "Cannot load extension \"%s\": dependencies "
                    "\"%s\" and \"%s\" are not of compatible versions.\n" VTRESET,
                    requestedModuleName->getCStringNoCopy(),
                    curName->getCStringNoCopy(),
                    dependencyName->getCStringNoCopy());
                LOG_DELAY();
                result = false;
                goto finish;
            }
        }
    }

finish:
    return result;
}


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

    round_headers_size = round_page(headers_size);
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

    round_headers_size  = round_page(headers_size);
    round_segments_size = round_page(size - headers_size);
    round_size  = round_headers_size + round_segments_size;
    headers_pad = round_headers_size - headers_size;

    k_result = vm_allocate(kernel_map, (vm_offset_t *)&buffer,
        round_size, TRUE);
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
int get_text_info_for_kmod(const char * kmod_name,
    char ** text_address,
    unsigned long * text_size) {

    // None of these needs to be released.
    OSDictionary * extensionsDict;
    OSDictionary * kmodDict;
    OSData * driverCode;

    vm_offset_t kmod_address;
    typedef union {
        struct mach_header mach_header;
        struct fat_header  fat_header;
    } kmod_header_composite;
    kmod_header_composite * kmod_headers;


   /* Get the requested kmod's info dictionary from the global
    * startup extensions dictionary.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("text_address_for_kmod(): No extensions dictionary.\n");
        LOG_DELAY();
        return 0;
    }
    
    kmodDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(kmod_name));
    if (!kmodDict) {
        IOLog("text_address_for_kmod(): "
            "Extension \"%s\" cannot be found.\n", kmod_name);
        LOG_DELAY();
        return 0;
    }

    driverCode = OSDynamicCast(OSData, kmodDict->getObject("code"));
    if (!driverCode) {
        IOLog("text_address_for_kmod(): "
            "Extension \"%s\" has no \"code\" property.\n",
            kmod_name);
        LOG_DELAY();
        return 0;
    }

    kmod_address = (vm_offset_t)driverCode->getBytesNoCopy();
    kmod_headers = (kmod_header_composite *)kmod_address;

   /* Now extract the appropriate code from the executable data.
    */
    if (kmod_headers->mach_header.magic == MH_MAGIC) {

        *text_address = (char *)kmod_address;
        *text_size = driverCode->getLength();
        return 1;

    } else if (kmod_headers->fat_header.magic == FAT_MAGIC ||
               kmod_headers->fat_header.magic == FAT_CIGAM) {
                             // CIGAM is byte-swapped MAGIC

        load_return_t load_return;
        struct fat_arch fatinfo;

        load_return = fatfile_getarch(NULL, kmod_address, &fatinfo);
        if (load_return != LOAD_SUCCESS) {
            IOLog("text_address_for_kmod(): Extension \"%s\" "
                "doesn't contain code for this computer.\n", kmod_name);
            LOG_DELAY();
            return 0;
        }

        *text_address = (char *)(kmod_address + fatinfo.offset);
        *text_size = fatinfo.size;
        return 1;

    } else {
        IOLog("text_address_for_kmod(): Extension \"%s\" either "
            "isn't code or doesn't contain code for this computer.\n",
            kmod_name);
        LOG_DELAY();
        return 0;
    }

    return 1;
}


/*********************************************************************
*********************************************************************/
bool verify_kmod(const char * kmod_name, kmod_info_t * kmod_info) {
    bool result = false;
    OSDictionary * extensionsDict = NULL;  // don't release
    OSDictionary * kmodDict = NULL;        // don't release
    OSDictionary * plist = NULL;           // don't release
    OSString     * versionString = NULL;   // don't release
    UInt32 plist_vers;
    UInt32 kmod_vers;

    if (strncmp(kmod_name, kmod_info->name, sizeof(kmod_info->name))) {
        IOLog("verify_kmod(): kmod loaded as \"%s\" has different "
            "identifier \"%s\".\n", kmod_name, kmod_info->name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    if (!VERS_parse_string(kmod_info->version,
         &kmod_vers)) {

        IOLog(VTYELLOW "verify_kmod(): kmod \"%s\" has an invalid "
            "version.\n" VTRESET, kmod_info->name);
        LOG_DELAY();
        result = false;
        goto finish;
    }


   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("verify_kmod(): No extensions dictionary.\n");
        LOG_DELAY();
        result = false;
        goto finish;
    }

    kmodDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(kmod_name));
    if (!kmodDict) {
        IOLog("verify_kmod(): Can't find record for kmod \"%s\".\n",
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    plist = OSDynamicCast(OSDictionary,
        extensionsDict->getObject("plist"));
    if (!kmodDict) {
        IOLog("verify_kmod(): Kmod \"%s\" has no property list.\n",
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    versionString = OSDynamicCast(OSString,
        extensionsDict->getObject("CFBundleVersion"));
    if (!versionString) {
        IOLog(VTYELLOW "verify_kmod(): Kmod \"%s\" has no \"CFBundleVersion\" "
            "property.\n" VTRESET,
            kmod_name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    if (!VERS_parse_string(versionString->getCStringNoCopy(),
         &plist_vers)) {

        IOLog(VTYELLOW "verify_kmod(): Property list for kmod \"%s\" has "
            "an invalid version.\n" VTRESET, kmod_info->name);
        LOG_DELAY();
        result = false;
        goto finish;
    }

    if (kmod_vers != plist_vers) {
        IOLog(VTYELLOW "verify_kmod(): Kmod \"%s\" and its property list "
            "claim different versions (%s & %s).\n" VTRESET,
            kmod_info->name,
            kmod_info->version,
            versionString->getCStringNoCopy());
        LOG_DELAY();
        result = false;
        goto finish;
    }


finish:

    // FIXME: make this really return the result after conversion
    return true;

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
    kmod_info_t * kmod_info;
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
    kmod_info = kmod_lookupbyname(requested_kmod_name);
    if (kmod_info) {
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
        g_current_kmod_info = kmod_lookupbyname(current_kmod_name);
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

        if (!get_text_info_for_kmod(current_kmod_name,
             &kmod_address, &kmod_size)) {

            IOLog("get_text_info_for_kmod() failed for dependency kmod "
                "\"%s\".\n", current_kmod_name);
            LOG_DELAY();
            result = KERN_FAILURE;
            goto finish;
        }

        kld_result = kld_load_from_memory(&kmod_header,
            current_kmod_name,
            (char *)kmod_address,
            kmod_size);

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

    if (!get_text_info_for_kmod(requested_kmod_name,
         &kmod_address, &kmod_size)) {
        IOLog("load_kmod: get_text_info_for_kmod() failed for "
            "kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }

    kld_result = kld_load_from_memory(&kmod_header,
        requested_kmod_name,
        (char *)kmod_address,
        kmod_size);

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
        (char *)link_buffer_address + round_page(link_header_size),
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


    if (!verify_kmod(requested_kmod_name, kmod_info)) {
        // verify_kmod() logs a meaningful message
        result = KERN_FAILURE;
        goto finish;
    }


   /* kld_lookup of _kmod_info yielded the actual linked address,
    * so now that we've copied the data into its real place,
    * we can set this stuff.
    */
    kmod_info->address = link_buffer_address;
    kmod_info->size = link_buffer_size;
    kmod_info->hdr_size = round_page(link_header_size);

   /* We've written data and instructions, so *flush* the data cache
    * and *invalidate* the instruction cache.
    */
    flush_dcache(link_buffer_address, link_buffer_size, false);
    invalidate_icache(link_buffer_address, link_buffer_size, false);


   /* Register the new kmod with the kernel proper.
    */
    if (kmod_create_internal(kmod_info, &kmod_id) != KERN_SUCCESS) {
        IOLog("load_kmod(): kmod_create() failed for "
            "kmod \"%s\".\n", requested_kmod_name);
        LOG_DELAY();
        result = KERN_FAILURE;
        goto finish;
    }

    IOLog("kmod id %d successfully created at 0x%lx, size %ld.\n",
        (unsigned int)kmod_id, link_buffer_address, link_buffer_size);
    LOG_DELAY();

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
    kmod_info_t * kmod_info;
    OSArray * dependencyList = NULL;     // must release
    OSArray * curDependencyList = NULL;  // must release


   /* This must be the very first thing done by this function.
    */
    IOLockLock(kld_lock);


   /* See if the kmod is already loaded.
    */
    kmod_info = kmod_lookupbyname(kmod_name);
    if (kmod_info) {  // NOT checked
        result = KERN_SUCCESS;
        goto finish;
    }

    // FIXME: Need to check whether kmod is built into the kernel!

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

    if (!verifyCompatibleVersions(dependencyList)) {
        IOLog(VTYELLOW "load_kernel_extension(): "
            "Version mismatch for kernel extension \"%s\".\n" VTRESET,
            kmod_name);
        LOG_DELAY();
#if 0
// FIXME: This is currently a warning only; when kexts are updated
// this will become an error.
        result = KERN_FAILURE;
        goto finish;
#else
        IOLog(VTYELLOW "Loading anyway.\n" VTRESET);
#endif 0
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


finish:

    if (dependencyList) {
        dependencyList->release();
        dependencyList = NULL;
    }
    if (curDependencyList) {
        curDependencyList->release();
        curDependencyList = NULL;
    }

   /* This must be the very last thing done before returning.
    */
    IOLockUnlock(kld_lock);

    return result;
}
