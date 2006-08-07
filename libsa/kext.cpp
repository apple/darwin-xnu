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
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOLib.h>
#include <libsa/kext.h>
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

#include "kld_patch.h"
#include "dgraph.h"
#include "load.h"
};


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

extern void flush_dcache(vm_offset_t addr, unsigned cnt, int phys);
extern void invalidate_icache(vm_offset_t addr, unsigned cnt, int phys);
};

#define DEBUG
#ifdef DEBUG
#define LOG_DELAY(x)    IODelay((x) * 1000000)
#define VTYELLOW  "\033[33m"
#define VTRESET   "\033[0m"
#else
#define LOG_DELAY(x)
#define VTYELLOW
#define VTRESET
#endif /* DEBUG */

/*********************************************************************
*
*********************************************************************/
static
bool getKext(
    const char * bundleid,
    OSDictionary ** plist,
    unsigned char ** code,
    unsigned long * code_size,
    bool * caller_owns_code)
{
    bool result = true;
    OSDictionary * extensionsDict;   // don't release
    OSDictionary * extDict;          // don't release
    OSDictionary * extPlist;         // don't release
    unsigned long code_size_local;

   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("startup extensions dictionary is missing\n");
        result = false;
        goto finish;
    }

   /* Get the requested extension's dictionary entry and its property
    * list, containing module dependencies.
    */
    extDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(bundleid));

    if (!extDict) {
        IOLog("extension \"%s\" cannot be found\n",
           bundleid);
        result = false;
        goto finish;
    }

    if (plist) {
        extPlist = OSDynamicCast(OSDictionary, extDict->getObject("plist"));
        if (!extPlist) {
            IOLog("extension \"%s\" has no info dictionary\n",
                bundleid);
            result = false;
            goto finish;
        }
        *plist = extPlist;
    }

    if (code) {

       /* If asking for code, the caller must provide a return buffer
        * for ownership!
        */
        if (!caller_owns_code) {
            IOLog("getKext(): invalid usage (caller_owns_code not provided)\n");
            result = false;
            goto finish;
        }
    
        *code = 0;
        if (code_size) {
            *code_size = 0;
        }
        *caller_owns_code = false;
    
        *code = (unsigned char *)kld_file_getaddr(bundleid,
            (long *)&code_size_local);
        if (*code) {
            if (code_size) {
                *code_size = code_size_local;
            }
        } else {
            OSData * driverCode = 0; // release only if uncompressing!
    
            driverCode = OSDynamicCast(OSData, extDict->getObject("code"));
            if (driverCode) {
                *code = (unsigned char *)driverCode->getBytesNoCopy();
                if (code_size) {
                    *code_size = driverCode->getLength();
                }
            } else { // Look for compressed code and uncompress it
                OSData * compressedCode = 0;
                compressedCode = OSDynamicCast(OSData,
                    extDict->getObject("compressedCode"));
                if (compressedCode) {
                    if (!uncompressModule(compressedCode, &driverCode)) {
                        IOLog("extension \"%s\": couldn't uncompress code\n",
                            bundleid);
                        result = false;
                        goto finish;
                    }
                    *caller_owns_code = true;
                    *code = (unsigned char *)driverCode->getBytesNoCopy();
                    if (code_size) {
                        *code_size = driverCode->getLength();
                    }
                    driverCode->release();
                }
            }
        }
    }

finish:

    return result;
}


/*********************************************************************
*
*********************************************************************/
static
bool verifyCompatibility(OSString * extName, OSString * requiredVersion)
{
    OSDictionary * extPlist;         // don't release
    OSString     * extVersion;       // don't release
    OSString     * extCompatVersion; // don't release
    VERS_version ext_version;
    VERS_version ext_compat_version;
    VERS_version required_version;

    if (!getKext(extName->getCStringNoCopy(), &extPlist, NULL, NULL, NULL)) {
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

    required_version = VERS_parse_string(requiredVersion->getCStringNoCopy());
    if (required_version < 0) {
        IOLog("verifyCompatibility(): "
            "Can't parse required version \"%s\" of dependency %s.\n",
            requiredVersion->getCStringNoCopy(),
            extName->getCStringNoCopy());
        return false;
    }
    ext_version = VERS_parse_string(extVersion->getCStringNoCopy());
    if (ext_version < 0) {
        IOLog("verifyCompatibility(): "
            "Can't parse version \"%s\" of dependency %s.\n",
            extVersion->getCStringNoCopy(),
            extName->getCStringNoCopy());
        return false;
    }
    ext_compat_version = VERS_parse_string(extCompatVersion->getCStringNoCopy());
    if (ext_compat_version < 0) {
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
bool kextIsDependency(const char * kext_name, char * is_kernel) {
    bool result = true;
    OSDictionary * extensionsDict = 0;    // don't release
    OSDictionary * extDict = 0;           // don't release
    OSDictionary * extPlist = 0;          // don't release
    OSBoolean * isKernelResourceObj = 0;  // don't release
    OSData * driverCode = 0;              // don't release
    OSData * compressedCode = 0;          // don't release

    if (is_kernel) {
        *is_kernel = false;
    }

   /* Get the dictionary of startup extensions.
    * This is keyed by module name.
    */
    extensionsDict = getStartupExtensions();
    if (!extensionsDict) {
        IOLog("startup extensions dictionary is missing\n");
        result = false;
        goto finish;
    }

   /* Get the requested extension's dictionary entry and its property
    * list, containing module dependencies.
    */
    extDict = OSDynamicCast(OSDictionary,
        extensionsDict->getObject(kext_name));

    if (!extDict) {
        IOLog("extension \"%s\" cannot be found\n",
           kext_name);
        result = false;
        goto finish;
    }

    extPlist = OSDynamicCast(OSDictionary, extDict->getObject("plist"));
    if (!extPlist) {
        IOLog("extension \"%s\" has no info dictionary\n",
            kext_name);
        result = false;
        goto finish;
    }

   /* A kext that is a kernel component is still a dependency, as there
    * are fake kmod entries for them.
    */
    isKernelResourceObj = OSDynamicCast(OSBoolean,
        extPlist->getObject("OSKernelResource"));
    if (isKernelResourceObj && isKernelResourceObj->isTrue()) {
        if (is_kernel) {
            *is_kernel = true;
        }
    }

    driverCode = OSDynamicCast(OSData, extDict->getObject("code"));
    compressedCode = OSDynamicCast(OSData,
        extDict->getObject("compressedCode"));

    if ((driverCode || compressedCode) && is_kernel && *is_kernel) {
        *is_kernel = 2;
    }

    if (!driverCode && !compressedCode && !isKernelResourceObj) {
        result = false;
        goto finish;
    }

finish:

    return result;
}

/*********************************************************************
*********************************************************************/
static bool
addDependenciesForKext(OSDictionary * kextPlist,
    OSArray   * dependencyList,
    OSString * trueParent,
    Boolean    skipKernelDependencies)
{
    bool result = true;
    bool hasDirectKernelDependency = false;
    OSString * kextName = 0;  // don't release
    OSDictionary * libraries = 0;  // don't release
    OSCollectionIterator * keyIterator = 0; // must release
    OSString * libraryName = 0; // don't release
    OSString * dependentName = 0; // don't release

    kextName = OSDynamicCast(OSString,
        kextPlist->getObject("CFBundleIdentifier"));
    if (!kextName) {
        // XXX: Add log message
        result = false;
        goto finish;
    }

    libraries = OSDynamicCast(OSDictionary,
        kextPlist->getObject("OSBundleLibraries"));
    if (!libraries) {
        result = true;
        goto finish;
    }

    keyIterator = OSCollectionIterator::withCollection(libraries);
    if (!keyIterator) {
        // XXX: Add log message
        result = false;
        goto finish;
    }

    dependentName = trueParent ? trueParent : kextName;

    while ( (libraryName = OSDynamicCast(OSString,
        keyIterator->getNextObject())) ) {

        OSString * libraryVersion = OSDynamicCast(OSString,
            libraries->getObject(libraryName));
        if (!libraryVersion) {
            // XXX: Add log message
            result = false;
            goto finish;
        }
        if (!verifyCompatibility(libraryName, libraryVersion)) {
            result = false;
            goto finish;
        } else {
            char is_kernel_component;

            if (!kextIsDependency(libraryName->getCStringNoCopy(),
                &is_kernel_component)) {

                is_kernel_component = false;
            }

            if (!skipKernelDependencies || !is_kernel_component) {
                dependencyList->setObject(dependentName);
                dependencyList->setObject(libraryName);
            }
            if (!hasDirectKernelDependency && is_kernel_component) {
                hasDirectKernelDependency = true;
            }
        }
    }
    if (!hasDirectKernelDependency) {
        const OSSymbol * kernelName = 0;

        /* a kext without any kernel dependency is assumed dependent on 6.0 */
        dependencyList->setObject(dependentName);

        kernelName = OSSymbol::withCString("com.apple.kernel.libkern");
        if (!kernelName) {
            // XXX: Add log message
            result = false;
            goto finish;
        }
        dependencyList->setObject(kernelName);
        kernelName->release();

        IOLog("Extension \"%s\" has no kernel dependency.\n",
            kextName->getCStringNoCopy());
    }

finish:
    if (keyIterator) keyIterator->release();
    return result;
}

/*********************************************************************
*********************************************************************/
static
bool getVersionForKext(OSDictionary * kextPlist, char ** version)
{
    OSString * kextName = 0;  // don't release
    OSString * kextVersion;       // don't release

    kextName = OSDynamicCast(OSString,
        kextPlist->getObject("CFBundleIdentifier"));
    if (!kextName) {
        // XXX: Add log message
        return false;
    }

    kextVersion = OSDynamicCast(OSString,
        kextPlist->getObject("CFBundleVersion"));
    if (!kextVersion) {
        IOLog("getVersionForKext(): "
            "Extension \"%s\" has no \"CFBundleVersion\" property.\n",
            kextName->getCStringNoCopy());
        return false;
    }

    if (version) {
        *version = (char *)kextVersion->getCStringNoCopy();
    }

    return true;
}

/*********************************************************************
*********************************************************************/
static
bool add_dependencies_for_kmod(const char * kmod_name, dgraph_t * dgraph)
{
    bool result = true;
    OSDictionary * kextPlist = 0; // don't release
    unsigned int index = 0;
    OSArray * dependencyList = 0;  // must release
    unsigned char * code = 0;
    unsigned long code_length = 0;
    bool code_is_kmem = false;
    char * kmod_vers = 0; // from plist, don't free
    char is_kernel_component = false;
    dgraph_entry_t * dgraph_entry = 0; // don't free
    dgraph_entry_t * dgraph_dependency = 0; // don't free
    bool kext_is_dependency = true;

   /*****
    * Set up the root kmod.
    */
    if (!getKext(kmod_name, &kextPlist, &code, &code_length,
        &code_is_kmem)) {
        IOLog("can't find extension %s\n", kmod_name);
        result = false;
        goto finish;
    }

    if (!kextIsDependency(kmod_name, &is_kernel_component)) {
        IOLog("extension %s is not loadable\n", kmod_name);
        result = false;
        goto finish;
    }

    if (!getVersionForKext(kextPlist, &kmod_vers)) {
        IOLog("can't get version for extension %s\n", kmod_name);
        result = false;
        goto finish;
    }

    dgraph_entry = dgraph_add_dependent(dgraph, kmod_name,
        code, code_length, code_is_kmem,
        kmod_name, kmod_vers,
        0 /* load_address not yet known */, is_kernel_component);
    if (!dgraph_entry) {
        IOLog("can't record %s in dependency graph\n", kmod_name);
        result = false;
        // kmem_alloc()ed code is freed in finish: block.
        goto finish;
    }

    // pass ownership of code to kld patcher
    if (code) {
        if (kload_map_entry(dgraph_entry) != kload_error_none) {
            IOLog("can't map %s in preparation for loading\n", kmod_name);
            result = false;
            // kmem_alloc()ed code is freed in finish: block.
           goto finish;
        }
    }
    // clear local record of code
    code = 0;
    code_length = 0;
    code_is_kmem = false;

   /*****
    * Now handle all the dependencies.
    */
    dependencyList = OSArray::withCapacity(5);
    if (!dependencyList) {
        IOLog("memory allocation failure\n");
        result = false;
        goto finish;
    }

    index = 0;
    if (!addDependenciesForKext(kextPlist, dependencyList, NULL, false)) {
        IOLog("can't determine immediate dependencies for extension %s\n",
            kmod_name);
        result = false;
        goto finish;
    }

   /* IMPORTANT: loop condition gets list count every time through, as the
    * array CAN change each iteration.
    */
    for (index = 0; index < dependencyList->getCount(); index += 2) {
        OSString * dependentName = 0;
        OSString * libraryName = 0;
        const char * dependent_name = 0;
        const char * library_name = 0;

       /* 255 is an arbitrary limit. Multiplied  by 2 because the dependency
        * list is stocked with pairs (dependent -> dependency).
        */
        if (index > (2 * 255)) {
            IOLog("extension dependency graph ridiculously long, indicating a loop\n");
            result = false;
            goto finish;
        }

        dependentName = OSDynamicCast(OSString,
            dependencyList->getObject(index));
        libraryName = OSDynamicCast(OSString,
            dependencyList->getObject(index + 1));

        if (!dependentName || !libraryName) {
            IOLog("malformed dependency list\n");
            result = false;
            goto finish;
        }

        dependent_name = dependentName->getCStringNoCopy();
        library_name = libraryName->getCStringNoCopy();

        if (!getKext(library_name, &kextPlist, NULL, NULL, NULL)) {

            IOLog("can't find extension %s\n", library_name);
            result = false;
            goto finish;
        }

        OSString * string = OSDynamicCast(OSString,
            kextPlist->getObject("OSBundleSharedExecutableIdentifier"));
        if (string) {
            library_name = string->getCStringNoCopy();
            if (!getKext(library_name, &kextPlist, NULL, NULL, NULL)) {
                IOLog("can't find extension %s\n", library_name);
                result = false;
                goto finish;
            }
        }

        kext_is_dependency = kextIsDependency(library_name,
            &is_kernel_component);

        if (kext_is_dependency) {
                dgraph_entry = dgraph_find_dependent(dgraph, dependent_name);
                if (!dgraph_entry) {
                    IOLog("internal error with dependency graph\n");
                    LOG_DELAY(1);
                    result = false;
                    goto finish;
                }

                if (!getVersionForKext(kextPlist, &kmod_vers)) {
                    IOLog("can't get version for extension %s\n", library_name);
                    result = false;
                    goto finish;
                }

               /* It's okay for code to be zero, as for a pseudokext
                * representing a kernel component.
                */
                if (!getKext(library_name, NULL /* already got it */,
                    &code, &code_length, &code_is_kmem)) {
                    IOLog("can't find extension %s\n", library_name);
                    result = false;
                    goto finish;
                }

                dgraph_dependency = dgraph_add_dependency(dgraph, dgraph_entry,
                    library_name, code, code_length, code_is_kmem,
                    library_name, kmod_vers,
                    0 /* load_address not yet known */, is_kernel_component);

                if (!dgraph_dependency) {
                    IOLog("can't record dependency %s -> %s\n", dependent_name,
                        library_name);
                    result = false;
                    // kmem_alloc()ed code is freed in finish: block.
                    goto finish;
                }

                // pass ownership of code to kld patcher
                if (code) {
                    if (kload_map_entry(dgraph_dependency) != kload_error_none) {
                        IOLog("can't map %s in preparation for loading\n", library_name);
                        result = false;
                        // kmem_alloc()ed code is freed in finish: block.
                        goto finish;
                    }
                }
                // clear local record of code
                code = 0;
                code_length = 0;
                code_is_kmem = false;
            }

           /* Now put the library's dependencies onto the pending set.
            */
            if (!addDependenciesForKext(kextPlist, dependencyList,
                kext_is_dependency ? NULL : dependentName, !kext_is_dependency)) {

                IOLog("can't determine immediate dependencies for extension %s\n",
                    library_name);
                result = false;
                goto finish;
            }
        }

finish:
    if (code && code_is_kmem) {
        kmem_free(kernel_map, (unsigned int)code, code_length);
    }
    if (dependencyList)  dependencyList->release();

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
kern_return_t load_kernel_extension(char * kmod_name)
{
    kern_return_t result = KERN_SUCCESS;
    kload_error load_result = kload_error_none;
    dgraph_t dgraph;
    bool free_dgraph = false;
    kmod_info_t * kmod_info;

// Put this in for lots of messages about kext loading.
#if 0
    kload_set_log_level(kload_log_level_load_details);
#endif

   /* See if the kmod is already loaded.
    */
    if ((kmod_info = kmod_lookupbyname_locked(kmod_name))) {
        kfree(kmod_info, sizeof(kmod_info_t));
        return KERN_SUCCESS;
    }

    if (dgraph_init(&dgraph) != dgraph_valid) {
        IOLog("Can't initialize dependency graph to load %s.\n",
            kmod_name);
        result = KERN_FAILURE;
        goto finish;
    }

    free_dgraph = true;
    if (!add_dependencies_for_kmod(kmod_name, &dgraph)) {
        IOLog("Can't determine dependencies for %s.\n",
            kmod_name);
        result = KERN_FAILURE;
        goto finish;
    }

    dgraph.root = dgraph_find_root(&dgraph);

    if (!dgraph.root) {
        IOLog("Dependency graph to load %s has no root.\n",
            kmod_name);
        result = KERN_FAILURE;
        goto finish;
    }

   /* A kernel component is built in and need not be loaded.
    */
    if (dgraph.root->is_kernel_component) {
        result = KERN_SUCCESS;
        goto finish;
    }

    dgraph_establish_load_order(&dgraph);

    load_result = kload_load_dgraph(&dgraph);
    if (load_result != kload_error_none &&
        load_result != kload_error_already_loaded) {

        IOLog(VTYELLOW "Failed to load extension %s.\n" VTRESET, kmod_name);

        result = KERN_FAILURE;
        goto finish;
    }

finish:

    if (free_dgraph) {
        dgraph_free(&dgraph, 0 /* don't free dgraph itself */);
    }
    return result;
}
