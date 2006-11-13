/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#include <IOKit/IOLib.h>
#include <mach/kmod.h>
#include <libkern/c++/OSDictionary.h>

#include <libsa/kext.h>
#include <libsa/catalogue.h>
#include <libsa/malloc.h>

#include "kld_patch.h"

/*****
 * This function is used by IOCatalogue to load a kernel
 * extension. libsa initially sets it to be a function
 * that uses libkld to load and link the extension from
 * within the kernel. Once the root filesystem is up,
 * this gets switch to the kmod_load_extension() function,
 * which merely queues the extension for loading by the
 * kmodload utility.
 */
extern kern_return_t (*kmod_load_function)(char *extension_name);
extern bool (*record_startup_extensions_function)(void);
extern bool (*add_from_mkext_function)(OSData * mkext);
extern void (*remove_startup_extension_function)(const char * name);

/****
 * IOCatalogue uses this variable to make a few decisions
 * about loading and matching drivers.
 */
extern int kernelLinkerPresent;


class KLDBootstrap {
public:
    KLDBootstrap();
    ~KLDBootstrap();
};


static KLDBootstrap bootstrap_obj;


/* The constructor creates a lock and puts entries into a dispatch
 * table for functions used to record and load kmods.
 */
KLDBootstrap::KLDBootstrap() {

    malloc_init();

    kmod_load_function = &load_kernel_extension;

    record_startup_extensions_function = &recordStartupExtensions;
    add_from_mkext_function = &addExtensionsFromArchive;
    remove_startup_extension_function = &removeStartupExtension;

    kernelLinkerPresent = 1;
}

/* The destructor frees all wired memory regions held
 * by libsa's malloc package and disposes of the lock.
 */
KLDBootstrap::~KLDBootstrap() {

    kld_file_cleanup_all_resources();

   /* Dump all device-tree entries for boot drivers, and all
    * info on startup extensions. The IOCatalogue will now
    * get personalities from kextd.
    */
    clearStartupExtensionsAndLoaderInfo();

   /* Free all temporary malloc memory.
    */
    malloc_reset();
}
