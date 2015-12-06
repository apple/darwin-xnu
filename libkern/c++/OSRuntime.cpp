/*
 * Copyright (c) 2000,2008-2009 Apple Inc. All rights reserved.
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
 * Copyright (c) 1997 Apple Inc.
 *
 */
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSSymbol.h>
#include <IOKit/IOKitDebug.h>

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <string.h>
#include <mach/mach_types.h>
#include <libkern/kernel_mach_header.h>
#include <stdarg.h>

#if PRAGMA_MARK
#pragma mark Constants &c.
#endif /* PRAGMA_MARK */
OSKextLogSpec kOSRuntimeLogSpec =
    kOSKextLogErrorLevel |
    kOSKextLogLoadFlag |
    kOSKextLogKextBookkeepingFlag;
    
#if PRAGMA_MARK
#pragma mark Logging Bootstrap
#endif /* PRAGMA_MARK */
/*********************************************************************
* kern_os Logging Bootstrap
*
* We can't call in to OSKext until the kernel's C++ environment is up
* and running, so let's mask those references with a check variable.
* We print unconditionally if C++ isn't up, but if that's the case
* we've generally hit a serious error in kernel init!
*********************************************************************/
static bool gKernelCPPInitialized = false;

#define OSRuntimeLog(kext, flags, format, args...)            \
    do {                                                      \
        if (gKernelCPPInitialized) {                          \
            OSKextLog((kext), (flags), (format), ## args);  \
        } else {                                              \
            printf((format), ## args);                        \
        }                                                     \
    } while (0)

#if PRAGMA_MARK
#pragma mark kern_os Allocator Package
#endif /* PRAGMA_MARK */
/*********************************************************************
* kern_os Allocator Package
*********************************************************************/

/*********************************************************************
*********************************************************************/
#if OSALLOCDEBUG
extern int debug_iomalloc_size;
#endif

struct _mhead {
    size_t  mlen;
    char    dat[0];
};

/*********************************************************************
*********************************************************************/
void *
kern_os_malloc(size_t size)
{
    struct _mhead * mem;
    size_t          memsize = sizeof (*mem) + size ;

    if (size == 0) {
        return (0);
    }

    mem = (struct _mhead *)kalloc_tag_bt(memsize, VM_KERN_MEMORY_LIBKERN);
    if (!mem) {
        return (0);
    }

#if OSALLOCDEBUG
    debug_iomalloc_size += memsize;
#endif

    mem->mlen = memsize;
    bzero(mem->dat, size);

    return mem->dat;
}

/*********************************************************************
*********************************************************************/
void
kern_os_free(void * addr)
{
    struct _mhead * hdr;

    if (!addr) {
        return;
    }

    hdr = (struct _mhead *)addr; 
    hdr--;

#if OSALLOCDEBUG
    debug_iomalloc_size -= hdr->mlen;
#endif

#if 0
    memset((vm_offset_t)hdr, 0xbb, hdr->mlen);
#else
    kfree(hdr, hdr->mlen);
#endif
}

/*********************************************************************
*********************************************************************/
void *
kern_os_realloc(
    void   * addr,
    size_t   nsize)
{
    struct _mhead * ohdr;
    struct _mhead * nmem;
    size_t          nmemsize, osize;

    if (!addr) {
        return (kern_os_malloc(nsize));
    }

    ohdr = (struct _mhead *)addr;
    ohdr--;
    osize = ohdr->mlen - sizeof(*ohdr);
    if (nsize == osize) {
        return (addr);
    }

    if (nsize == 0) {
        kern_os_free(addr);
        return (0);
    }

    nmemsize = sizeof (*nmem) + nsize ;
    nmem = (struct _mhead *) kalloc_tag_bt(nmemsize, VM_KERN_MEMORY_LIBKERN);
    if (!nmem){
        kern_os_free(addr);
        return (0);
    }

#if OSALLOCDEBUG
    debug_iomalloc_size += (nmemsize - ohdr->mlen);
#endif

    nmem->mlen = nmemsize;
    if (nsize > osize) {
        (void) memset(&nmem->dat[osize], 0, nsize - osize);
    }
    (void)memcpy(nmem->dat, ohdr->dat, (nsize > osize) ? osize : nsize);
    kfree(ohdr, ohdr->mlen);

    return (nmem->dat);
}

/*********************************************************************
*********************************************************************/
size_t
kern_os_malloc_size(void * addr)
{
    struct _mhead * hdr;

    if (!addr) {
        return(0);
    }

    hdr = (struct _mhead *) addr; hdr--;
    return hdr->mlen - sizeof (struct _mhead);
}

#if PRAGMA_MARK
#pragma mark C++ Runtime Load/Unload
#endif /* PRAGMA_MARK */
/*********************************************************************
* kern_os C++ Runtime Load/Unload
*********************************************************************/

/*********************************************************************
*********************************************************************/
#if __GNUC__ >= 3
void __cxa_pure_virtual( void )    { panic("%s", __FUNCTION__); }
#else
void __pure_virtual( void )        { panic("%s", __FUNCTION__); }
#endif

typedef void (*structor_t)(void);

/*********************************************************************
*********************************************************************/
static boolean_t
sectionIsDestructor(kernel_section_t * section)
{
    boolean_t result;

    result = !strncmp(section->sectname, SECT_MODTERMFUNC,
        sizeof(SECT_MODTERMFUNC) - 1);
#if !__LP64__
    result = result || !strncmp(section->sectname, SECT_DESTRUCTOR, 
        sizeof(SECT_DESTRUCTOR) - 1);
#endif

    return result;
}

/*********************************************************************
*********************************************************************/
static boolean_t
sectionIsConstructor(kernel_section_t * section)
{
    boolean_t result;

    result = !strncmp(section->sectname, SECT_MODINITFUNC,
        sizeof(SECT_MODINITFUNC) - 1);
#if !__LP64__
    result = result || !strncmp(section->sectname, SECT_CONSTRUCTOR, 
        sizeof(SECT_CONSTRUCTOR) - 1);
#endif

    return result;
}


/*********************************************************************
* OSRuntimeUnloadCPPForSegment()
*
* Given a pointer to a mach object segment, iterate the segment to
* obtain a destructor section for C++ objects, and call each of the
* destructors there.
*********************************************************************/

void
OSRuntimeUnloadCPPForSegmentInKmod(
    kernel_segment_command_t * segment,
    kmod_info_t              * kmodInfo)
{

    kernel_section_t * section = NULL;  // do not free
    OSKext           * theKext = NULL;  // must release

    if (gKernelCPPInitialized && kmodInfo) {
        theKext = OSKext::lookupKextWithIdentifier(kmodInfo->name);
    }

    for (section = firstsect(segment);
         section != 0;
         section = nextsect(segment, section)) {

        if (sectionIsDestructor(section)) {
            structor_t * destructors = (structor_t *)section->addr;

            if (destructors) {
                int num_destructors = section->size / sizeof(structor_t);
                int hit_null_destructor = 0;

                for (int i = 0; i < num_destructors; i++) {
                    if (destructors[i]) {
                        (*destructors[i])();
                    } else if (!hit_null_destructor) {
                        hit_null_destructor = 1;
                        OSRuntimeLog(theKext, kOSRuntimeLogSpec,
                            "Null destructor in kext %s segment %s!",
                            kmodInfo ? kmodInfo->name : "(unknown)",
                            section->segname);
                    }
                }
            } /* if (destructors) */
        } /* if (strncmp...) */
    } /* for (section...) */

    OSSafeRelease(theKext);
    return;
}

void
OSRuntimeUnloadCPPForSegment(kernel_segment_command_t * segment) {
    OSRuntimeUnloadCPPForSegmentInKmod(segment, NULL);
}

/*********************************************************************
*********************************************************************/
void
OSRuntimeUnloadCPP(
    kmod_info_t * kmodInfo,
    void        * data __unused)
{
    if (kmodInfo && kmodInfo->address) {

        kernel_segment_command_t * segment;
        kernel_mach_header_t * header;

        OSSymbol::checkForPageUnload((void *)kmodInfo->address,
            (void *)(kmodInfo->address + kmodInfo->size));

        header = (kernel_mach_header_t *)kmodInfo->address;
        segment = firstsegfromheader(header);

        for (segment = firstsegfromheader(header);
             segment != 0;
             segment = nextsegfromheader(header, segment)) {

            OSRuntimeUnloadCPPForSegmentInKmod(segment, kmodInfo);
        }
    }

    return;
}

/*********************************************************************
*********************************************************************/
kern_return_t
OSRuntimeFinalizeCPP(
    kmod_info_t * kmodInfo,
    void        * data __unused)
{
    kern_return_t   result = KMOD_RETURN_FAILURE;
    void          * metaHandle = NULL;  // do not free
    OSKext        * theKext    = NULL;  // must release

    if (gKernelCPPInitialized) {
        theKext = OSKext::lookupKextWithIdentifier(kmodInfo->name);
    }

    if (theKext && !theKext->isCPPInitialized()) {
        result = KMOD_RETURN_SUCCESS;
        goto finish;
    }

   /* OSKext checks for this condition now, but somebody might call
    * this function directly (the symbol is exported....).
    */
    if (OSMetaClass::modHasInstance(kmodInfo->name)) {
        // xxx - Don't log under errors? this is more of an info thing
        OSRuntimeLog(theKext, kOSRuntimeLogSpec,
            "Can't tear down kext %s C++; classes have instances:",
            kmodInfo->name);
        OSKext::reportOSMetaClassInstances(kmodInfo->name, kOSRuntimeLogSpec);
        result = kOSMetaClassHasInstances;
        goto finish;
    }

   /* Tell the meta class system that we are starting to unload.
    * metaHandle isn't actually needed on the finalize path,
    * so we don't check it here, even though OSMetaClass::postModLoad() will
    * return a failure (it only does actual work on the init path anyhow).
    */
    metaHandle = OSMetaClass::preModLoad(kmodInfo->name);
    OSRuntimeUnloadCPP(kmodInfo, 0);
    (void)OSMetaClass::postModLoad(metaHandle);

    if (theKext) {
        theKext->setCPPInitialized(false);
    }
    result = KMOD_RETURN_SUCCESS;
finish:
    OSSafeRelease(theKext);
    return result;
}

// Functions used by the extenTools/kmod library project

/*********************************************************************
*********************************************************************/
kern_return_t
OSRuntimeInitializeCPP(
    kmod_info_t * kmodInfo,
    void *        data __unused)
{
    kern_return_t              result          = KMOD_RETURN_FAILURE;
    OSKext                   * theKext         = NULL;  // must release
    kernel_mach_header_t     * header          = NULL;
    void                     * metaHandle      = NULL;  // do not free
    bool                       load_success    = true;
    kernel_segment_command_t * segment         = NULL;  // do not free
    kernel_segment_command_t * failure_segment = NULL;  // do not free

    if (!kmodInfo || !kmodInfo->address) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    if (gKernelCPPInitialized) {
        theKext = OSKext::lookupKextWithIdentifier(kmodInfo->name);
    }

    if (theKext && theKext->isCPPInitialized()) {
        result = KMOD_RETURN_SUCCESS;
        goto finish;
    }

    header = (kernel_mach_header_t *)kmodInfo->address;

   /* Tell the meta class system that we are starting the load
    */
    metaHandle = OSMetaClass::preModLoad(kmodInfo->name);
    assert(metaHandle);
    if (!metaHandle) {
        goto finish;
    }

   /* NO GOTO PAST HERE. */

   /* Scan the header for all constructor sections, in any
    * segment, and invoke the constructors within those sections.
    */
    for (segment = firstsegfromheader(header);
         segment != NULL && load_success;
         segment = nextsegfromheader(header, segment)) {

        kernel_section_t * section;

       /* Record the current segment in the event of a failure.
        */
        failure_segment = segment;

        for (section = firstsect(segment);
             section != NULL;
             section = nextsect(segment, section)) {

            if (sectionIsConstructor(section)) {
                structor_t * constructors = (structor_t *)section->addr;

                if (constructors) {
                    int num_constructors = section->size / sizeof(structor_t);
                    int hit_null_constructor = 0;

                    for (int i = 0;
                         i < num_constructors &&
                         OSMetaClass::checkModLoad(metaHandle);
                         i++) {

                        if (constructors[i]) {
                            (*constructors[i])();
                        } else if (!hit_null_constructor) {
                            hit_null_constructor = 1;
                            OSRuntimeLog(theKext, kOSRuntimeLogSpec,
                                "Null constructor in kext %s segment %s!",
                                kmodInfo->name, section->segname);
                        }
                    }
                    load_success = OSMetaClass::checkModLoad(metaHandle);

                    break;
                } /* if (constructors) */
            } /* if (strncmp...) */
        } /* for (section...) */
    } /* for (segment...) */

   /* We failed so call all of the destructors. We must do this before
    * calling OSMetaClass::postModLoad() as the OSMetaClass destructors
    * will alter state (in the metaHandle) used by that function.
    */
    if (!load_success) {

       /* Scan the header for all destructor sections, in any
        * segment, and invoke the constructors within those sections.
        */
        for (segment = firstsegfromheader(header);
             segment != failure_segment && segment != 0;
             segment = nextsegfromheader(header, segment)) {

            OSRuntimeUnloadCPPForSegment(segment);

        } /* for (segment...) */
    }

   /* Now, regardless of success so far, do the post-init registration
    * and cleanup. If we had to call the unloadCPP function, static
    * destructors have removed classes from the stalled list so no
    * metaclasses will actually be registered.
    */
    result = OSMetaClass::postModLoad(metaHandle);

   /* If we've otherwise been fine up to now, but OSMetaClass::postModLoad()
    * fails (typically due to a duplicate class), tear down all the C++
    * stuff from the kext. This isn't necessary for libkern/OSMetaClass stuff,
    * but may be necessary for other C++ code. We ignore the return value
    * because it's only a fail when there are existing instances of libkern
    * classes, and there had better not be any created on the C++ init path.
    */
    if (load_success && result != KMOD_RETURN_SUCCESS) {
        (void)OSRuntimeFinalizeCPP(kmodInfo, NULL);
    }

    if (theKext && load_success && result == KMOD_RETURN_SUCCESS) {
        theKext->setCPPInitialized(true);
    }
finish:
    OSSafeRelease(theKext);
    return result;
}

#if PRAGMA_MARK
#pragma mark Libkern Init
#endif /* PRAGMA_MARK */
/*********************************************************************
* Libkern Init
*********************************************************************/

/*********************************************************************
*********************************************************************/
extern lck_grp_t * IOLockGroup;
extern kmod_info_t g_kernel_kmod_info;

void OSlibkernInit(void)
{
    // This must be called before calling OSRuntimeInitializeCPP.
    OSMetaClassBase::initialize();
    
    g_kernel_kmod_info.address = (vm_address_t) &_mh_execute_header;
    if (kOSReturnSuccess != OSRuntimeInitializeCPP(&g_kernel_kmod_info, 0)) {
        panic("OSRuntime: C++ runtime failed to initialize.");
    }
    
    gKernelCPPInitialized = true;

    return;
}

__END_DECLS

#if PRAGMA_MARK
#pragma mark C++ Allocators & Deallocators
#endif /* PRAGMA_MARK */
/*********************************************************************
* C++ Allocators & Deallocators
*********************************************************************/
void *
operator new(size_t size)
#if __cplusplus >= 201103L
								noexcept
#endif
{
    void * result;

    result = (void *) kern_os_malloc(size);
    return result;
}

void
operator delete(void * addr)
#if __cplusplus >= 201103L
								noexcept
#endif
{
    kern_os_free(addr);
    return;
}

void *
operator new[](unsigned long sz)
#if __cplusplus >= 201103L
								noexcept
#endif
{
    if (sz == 0) sz = 1;
    return kern_os_malloc(sz);
}

void
operator delete[](void * ptr)
#if __cplusplus >= 201103L
								noexcept
#endif
{
    if (ptr) {
        kern_os_free(ptr);
    }
    return;
}

/* PR-6481964 - The compiler is going to check for size overflows in calls to
 * new[], and if there is an overflow, it will call __throw_length_error.
 * This is an unrecoverable error by the C++ standard, so we must panic here.
 *
 * We have to put the function inside the std namespace because of how the
 * compiler expects the name to be mangled.
 */
namespace std {

void
__throw_length_error(const char *msg __unused)
{
    panic("Size of array created by new[] has overflowed");
}

};

