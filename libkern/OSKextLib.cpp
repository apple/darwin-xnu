/*
 * Copyright (c) 2008-2016 Apple Inc. All rights reserved.
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
#include <libkern/OSKextLibPrivate.h>
#include <libkern/mkext.h>
};

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSKext.h>
#include <libkern/OSKextLib.h>
#include <libkern/OSKextLibPrivate.h>

extern "C" {

#if PRAGMA_MARK
#pragma mark C-based kext interface (loading/loaded kexts only)
#endif
/*********************************************************************
*********************************************************************/
kern_return_t OSKextLoadKextWithIdentifier(const char * bundle_id)
{
    return OSKext::loadKextWithIdentifier(bundle_id);
}

uint32_t OSKextGetLoadTagForIdentifier(const char * kextIdentifier);
/*********************************************************************
*********************************************************************/
uint32_t
OSKextGetLoadTagForIdentifier(const char * kextIdentifier)
{
    uint32_t result  = kOSKextInvalidLoadTag;
    OSKext * theKext = NULL;  // must release

    if (!kextIdentifier) {
        goto finish;
    }

    theKext = OSKext::lookupKextWithIdentifier(kextIdentifier);
    if (theKext && theKext->isLoaded()) {
        result = theKext->getLoadTag();
    }
finish:
    if (theKext) theKext->release();
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn OSKextRetainKextWithLoadTag(uint32_t loadTag)
{
    OSReturn   result = kOSKextReturnNotFound;
    OSKext   * theKext = NULL;  // do not release; as this function is a retain

    if (loadTag == kOSKextInvalidLoadTag) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }
    theKext = OSKext::lookupKextWithLoadTag(loadTag);
    if (theKext) {
        result = kOSReturnSuccess;

        OSKextLog(theKext,
            kOSKextLogDebugLevel |
            kOSKextLogKextBookkeepingFlag,
            "Kext %s (load tag %d) has been retained.",
            theKext->getIdentifierCString(),
            loadTag);

       /* Call this after so a log message about autounload comes second.
        */
        theKext->setAutounloadEnabled(true);
    } else {
        OSKextLog(theKext,
            kOSKextLogErrorLevel |
            kOSKextLogKextBookkeepingFlag,
            "Can't retain kext with load tag %d - no such kext is loaded.",
           loadTag);
    }
finish:
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn OSKextReleaseKextWithLoadTag(uint32_t loadTag)
{
    OSReturn result  = kOSKextReturnNotFound;
    OSKext * theKext = NULL;  // must release twice!
    
    if (loadTag == kOSKextInvalidLoadTag) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }
    theKext = OSKext::lookupKextWithLoadTag(loadTag);
    if (theKext) {
        result = kOSReturnSuccess;
        OSKext::considerUnloads();  // schedule autounload pass
        theKext->release();  // do the release the caller wants
        theKext->release();  // now do the release on the lookup
        OSKextLog(theKext,
            kOSKextLogDebugLevel |
            kOSKextLogKextBookkeepingFlag,
            "Kext %s (load tag %d) has been released.",
            theKext->getIdentifierCString(),
            loadTag);
    } else {
        OSKextLog(theKext,
            kOSKextLogErrorLevel |
            kOSKextLogKextBookkeepingFlag,
            "Can't release kext with load tag %d - no such kext is loaded.",
           loadTag);
    }
    
    // xxx - should I check that the refcount of the OSKext is above the lower bound?
    // xxx - do we want a OSKextGetRetainCountOfKextWithLoadTag()?
finish:
    return result;
}

/*********************************************************************
* Not to be called by the kext being unloaded!
*********************************************************************/
OSReturn OSKextUnloadKextWithLoadTag(uint32_t loadTag)
{
    return OSKext::removeKextWithLoadTag(loadTag,
        /* terminateServicesAndRemovePersonalitiesFlag */ false);
}


#if PRAGMA_MARK
#pragma mark Kext Requests
#endif
/*********************************************************************
* Kext Requests
*********************************************************************/
OSReturn OSKextRequestResource(
    const char                    * kextIdentifier,
    const char                    * resourceName,
    OSKextRequestResourceCallback   callback,
    void                          * context,
    OSKextRequestTag              * requestTagOut)
{
    return OSKext::requestResource(kextIdentifier, resourceName,
        callback, context, requestTagOut);
}

/*********************************************************************
*********************************************************************/
OSReturn OSKextCancelRequest(
    OSKextRequestTag    requestTag,
    void             ** contextOut)
{
    return OSKext::cancelRequest(requestTag, contextOut);
}

#if PRAGMA_MARK
#pragma mark MIG Functions & Wrappers
#endif
/*********************************************************************
* IMPORTANT: Once we have done the vm_map_copyout(), we *must* return
* KERN_SUCCESS or the kernel map gets messed up (reason as yet
* unknown). We use op_result to return the real result of our work.
*********************************************************************/
kern_return_t kext_request(
    host_priv_t                             hostPriv,
    /* in only */  uint32_t                 clientLogSpec,
    /* in only */  vm_offset_t              requestIn,
    /* in only */  mach_msg_type_number_t   requestLengthIn,
    /* out only */ vm_offset_t            * responseOut,
    /* out only */ mach_msg_type_number_t * responseLengthOut,
    /* out only */ vm_offset_t            * logDataOut,
    /* out only */ mach_msg_type_number_t * logDataLengthOut,
    /* out only */ kern_return_t          * op_result)
{
    kern_return_t     result          = KERN_FAILURE;
    vm_map_address_t  map_addr        = 0;     // do not free/deallocate
    char            * request         = NULL;  // must vm_deallocate

    mkext2_header   * mkextHeader     = NULL;  // do not release
    bool              isMkext         = false;

    char            * response        = NULL;  // must kmem_free
    uint32_t          responseLength  = 0;
    char            * logData         = NULL;  // must kmem_free
    uint32_t          logDataLength   = 0;

   /* MIG doesn't pass "out" parameters as empty, so clear them immediately
    * just in case, or MIG will try to copy out bogus data.
    */    
    *op_result = KERN_FAILURE;
    *responseOut = NULL;
    *responseLengthOut = 0;
    *logDataOut = NULL;
    *logDataLengthOut = 0;

   /* Check for input. Don't discard what isn't there, though.
    */
    if (!requestLengthIn || !requestIn) {
		OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Invalid request from user space (no data).");
        *op_result = KERN_INVALID_ARGUMENT;
        goto finish;
    }

   /* Once we have done the vm_map_copyout(), we *must* return KERN_SUCCESS
    * or the kernel map gets messed up (reason as yet unknown). We will use
    * op_result to return the real result of our work.
    */
    result = vm_map_copyout(kernel_map, &map_addr, (vm_map_copy_t)requestIn);
    if (result != KERN_SUCCESS) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "vm_map_copyout() failed for request from user space.");
        vm_map_copy_discard((vm_map_copy_t)requestIn);
        goto finish;
    }
    request = CAST_DOWN(char *, map_addr);

   /* Check if request is an mkext; this is always a load request
    * and requires root access. If it isn't an mkext, see if it's
    * an XML request, and check the request to see if that requires
    * root access.
    */
    if (requestLengthIn > sizeof(mkext2_header)) {
        mkextHeader = (mkext2_header *)request;
        if (MKEXT_GET_MAGIC(mkextHeader) == MKEXT_MAGIC &&
            MKEXT_GET_SIGNATURE(mkextHeader) == MKEXT_SIGN) {

            isMkext = true;
        }
    }

    if (isMkext) {
#ifdef SECURE_KERNEL
        // xxx - something tells me if we have a secure kernel we don't even
        // xxx - want to log a message here. :-)
        *op_result = KERN_NOT_SUPPORTED;
        goto finish;
#else
        // xxx - can we find out if calling task is kextd?
        // xxx - can we find the name of the calling task?
        if (hostPriv == HOST_PRIV_NULL) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag | kOSKextLogIPCFlag,
                "Attempt by non-root process to load a kext.");
            *op_result = kOSKextReturnNotPrivileged;
            goto finish;
        }

        *op_result = OSKext::loadFromMkext((OSKextLogSpec)clientLogSpec,
            request, requestLengthIn,
            &logData, &logDataLength);

#endif /* defined(SECURE_KERNEL) */

    } else {

       /* If the request isn't an mkext, then is should be XML. Parse it
        * if possible and hand the request over to OSKext.
        */
        *op_result = OSKext::handleRequest(hostPriv,
            (OSKextLogSpec)clientLogSpec,
            request, requestLengthIn,
            &response, &responseLength,
            &logData, &logDataLength);
    }

    if (response && responseLength > 0) {
        kern_return_t copyin_result;

        copyin_result = vm_map_copyin(kernel_map,
            CAST_USER_ADDR_T(response), responseLength,
            /* src_destroy */ false, (vm_map_copy_t *)responseOut);
        if (copyin_result == KERN_SUCCESS) {
            *responseLengthOut = responseLength;
        } else {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to copy response to request from user space.");
            *op_result = copyin_result;  // xxx - should we map to our own code?
            *responseOut = NULL;
            *responseLengthOut = 0;
            goto finish;
        }
    }

    if (logData && logDataLength > 0) {
        kern_return_t copyin_result;

        copyin_result = vm_map_copyin(kernel_map,
            CAST_USER_ADDR_T(logData), logDataLength,
            /* src_destroy */ false, (vm_map_copy_t *)logDataOut);
        if (copyin_result == KERN_SUCCESS) {
            *logDataLengthOut = logDataLength;
        } else {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to copy log data for request from user space.");
            *op_result = copyin_result;  // xxx - should we map to our own code?
            *logDataOut = NULL;
            *logDataLengthOut = 0;
            goto finish;
        }
    }

finish:
    if (request) {
        (void)vm_deallocate(kernel_map, (vm_offset_t)request, requestLengthIn);
    }
    if (response) {
        /* 11981737 - clear uninitialized data in last page */
        kmem_free(kernel_map, (vm_offset_t)response, round_page(responseLength));
    }
    if (logData) {
        /* 11981737 - clear uninitialized data in last page */
        kmem_free(kernel_map, (vm_offset_t)logData, round_page(logDataLength));
    }

    return result;
}

/*********************************************************************
* Gets the vm_map for the current kext
*********************************************************************/
extern vm_offset_t segPRELINKTEXTB;
extern unsigned long segSizePRELINKTEXT;
extern int kth_started;
extern vm_map_t g_kext_map;

vm_map_t
kext_get_vm_map(kmod_info_t *info)
{
    vm_map_t kext_map = NULL;

    /* Set the vm map */
    if ((info->address >= segPRELINKTEXTB) &&
            (info->address < (segPRELINKTEXTB + segSizePRELINKTEXT)))
    {
        kext_map = kernel_map;
    } else {
        kext_map = g_kext_map;
    }

    return kext_map;
}


#if PRAGMA_MARK
/********************************************************************/
#pragma mark Weak linking support
/********************************************************************/
#endif
void
kext_weak_symbol_referenced(void)
{
    panic("A kext referenced an unresolved weak symbol\n");
}

const void *gOSKextUnresolved = (const void *)&kext_weak_symbol_referenced;

#if PRAGMA_MARK
#pragma mark Kernel-Internal C Functions
#endif
/*********************************************************************
* Called from startup.c.
*********************************************************************/
void OSKextRemoveKextBootstrap(void)
{
    OSKext::removeKextBootstrap();
    return;
}

#if CONFIG_DTRACE
/*********************************************************************
*********************************************************************/
void OSKextRegisterKextsWithDTrace(void)
{
    OSKext::registerKextsWithDTrace();
    return;
}
#endif /* CONFIG_DTRACE */

/*********************************************************************
*********************************************************************/
void kext_dump_panic_lists(int (*printf_func)(const char * fmt, ...))
{
    OSKext::printKextPanicLists(printf_func);
    return;
}

#if PRAGMA_MARK
#pragma mark Kmod Compatibility Functions
#endif
/*********************************************************************
**********************************************************************
*                    KMOD COMPATIBILITY FUNCTIONS                    *
*              (formerly in kmod.c, or C++ bridges from)             *
**********************************************************************
**********************************************************************
* These two functions are used in various places in the kernel, but
* are not exported. We might rename them at some point to start with
* kext_ or OSKext.
*
* kmod_panic_dump() must not be called outside of a panic context.
* kmod_dump_log() must not be called in a panic context.
*********************************************************************/
void
kmod_panic_dump(vm_offset_t * addr, unsigned int cnt)
{
    extern int paniclog_append_noflush(const char *format, ...) __printflike(1,2);

    OSKext::printKextsInBacktrace(addr, cnt, &paniclog_append_noflush, 0);

    return;
}

/********************************************************************/
void kmod_dump_log(vm_offset_t *addr, unsigned int cnt, boolean_t doUnslide);

void
kmod_dump_log(
    vm_offset_t * addr,
    unsigned int cnt,
    boolean_t doUnslide)
{
    uint32_t flags = OSKext::kPrintKextsLock;
    if (doUnslide) flags |= OSKext::kPrintKextsUnslide;
    OSKext::printKextsInBacktrace(addr, cnt, &printf, flags);
}

void *
OSKextKextForAddress(const void *addr)
{
    return OSKext::kextForAddress(addr);
}


/*********************************************************************
* Compatibility implementation for kmod_get_info() host_priv routine.
* Only supported on old 32-bit architectures.
*********************************************************************/

#if PRAGMA_MARK
#pragma mark Loaded Kext Summary
#endif

void 
OSKextLoadedKextSummariesUpdated(void)
{
    // Do nothing.
}

};
