/*
 * Copyright (c) 2008-2009 Apple Inc. All rights reserved.
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
#include <kern/clock.h>
#include <kern/host.h>
#include <kern/kext_alloc.h>
#include <kextd/kextd_mach.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/kext_panic_report.h>
#include <libkern/kext_request_keys.h>
#include <libkern/mkext.h>
#include <libkern/prelink.h>
#include <libkern/version.h>
#include <libkern/zlib.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
};

#include <libkern/OSKextLibPrivate.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSLib.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>

#if PRAGMA_MARK
#pragma mark External & Internal Function Protos
#endif
/*********************************************************************
*********************************************************************/
extern "C" {
// in libkern/OSKextLib.cpp, not in header for a reason.
extern kern_return_t OSKextPingKextd(void);

extern int  IODTGetLoaderInfo(const char * key, void ** infoAddr, int * infoSize);
extern void IODTFreeLoaderInfo(const char * key, void * infoAddr, int infoSize);
extern void OSRuntimeUnloadCPPForSegment(kernel_segment_command_t * segment);
extern void OSRuntimeUnloadCPP(kmod_info_t * ki, void * data);

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va); /* osfmk/machine/pmap.h */
}

static OSReturn _OSKextCreateRequest(
    const char    * predicate,
    OSDictionary ** requestP);
static OSString * _OSKextGetRequestPredicate(OSDictionary * requestDict);
static OSObject * _OSKextGetRequestArgument(
    OSDictionary * requestDict,
    const char   * argName);
static bool _OSKextSetRequestArgument(
    OSDictionary * requestDict,
    const char   * argName,
    OSObject     * value);
static void * _OSKextExtractPointer(OSData * wrapper);
static OSReturn _OSDictionarySetCStringValue(
    OSDictionary * dict,
    const char   * key,
    const char   * value);
#if CONFIG_MACF_KEXT
static void * MACFCopyModuleDataForKext(
    OSKext                 * theKext,
    mach_msg_type_number_t * datalen);
#endif /* CONFIG_MACF_KEXT */

#if PRAGMA_MARK
#pragma mark Constants & Macros
#endif
/*********************************************************************
* Constants & Macros
*********************************************************************/

/* A typical Snow Leopard system has a bit under 120 kexts loaded.
 * Use this number to create containers.
 */
#define kOSKextTypicalLoadCount      (120)

/* Any kext will have at least 1 retain for the internal lookup-by-ID dict.
 * A loaded kext will no dependents or external retains will have 2 retains.
 */
#define kOSKextMinRetainCount        (1)
#define kOSKextMinLoadedRetainCount  (2)

/**********
 * Strings and substrings used in dependency resolution.
 */
#define APPLE_KEXT_PREFIX            "com.apple."
#define KERNEL_LIB                   "com.apple.kernel"

#define PRIVATE_KPI                  "com.apple.kpi.private"

/* Version for compatbility pseudokexts (com.apple.kernel.*),
 * compatible back to v6.0.
 */
#define KERNEL6_LIB                  "com.apple.kernel.6.0"
#define KERNEL6_VERSION              "7.9.9"

#define KERNEL_LIB_PREFIX            "com.apple.kernel."
#define KPI_LIB_PREFIX               "com.apple.kpi."

#define STRING_HAS_PREFIX(s, p)      (strncmp((s), (p), strlen(p)) == 0)

/*********************************************************************
* infoDict keys for internally-stored data. Saves on ivar slots for
* objects we don't keep around past boot time or during active load.
*********************************************************************/

/* A usable, uncompressed file is stored under this key.
 */
#define _kOSKextExecutableKey                "_OSKextExecutable"

/* An indirect reference to the executable file from an mkext
 * is stored under this key.
 */
#define _kOSKextMkextExecutableReferenceKey  "_OSKextMkextExecutableReference"

/* If the file is contained in a larger buffer laid down by the booter or
 * sent from user space, the OSKext stores that OSData under this key so that
 * references are properly tracked. This is always an mkext, right now.
 */
#define _kOSKextExecutableExternalDataKey    "_OSKextExecutableExternalData"

#if PRAGMA_MARK
#pragma mark Typedefs
#endif
/*********************************************************************
* Typedefs
*********************************************************************/

/*********************************************************************
* MkextEntryRef describes the contents of an OSData object
* referencing a file entry from an mkext so that we can uncompress
* (if necessary) and extract it on demand.
*
* It contains the mkextVersion in case we ever wind up supporting
* multiple mkext formats. Mkext format 1 is officially retired as of
* Snow Leopard.
*********************************************************************/
typedef struct MkextEntryRef {
    mkext_basic_header * mkext;     // beginning of whole mkext file
    void               * fileinfo;  // mkext2_file_entry or equiv; see mkext.h
} MkextEntryRef;

#if PRAGMA_MARK
#pragma mark Global and static Module Variables
#endif
/*********************************************************************
* Global & static variables, used to keep track of kexts.
*********************************************************************/

static  bool                sPrelinkBoot               = false;
static  bool                sSafeBoot                  = false;

/******
* sKextLock is the principal lock for OSKext. Below, there is also an
* sKextInnerLock used to guard access to data accessed on in-calls from
* IOService. This 2nd lock is required to prevent a deadlock
* with IOService calling back into OSKext::considerUnloads()
* on a separate thread during a kext load operation.
*/
static IORecursiveLock    * sKextLock                  = NULL;

static OSDictionary       * sKextsByID                 = NULL;
static OSArray            * sLoadedKexts               = NULL;

// Requests to kextd waiting to be picked up.
static OSArray            * sKernelRequests            = NULL;
// Identifier of kext load requests in sKernelRequests
static OSSet              * sPostedKextLoadIdentifiers = NULL;
static OSArray            * sRequestCallbackRecords    = NULL;

// Identifiers of all kexts ever requested in kernel; used for prelinked kernel
static OSSet              * sAllKextLoadIdentifiers    = NULL;
static KXLDContext        * sKxldContext               = NULL;
static uint32_t             sNextLoadTag               = 0;
static uint32_t             sNextRequestTag            = 0;

static bool                 sUserLoadsActive           = false;
static bool                 sKextdActive               = false;
static bool                 sDeferredLoadSucceeded     = false;
static bool                 sConsiderUnloadsExecuted   = false;

static bool                 sKernelRequestsEnabled     = true;
static bool                 sLoadEnabled               = true;
static bool                 sUnloadEnabled             = true;

/*********************************************************************
* Stuff for the OSKext representing the kernel itself.
**********/
static OSKext          * sKernelKext             = NULL;

/* Set up a fake kmod_info struct for the kernel.
 * It's used in OSRuntime.cpp to call OSRuntimeInitializeCPP()
 * before OSKext is initialized; that call only needs the name
 * and address to be set correctly.
 *
 * We don't do much else with the kerne's kmod_info; we never
 * put it into the kmod list, never adjust the reference count,
 * and never have kernel components reference it.
 * For that matter, we don't do much with kmod_info structs
 * at all anymore! We just keep them filled in for gdb and
 * binary compability.
 */
kmod_info_t g_kernel_kmod_info = {
    /* next            */ 0,
    /* info_version    */ KMOD_INFO_VERSION,
    /* id              */ 0,                 // loadTag: kernel is always 0
    /* name            */ kOSKextKernelIdentifier,    // bundle identifier
    /* version         */ "0",               // filled in in OSKext::initialize()
    /* reference_count */ -1,                // never adjusted; kernel never unloads
    /* reference_list  */ NULL,
    /* address         */ (vm_address_t)&_mh_execute_header,
    /* size            */ 0,                 // filled in in OSKext::initialize()
    /* hdr_size        */ 0,
    /* start           */ 0,
    /* stop            */ 0
};

extern "C" {
// symbol 'kmod' referenced in: model_dep.c, db_trace.c, symbols.c, db_low_trace.c,
// dtrace.c, dtrace_glue.h, OSKext.cpp, locore.s, lowmem_vectors.s,
// misc_protos.h, db_low_trace.c, kgmacros
// 'kmod' is a holdover from the old kmod system, we can't rename it.
kmod_info_t * kmod = NULL;

#define KEXT_PANICLIST_SIZE  (2 * PAGE_SIZE)

static char     * unloaded_kext_paniclist        = NULL;
static uint32_t   unloaded_kext_paniclist_size   = 0;
static uint32_t   unloaded_kext_paniclist_length = 0;
AbsoluteTime      last_loaded_timestamp;

static char     * loaded_kext_paniclist          = NULL;
static uint32_t   loaded_kext_paniclist_size     = 0;
static uint32_t   loaded_kext_paniclist_length   = 0;
AbsoluteTime      last_unloaded_timestamp;
static void     * last_unloaded_address          = NULL;
#if __LP64__
static uint64_t   last_unloaded_size             = 0;
#else
static uint32_t   last_unloaded_size             = 0;
#endif /* __LP64__ */

};

/*********************************************************************
* Because we can start IOService matching from OSKext (via IOCatalogue)
* and IOService can call into OSKext, there is potential for cross-lock
* contention, so OSKext needs two locks. The regular sKextLock above
* guards most OSKext class/static variables, and sKextInnerLock guards
* variables that can be accessed on in-calls from IOService, currently:
*
*   * OSKext::considerUnloads()
*
* Note that sConsiderUnloadsExecuted above belongs to sKextLock!
*
* When both sKextLock and sKextInnerLock need to be taken,
* always lock sKextLock first and unlock it second. Never take both
* locks in an entry point to OSKext; if you need to do so, you must
* spawn an independent thread to avoid potential deadlocks for threads
* calling into OSKext.
*
* All static variables from here to the closing comment block fall
* under sKextInnerLock.
**********/
static IORecursiveLock *    sKextInnerLock             = NULL;

static bool                 sAutounloadEnabled         = true;
static bool                 sConsiderUnloadsCalled     = false;
static bool                 sConsiderUnloadsPending    = false;

static unsigned int         sConsiderUnloadDelay       = 60;     // seconds
static thread_call_t        sUnloadCallout             = 0;
static thread_call_t        sDestroyLinkContextThread  = 0;      // one-shot, one-at-a-time thread
static bool                 sSystemSleep               = false;  // true when system going to sleep

static  const OSKextLogSpec kDefaultKernelLogFilter    = kOSKextLogBasicLevel |
                                                         kOSKextLogVerboseFlagsMask;
static  OSKextLogSpec       sKernelLogFilter           = kDefaultKernelLogFilter;
static  bool                sBootArgLogFilterFound     = false;
SYSCTL_INT(_debug, OID_AUTO, kextlog, CTLFLAG_RW, &sKernelLogFilter,
    sKernelLogFilter, "kernel kext logging");

static  OSKextLogSpec       sUserSpaceKextLogFilter    = kOSKextLogSilentFilter;
static  OSArray           * sUserSpaceLogSpecArray     = NULL;
static  OSArray           * sUserSpaceLogMessageArray  = NULL;

/*********
* End scope for sKextInnerLock-protected variables.
*********************************************************************/

#if PRAGMA_MARK
#pragma mark OSData callbacks (need to move to OSData)
#endif
/*********************************************************************
* C functions used for callbacks.
*********************************************************************/
extern "C" {
void osdata_kmem_free(void * ptr, unsigned int length) {
    kmem_free(kernel_map, (vm_address_t)ptr, length);
    return;
}

void osdata_phys_free(void * ptr, unsigned int length) {
    ml_static_mfree((vm_offset_t)ptr, length);
    return;
}

void osdata_vm_deallocate(void * ptr, unsigned int length)
{
    (void)vm_deallocate(kernel_map, (vm_offset_t)ptr, length);
    return;
}
};

#if PRAGMA_MARK
#pragma mark KXLD Allocation Callback
#endif
/*********************************************************************
* KXLD Allocation Callback
*********************************************************************/
kxld_addr_t
kern_allocate(
    u_long              size,
    KXLDAllocateFlags * flags,
    void              * user_data)
{
    vm_address_t  result       = 0;     // returned
    kern_return_t mach_result  = KERN_FAILURE;
    bool          success      = false;
    OSKext      * theKext      = (OSKext *)user_data;
    u_long        roundSize    = round_page(size);
    OSData      * linkBuffer   = NULL;  // must release

    mach_result = kext_alloc(&result, roundSize, /* fixed */ FALSE);
    if (mach_result != KERN_SUCCESS) {
        OSKextLog(theKext,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag,
            "Can't allocate kernel memory to link %s.",
            theKext->getIdentifierCString());
        goto finish;
    }

   /* Create an OSData wrapper for the allocated buffer.
    * Note that we do not set a dealloc function on it here.
    * We have to call vm_map_unwire() on it in OSKext::unload()
    * and an OSData dealloc function can't take all those parameters.
    */
    linkBuffer = OSData::withBytesNoCopy((void *)result, roundSize);
    if (!linkBuffer) {
        OSKextLog(theKext,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag,
            "Can't allocate linked executable wrapper for %s.",
            theKext->getIdentifierCString());
        goto finish;
    }

    OSKextLog(theKext,
        kOSKextLogProgressLevel |
        kOSKextLogLoadFlag | kOSKextLogLinkFlag,
        "Allocated link buffer for kext %s at %p (%lu bytes).",
        theKext->getIdentifierCString(),
        (void *)result, (unsigned long)roundSize);

    theKext->setLinkedExecutable(linkBuffer);

    *flags = kKxldAllocateWritable;
    success = true;

finish:
    if (!success && result) {
        kext_free(result, roundSize);
        result = 0;
    }

    OSSafeRelease(linkBuffer);

    return (kxld_addr_t)result;
}

/*********************************************************************
*********************************************************************/
void
kxld_log_callback(
    KXLDLogSubsystem    subsystem,
    KXLDLogLevel        level,
    const char        * format,
    va_list             argList,
    void              * user_data)
{
    OSKext *theKext = (OSKext *) user_data;
    OSKextLogSpec logSpec = 0;

    switch (subsystem) {
    case kKxldLogLinking:
        logSpec |= kOSKextLogLinkFlag;
        break;
    case kKxldLogPatching:
        logSpec |= kOSKextLogPatchFlag;
        break;
    }

    switch (level) {
    case kKxldLogExplicit:
        logSpec |= kOSKextLogExplicitLevel;
        break;
    case kKxldLogErr:
        logSpec |= kOSKextLogErrorLevel;
        break;
    case kKxldLogWarn:
        logSpec |= kOSKextLogWarningLevel;
        break;
    case kKxldLogBasic:
        logSpec |= kOSKextLogProgressLevel;
        break;
    case kKxldLogDetail:
        logSpec |= kOSKextLogDetailLevel;
        break;
    case kKxldLogDebug:
        logSpec |= kOSKextLogDebugLevel;
        break;
    }

    OSKextVLog(theKext, logSpec, format, argList);
}

#if PRAGMA_MARK
#pragma mark Module Config (Startup & Shutdown)
#endif
/*********************************************************************
* Module Config (Class Definition & Class Methods)
*********************************************************************/
#define super OSObject
OSDefineMetaClassAndStructors(OSKext, OSObject)

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::initialize(void)
{
    OSData          * kernelExecutable   = NULL;  // do not release
    u_char          * kernelStart        = NULL;  // do not free
    size_t            kernelLength       = 0;
    OSString        * scratchString      = NULL;  // must release
    IORegistryEntry * registryRoot       = NULL;  // do not release
    OSNumber        * kernelCPUType      = NULL;  // must release
    OSNumber        * kernelCPUSubtype   = NULL;  // must release
    OSKextLogSpec     bootLogFilter      = kOSKextLogSilentFilter;
    bool              setResult          = false;
    uint64_t        * timestamp          = 0;
    char              bootArgBuffer[16];  // for PE_parse_boot_argn w/strings

   /* This must be the first thing allocated. Everything else grabs this lock.
    */
    sKextLock = IORecursiveLockAlloc();
    sKextInnerLock = IORecursiveLockAlloc();
    assert(sKextLock);
    assert(sKextInnerLock);

    sKextsByID = OSDictionary::withCapacity(kOSKextTypicalLoadCount);
    sLoadedKexts = OSArray::withCapacity(kOSKextTypicalLoadCount);
    sKernelRequests = OSArray::withCapacity(0);
    sPostedKextLoadIdentifiers = OSSet::withCapacity(0);
    sAllKextLoadIdentifiers = OSSet::withCapacity(kOSKextTypicalLoadCount);
    sRequestCallbackRecords = OSArray::withCapacity(0);
    assert(sKextsByID && sLoadedKexts && sKernelRequests &&
        sPostedKextLoadIdentifiers && sAllKextLoadIdentifiers &&
        sRequestCallbackRecords);

   /* Read the log flag boot-args and set the log flags.
    */
    if (PE_parse_boot_argn("kextlog", &bootLogFilter, sizeof("kextlog=0x00000000 "))) {
        sBootArgLogFilterFound = true;
        sKernelLogFilter = bootLogFilter;
        // log this if any flags are set
        OSKextLog(/* kext */ NULL,
            kOSKextLogBasicLevel |
            kOSKextLogFlagsMask,
            "Kernel kext log filter 0x%x per kextlog boot arg.",
            (unsigned)sKernelLogFilter);
    }

    sSafeBoot = PE_parse_boot_argn("-x", bootArgBuffer,
        sizeof(bootArgBuffer)) ? true : false;

    if (sSafeBoot) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogWarningLevel |
            kOSKextLogGeneralFlag,
            "SAFE BOOT DETECTED - "
            "only valid OSBundleRequired kexts will be loaded.");
    }

   /* Set up an OSKext instance to represent the kernel itself.
    */
    sKernelKext = new OSKext;
    assert(sKernelKext);

    kernelStart = (u_char *)&_mh_execute_header;
    kernelLength = getlastaddr() - (vm_offset_t)kernelStart;
    kernelExecutable = OSData::withBytesNoCopy(
        kernelStart, kernelLength);
    assert(kernelExecutable);

    sKernelKext->loadTag = sNextLoadTag++;  // the kernel is load tag 0
    sKernelKext->bundleID = OSSymbol::withCString(kOSKextKernelIdentifier);
    
    sKernelKext->version = OSKextParseVersionString(osrelease);
    sKernelKext->compatibleVersion = sKernelKext->version;
    sKernelKext->linkedExecutable = kernelExecutable;
    // linkState will be set first time we do a link
    
    sKernelKext->flags.hasAllDependencies = 1;
    sKernelKext->flags.kernelComponent = 1;
    sKernelKext->flags.prelinked = 0;
    sKernelKext->flags.loaded = 1;
    sKernelKext->flags.started = 1;
    sKernelKext->flags.CPPInitialized = 0;

    sKernelKext->kmod_info = &g_kernel_kmod_info;
    strlcpy(g_kernel_kmod_info.version, osrelease,
        sizeof(g_kernel_kmod_info.version));
    g_kernel_kmod_info.size = kernelLength;
    g_kernel_kmod_info.id = sKernelKext->loadTag;

   /* Cons up an info dict, so we don't have to have special-case
    * checking all over.
    */
    sKernelKext->infoDict = OSDictionary::withCapacity(5);
    assert(sKernelKext->infoDict);
    setResult = sKernelKext->infoDict->setObject(kCFBundleIdentifierKey,
        sKernelKext->bundleID);
    assert(setResult);
    setResult = sKernelKext->infoDict->setObject(kOSKernelResourceKey,
        kOSBooleanTrue);
    assert(setResult);
        
    scratchString = OSString::withCStringNoCopy(osrelease);
    assert(scratchString);
    setResult = sKernelKext->infoDict->setObject(kCFBundleVersionKey,
        scratchString);
    assert(setResult);
    OSSafeReleaseNULL(scratchString);

    scratchString = OSString::withCStringNoCopy("mach_kernel");
    assert(scratchString);
    setResult = sKernelKext->infoDict->setObject(kCFBundleNameKey,
        scratchString);
    assert(setResult);
    OSSafeReleaseNULL(scratchString);

   /* Add the kernel kext to the bookkeeping dictionaries. Note that
    * the kernel kext doesn't have a kmod_info struct. copyInfo()
    * gathers info from other places anyhow.
    */
    setResult = sKextsByID->setObject(sKernelKext->bundleID, sKernelKext);
    assert(setResult);
    setResult = sLoadedKexts->setObject(sKernelKext);
    assert(setResult);
    sKernelKext->release();

    registryRoot = IORegistryEntry::getRegistryRoot();
    kernelCPUType = OSNumber::withNumber(
        (long long unsigned int)_mh_execute_header.cputype,
        8 * sizeof(_mh_execute_header.cputype));
    kernelCPUSubtype = OSNumber::withNumber(
        (long long unsigned int)_mh_execute_header.cpusubtype,
        8 * sizeof(_mh_execute_header.cpusubtype));
    assert(registryRoot && kernelCPUSubtype && kernelCPUType);
    
    registryRoot->setProperty(kOSKernelCPUTypeKey, kernelCPUType);
    registryRoot->setProperty(kOSKernelCPUSubtypeKey, kernelCPUSubtype);

    OSSafeRelease(kernelCPUType);
    OSSafeRelease(kernelCPUSubtype);

    timestamp = __OSAbsoluteTimePtr(&last_loaded_timestamp);
    *timestamp = 0;
    timestamp = __OSAbsoluteTimePtr(&last_unloaded_timestamp);
    *timestamp = 0;

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogGeneralFlag,
        "Kext system initialized.");

    return;
}

/*********************************************************************
* This could be in OSKextLib.cpp but we need to hold a lock
* while removing all the segments and sKextLock will do.
*********************************************************************/
/* static */
OSReturn
OSKext::removeKextBootstrap(void)
{
    OSReturn                   result                = kOSReturnError;
    
    static bool                alreadyDone           = false;
    boolean_t                  keepsyms              = FALSE;

    const char               * dt_kernel_header_name = "Kernel-__HEADER";
    const char               * dt_kernel_symtab_name = "Kernel-__SYMTAB";
    kernel_mach_header_t     * dt_mach_header        = NULL;
    int                        dt_mach_header_size   = 0;
    struct symtab_command    * dt_symtab             = NULL;
    int                        dt_symtab_size        = 0;
    int                        dt_result             = 0;

    kernel_segment_command_t * seg_to_remove         = NULL;
#if __ppc__ || __arm__
    const char               * dt_segment_name       = NULL;
    void                     * segment_paddress      = NULL;
    int                        segment_size          = 0;
#endif

   /* This must be the very first thing done by this function.
    */
    IORecursiveLockLock(sKextLock);

   /* If we already did this, it's a success.
    */
    if (alreadyDone) {
        result = kOSReturnSuccess;
        goto finish;
    }

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogGeneralFlag,
        "Jettisoning kext bootstrap segments.");

    PE_parse_boot_argn("keepsyms", &keepsyms, sizeof(keepsyms));
 
   /*****
    * Dispose of unnecessary stuff that the booter didn't need to load.
    */
    dt_result = IODTGetLoaderInfo(dt_kernel_header_name,
        (void **)&dt_mach_header, &dt_mach_header_size);
    if (dt_result == 0 && dt_mach_header) {
        IODTFreeLoaderInfo(dt_kernel_header_name, (void *)dt_mach_header,
            round_page_32(dt_mach_header_size));
    }
    dt_result = IODTGetLoaderInfo(dt_kernel_symtab_name,
        (void **)&dt_symtab, &dt_symtab_size);
    if (dt_result == 0 && dt_symtab) {
        IODTFreeLoaderInfo(dt_kernel_symtab_name, (void *)dt_symtab,
            round_page_32(dt_symtab_size));
    }

   /*****
    * KLD bootstrap segment.
    */
    // xxx - should rename KLD segment
    seg_to_remove = getsegbyname("__KLD");
    if (seg_to_remove) {
        OSRuntimeUnloadCPPForSegment(seg_to_remove);
    }

#if __ppc__ || __arm__
   /* Free the memory that was set up by bootx.
    */
    dt_segment_name = "Kernel-__KLD";
    if (0 == IODTGetLoaderInfo(dt_segment_name, &segment_paddress, &segment_size)) {
        IODTFreeLoaderInfo(dt_segment_name, (void *)segment_paddress,
            (int)segment_size);
    }
#elif __i386__ || __x86_64__
   /* On x86, use the mapping data from the segment load command to
    * unload KLD directly.
    * This may invalidate any assumptions about  "avail_start"
    * defining the lower bound for valid physical addresses.
    */
    if (seg_to_remove && seg_to_remove->vmaddr && seg_to_remove->vmsize) {
        ml_static_mfree(seg_to_remove->vmaddr, seg_to_remove->vmsize);
    }
#else
#error arch
#endif

    seg_to_remove = NULL;

   /*****
    * Prelinked kernel's symtab (if there is one).
    */
    kernel_section_t * sect;
    sect = getsectbyname("__PRELINK", "__symtab");
    if (sect && sect->addr && sect->size) {
        ml_static_mfree(sect->addr, sect->size);
    }

   /*****
    * Dump the LINKEDIT segment, unless keepsyms is set.
    */
    if (!keepsyms) {
        seg_to_remove = (kernel_segment_command_t *)getsegbyname("__LINKEDIT");
        if (seg_to_remove) {
            OSRuntimeUnloadCPPForSegment(seg_to_remove);
        }

#if __ppc__ || __arm__
        dt_segment_name = "Kernel-__LINKEDIT";
        if (0 == IODTGetLoaderInfo(dt_segment_name,
            &segment_paddress, &segment_size)) {

            IODTFreeLoaderInfo(dt_segment_name, (void *)segment_paddress,
                (int)segment_size);
        }
#elif __i386__ || __x86_64__
        if (seg_to_remove && seg_to_remove->vmaddr && seg_to_remove->vmsize) {
            ml_static_mfree(seg_to_remove->vmaddr, seg_to_remove->vmsize);
        }
#else
#error arch
#endif
    } else {
        OSKextLog(/* kext */ NULL,
            kOSKextLogBasicLevel |
            kOSKextLogGeneralFlag,
            "keepsyms boot arg specified; keeping linkedit segment for symbols.");
    }

    seg_to_remove = NULL;

    alreadyDone = true;
    result = kOSReturnSuccess;

finish:

   /* This must be the very last thing done before returning.
    */
    IORecursiveLockUnlock(sKextLock);

    return result;
}

/*********************************************************************
*********************************************************************/
void
OSKext::flushNonloadedKexts(
    Boolean flushPrelinkedKexts)
{
    OSSet                * prelinkedKexts  = NULL;  // must release
    OSCollectionIterator * kextIterator    = NULL;  // must release
    OSCollectionIterator * prelinkIterator = NULL;  // must release
    const OSSymbol       * thisID          = NULL;  // do not release
    OSKext               * thisKext        = NULL;  // do not release
    uint32_t               count, i;

    IORecursiveLockLock(sKextLock);

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogKextBookkeepingFlag,
        "Flushing nonloaded kexts and other unused data.");

    OSKext::considerDestroyingLinkContext();

   /* If we aren't flushing unused prelinked kexts, we have to put them
    * aside while we flush everything else so make a container for them.
    */
    if (!flushPrelinkedKexts) {
        prelinkedKexts = OSSet::withCapacity(0);
        if (!prelinkedKexts) {
            goto finish;
        }
    }
    
   /* Set aside prelinked kexts (in-use or not) and break
    * any lingering inter-kext references for nonloaded kexts
    * so they have min. retain counts.
    */
    kextIterator = OSCollectionIterator::withCollection(sKextsByID);
    if (!kextIterator) {
        goto finish;
    }

    while ((thisID = OSDynamicCast(OSSymbol, 
            kextIterator->getNextObject()))) {

        thisKext = OSDynamicCast(OSKext, sKextsByID->getObject(thisID));

        if (thisKext) {
            if (prelinkedKexts && thisKext->isPrelinked()) {
                prelinkedKexts->setObject(thisKext);
            }
            thisKext->flushDependencies(/* forceIfLoaded */ false);
        }
    }

   /* Dump all the kexts in the ID dictionary; we'll repopulate it shortly.
    */
    sKextsByID->flushCollection();

   /* Now put the loaded kexts back into the ID dictionary.
    */
    count = sLoadedKexts->getCount();
    for (i = 0; i < count; i++) {
        thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        sKextsByID->setObject(thisKext->getIdentifierCString(), thisKext);
    }

   /* Finally, put back the prelinked kexts if we saved any.
    */
    if (prelinkedKexts) {
        prelinkIterator = OSCollectionIterator::withCollection(prelinkedKexts);
        if (!prelinkIterator) {
            goto finish;
        }

        while ((thisKext = OSDynamicCast(OSKext,
            prelinkIterator->getNextObject()))) {

            sKextsByID->setObject(thisKext->getIdentifierCString(),
                thisKext);
        }
    }

finish:
    IORecursiveLockUnlock(sKextLock);

    OSSafeRelease(prelinkedKexts);
    OSSafeRelease(kextIterator);
    OSSafeRelease(prelinkIterator);

    return;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::setKextdActive(Boolean active)
{
    IORecursiveLockLock(sKextLock);
    sKextdActive = active;
    if (sKernelRequests->getCount()) {
        OSKextPingKextd();
    }
    IORecursiveLockUnlock(sKextLock);

    return;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::setDeferredLoadSucceeded(Boolean succeeded)
{
    IORecursiveLockLock(sKextLock);
    sDeferredLoadSucceeded = succeeded;
    IORecursiveLockUnlock(sKextLock);

    return;
}

/*********************************************************************
* Called from IOSystemShutdownNotification.
*********************************************************************/
/* static */
void
OSKext::willShutdown(void)
{
    OSReturn       checkResult = kOSReturnError;
    OSDictionary * exitRequest = NULL;  // must release

    IORecursiveLockLock(sKextLock);

    OSKext::setLoadEnabled(false);
    OSKext::setUnloadEnabled(false);
    OSKext::setAutounloadsEnabled(false);
    OSKext::setKernelRequestsEnabled(false);

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogGeneralFlag,
        "System shutdown; requesting immediate kextd exit.");

    checkResult = _OSKextCreateRequest(kKextRequestPredicateRequestKextdExit,
        &exitRequest);
    if (checkResult != kOSReturnSuccess) {
        goto finish;
    }
    if (!sKernelRequests->setObject(exitRequest)) {
        goto finish;
    }

    OSKextPingKextd();

finish:
    IORecursiveLockUnlock(sKextLock);

    OSSafeRelease(exitRequest);
    return;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::getLoadEnabled(void)
{
    bool result;

    IORecursiveLockLock(sKextLock);
    result = sLoadEnabled;
    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::setLoadEnabled(bool flag)
{
    bool result;

    IORecursiveLockLock(sKextLock);
    result = sLoadEnabled;
    sLoadEnabled = (flag ? true : false);
    
    if (sLoadEnabled != result) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogBasicLevel |
            kOSKextLogLoadFlag,
            "Kext loading now %sabled.", sLoadEnabled ? "en" : "dis");
    }

    IORecursiveLockUnlock(sKextLock);

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::getUnloadEnabled(void)
{
    bool result;

    IORecursiveLockLock(sKextLock);
    result = sUnloadEnabled;
    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::setUnloadEnabled(bool flag)
{
    bool result;

    IORecursiveLockLock(sKextLock);
    result = sUnloadEnabled;
    sUnloadEnabled = (flag ? true : false);
    IORecursiveLockUnlock(sKextLock);
    
    if (sUnloadEnabled != result) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogBasicLevel |
            kOSKextLogGeneralFlag | kOSKextLogLoadFlag,
            "Kext unloading now %sabled.", sUnloadEnabled ? "en" : "dis");
    }

    return result;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
/* static */
bool
OSKext::getAutounloadEnabled(void)
{
    bool result;

    IORecursiveLockLock(sKextInnerLock);
    result = sAutounloadEnabled ? true : false;
    IORecursiveLockUnlock(sKextInnerLock);
    return result;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
/* static */
bool
OSKext::setAutounloadsEnabled(bool flag)
{
    bool result;

    IORecursiveLockLock(sKextInnerLock);

    result = sAutounloadEnabled;
    sAutounloadEnabled = (flag ? true : false);
    if (!sAutounloadEnabled && sUnloadCallout) {
        thread_call_cancel(sUnloadCallout);
    }
    
    if (sAutounloadEnabled != result) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogBasicLevel |
            kOSKextLogGeneralFlag | kOSKextLogLoadFlag,
            "Kext autounloading now %sabled.",
            sAutounloadEnabled ? "en" : "dis");
    }

    IORecursiveLockUnlock(sKextInnerLock);

    return result;
}

/*********************************************************************
*********************************************************************/
/* instance method operating on OSKext field */
bool
OSKext::setAutounloadEnabled(bool flag)
{
    bool result = flags.autounloadEnabled ? true : false;
    flags.autounloadEnabled = flag ? 1 : 0;
    
    if (result != (flag ? true : false)) {
        OSKextLog(this,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
            "Autounloading for kext %s now %sabled.",
            getIdentifierCString(),
            flags.autounloadEnabled ? "en" : "dis");
    }
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::setKernelRequestsEnabled(bool flag)
{
    bool result;

    IORecursiveLockLock(sKextLock);
    result = sKernelRequestsEnabled;
    sKernelRequestsEnabled = flag ? true : false;
    
    if (sKernelRequestsEnabled != result) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogBasicLevel |
            kOSKextLogGeneralFlag,
            "Kernel requests now %sabled.",
            sKernelRequestsEnabled ? "en" : "dis");
    }
    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::getKernelRequestsEnabled(void)
{
    bool result;

    IORecursiveLockLock(sKextLock);
    result = sKernelRequestsEnabled;
    IORecursiveLockUnlock(sKextLock);
    return result;
}

#if PRAGMA_MARK
#pragma mark Kext Life Cycle
#endif
/*********************************************************************
*********************************************************************/
OSKext *
OSKext::withPrelinkedInfoDict(
    OSDictionary * anInfoDict)
{
    OSKext * newKext = new OSKext;

    if (newKext && !newKext->initWithPrelinkedInfoDict(anInfoDict)) {
        newKext->release();
        return NULL;
    }

    return newKext;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::initWithPrelinkedInfoDict(
    OSDictionary * anInfoDict)
{
    bool            result              = false;
    kern_return_t   alloc_result        = KERN_SUCCESS;
    OSString      * kextPath            = NULL;  // do not release
    OSNumber      * addressNum          = NULL;  // reused; do not release
    OSNumber      * lengthNum           = NULL;  // reused; do not release
    void          * data                = NULL;  // do not free
    void          * srcData             = NULL;  // do not free
    OSData        * prelinkedExecutable = NULL;  // must release
    void          * linkStateCopy       = NULL;  // kmem_free on error
    uint32_t        linkStateLength     = 0;
    uint32_t        length              = 0;     // reused

    if (!super::init()) {
        goto finish;
    }

   /* Get the path. Don't look for an arch-specific path property.
    */
    kextPath = OSDynamicCast(OSString,
        anInfoDict->getObject(kPrelinkBundlePathKey));

    if (!setInfoDictionaryAndPath(anInfoDict, kextPath)) {
        goto finish;
    }

   /* Don't need the path to be in the info dictionary any more.
    */
    anInfoDict->removeObject(kPrelinkBundlePathKey);

   /* If we have a link state, create an OSData wrapper for it.
    */
    addressNum = OSDynamicCast(OSNumber,
        anInfoDict->getObject(kPrelinkLinkStateKey));
    if (addressNum) {
        lengthNum = OSDynamicCast(OSNumber, 
            anInfoDict->getObject(kPrelinkLinkStateSizeKey));
        if (!lengthNum) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s can't find prelinked kext link state size.",
                getIdentifierCString());
            goto finish;
        }

        data = (void *) (intptr_t) (addressNum->unsigned64BitValue());
        linkStateLength = (uint32_t) (lengthNum->unsigned32BitValue());

        anInfoDict->removeObject(kPrelinkLinkStateKey);
        anInfoDict->removeObject(kPrelinkLinkStateSizeKey);

       /* Copy the link state out of the booter-provided memory so it is in
        * the VM system and we can page it out.
        */
        alloc_result = kmem_alloc_pageable(kernel_map,
            (vm_offset_t *)&linkStateCopy, linkStateLength);
        if (alloc_result != KERN_SUCCESS) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s failed to copy prelinked link state.",
                getIdentifierCString());
            goto finish;
        }
        memcpy(linkStateCopy, data, linkStateLength);

        linkState = OSData::withBytesNoCopy(linkStateCopy, linkStateLength);
        if (!linkState) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s failed to create link state wrapper.",
                getIdentifierCString());
            goto finish;
        }
        linkState->setDeallocFunction(osdata_kmem_free);

       /* Clear linkStateCopy; the OSData owns it now so we mustn't free it.
        */
        linkStateCopy = NULL;
    }

   /* Create an OSData wrapper around the linked executable.
    */
    addressNum = OSDynamicCast(OSNumber,
        anInfoDict->getObject(kPrelinkExecutableLoadKey));
    if (addressNum) {
        lengthNum = OSDynamicCast(OSNumber,
            anInfoDict->getObject(kPrelinkExecutableSizeKey));
        if (!lengthNum) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s can't find prelinked kext executable size.",
                getIdentifierCString());
            goto finish;
        }

        data = (void *) (intptr_t) (addressNum->unsigned64BitValue());
        length = (uint32_t) (lengthNum->unsigned32BitValue());

        anInfoDict->removeObject(kPrelinkExecutableLoadKey);
        anInfoDict->removeObject(kPrelinkExecutableSizeKey);

       /* If the kext's load address differs from its source address, allocate
        * space in the kext map at the load address and copy the kext over.
        */
        addressNum = OSDynamicCast(OSNumber, anInfoDict->getObject(kPrelinkExecutableSourceKey));
        if (addressNum) {
            srcData = (void *) (intptr_t) (addressNum->unsigned64BitValue());

            if (data != srcData) {
#if __LP64__
                alloc_result = kext_alloc((vm_offset_t *)&data, length, /* fixed */ TRUE);
                if (alloc_result != KERN_SUCCESS) {
                    OSKextLog(this,
                        kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
                        "Failed to allocate space for prelinked kext %s.",
                        getIdentifierCString());
                    goto finish;
                }
                memcpy(data, srcData, length);
#else
                OSKextLog(this,
                    kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
                    "Error: prelinked kext %s - source and load addresses "
                    "differ on ILP32 architecture.",
                    getIdentifierCString());
                goto finish;
#endif /* __LP64__ */
            }

            anInfoDict->removeObject(kPrelinkExecutableSourceKey);
        }

       /* We don't need to set a dealloc function for the linked executable
        * because it is freed separately in OSKext::unload(), which must unwire
        * part of the memory.
        * xxx - do we *have* to do it that way?
        */
        prelinkedExecutable = OSData::withBytesNoCopy(data, length);
        if (!prelinkedExecutable) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
                "Kext %s failed to create executable wrapper.",
                getIdentifierCString());
            goto finish;
        }
        setLinkedExecutable(prelinkedExecutable);

        addressNum = OSDynamicCast(OSNumber,
            anInfoDict->getObject(kPrelinkKmodInfoKey));
        if (!addressNum) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag, 
                "Kext %s can't find prelinked kext kmod_info address.",
                getIdentifierCString());
            goto finish;
        }

        kmod_info = (kmod_info_t *) (intptr_t) (addressNum->unsigned64BitValue());

        anInfoDict->removeObject(kPrelinkKmodInfoKey);
    }

   /* If the plist has a UUID for an interface, save that off.
    */
    if (isInterface()) {
        interfaceUUID = OSDynamicCast(OSData,
            anInfoDict->getObject(kPrelinkInterfaceUUIDKey));
        if (interfaceUUID) {
            interfaceUUID->retain();
            anInfoDict->removeObject(kPrelinkInterfaceUUIDKey);
        }
    }

    flags.prelinked = true;

   /* If we created a kext from prelink info,
    * we must be booting from a prelinked kernel.
    */
    sPrelinkBoot = true;

    result = registerIdentifier();

finish:

   /* If we didn't hand linkStateCopy off to an OSData, free it.
    */
    if (linkStateCopy) {
        kmem_free(kernel_map, (vm_offset_t)linkStateCopy, linkStateLength);
    }
    
    OSSafeRelease(prelinkedExecutable);

    return result;
}

/*********************************************************************
*********************************************************************/
OSKext *
OSKext::withBooterData(
    OSString * deviceTreeName,
    OSData   * booterData)
{
    OSKext * newKext = new OSKext;

    if (newKext && !newKext->initWithBooterData(deviceTreeName, booterData)) {
        newKext->release();
        return NULL;
    }
    
    return newKext;
}

/*********************************************************************
*********************************************************************/
typedef struct _BooterKextFileInfo {
    uint32_t  infoDictPhysAddr;
    uint32_t  infoDictLength;
    uint32_t  executablePhysAddr;
    uint32_t  executableLength;
    uint32_t  bundlePathPhysAddr;
    uint32_t  bundlePathLength;
} _BooterKextFileInfo;

bool
OSKext::initWithBooterData(
    OSString * deviceTreeName,
    OSData   * booterData)
{
    bool                  result         = false;
    _BooterKextFileInfo * kextFileInfo   = NULL;  // do not free
    char                * infoDictAddr   = NULL;  // do not free
    void                * executableAddr = NULL;  // do not free
    char                * bundlePathAddr = NULL;  // do not free

    OSObject            * parsedXML = NULL;  // must release
    OSDictionary        * theInfoDict    = NULL;  // do not release
    OSString            * kextPath       = NULL;  // must release
    OSString            * errorString    = NULL;  // must release
    OSData              * executable     = NULL;  // must release

    if (!super::init()) {
        goto finish;
    }

    kextFileInfo = (_BooterKextFileInfo *)booterData->getBytesNoCopy();
    if (!kextFileInfo) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag, 
            "No booter-provided data for kext device tree entry %s.",
            deviceTreeName->getCStringNoCopy());
        goto finish;
    }

   /* The info plist must exist or we can't read the kext.
    */
    if (!kextFileInfo->infoDictPhysAddr || !kextFileInfo->infoDictLength) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag, 
            "No kext info dictionary for booter device tree entry %s.",
            deviceTreeName->getCStringNoCopy());
        goto finish;
    }
    
    infoDictAddr = (char *)ml_static_ptovirt(kextFileInfo->infoDictPhysAddr);
    if (!infoDictAddr) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag, 
            "Can't translate physical address 0x%x of kext info dictionary "
            "for device tree entry %s.",
            (int)kextFileInfo->infoDictPhysAddr,
            deviceTreeName->getCStringNoCopy());
        goto finish;
    }

    parsedXML = OSUnserializeXML(infoDictAddr, &errorString);
    if (parsedXML) {
        theInfoDict = OSDynamicCast(OSDictionary, parsedXML);
    }
    if (!theInfoDict) {
        const char * errorCString = "(unknown error)";
        
        if (errorString && errorString->getCStringNoCopy()) {
            errorCString = errorString->getCStringNoCopy();
        } else if (parsedXML) {
            errorCString = "not a dictionary";
        }
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag, 
            "Error unserializing info dictionary for device tree entry %s: %s.",
            deviceTreeName->getCStringNoCopy(), errorCString);
        goto finish;
    }

   /* A bundle path is not mandatory.
    */
    if (kextFileInfo->bundlePathPhysAddr && kextFileInfo->bundlePathLength) {
        bundlePathAddr = (char *)ml_static_ptovirt(kextFileInfo->bundlePathPhysAddr);
        if (!bundlePathAddr) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag, 
                "Can't translate physical address 0x%x of kext bundle path "
                "for device tree entry %s.",
                (int)kextFileInfo->bundlePathPhysAddr,
                deviceTreeName->getCStringNoCopy());
            goto finish;
        }
        bundlePathAddr[kextFileInfo->bundlePathLength-1] = '\0'; // just in case!
        
        kextPath = OSString::withCString(bundlePathAddr);
        if (!kextPath) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag, 
                "Failed to create wrapper for device tree entry %s kext path %s.",
                deviceTreeName->getCStringNoCopy(), bundlePathAddr);
            goto finish;
        }
    }

    if (!setInfoDictionaryAndPath(theInfoDict, kextPath)) {
        goto finish;
    }

   /* An executable is not mandatory.
    */
    if (kextFileInfo->executablePhysAddr && kextFileInfo->executableLength) {
        executableAddr = (void *)ml_static_ptovirt(kextFileInfo->executablePhysAddr);
        if (!executableAddr) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag, 
                "Can't translate physical address 0x%x of kext executable "
                "for device tree entry %s.",
                (int)kextFileInfo->executablePhysAddr,
                deviceTreeName->getCStringNoCopy());
            goto finish;
        }

        executable = OSData::withBytesNoCopy(executableAddr,
            kextFileInfo->executableLength);
        if (!executable) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag, 
                "Failed to create executable wrapper for device tree entry %s.",
                deviceTreeName->getCStringNoCopy());
            goto finish;
        }

       /* A kext with an executable needs to retain the whole booterData
        * object to keep the executable in memory.
        */
        if (!setExecutable(executable, booterData)) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag, 
                "Failed to set kext executable for device tree entry %s.",
                deviceTreeName->getCStringNoCopy());
            goto finish;
        }
    }

    result = registerIdentifier();

finish:
    OSSafeRelease(parsedXML);
    OSSafeRelease(kextPath);
    OSSafeRelease(errorString);
    OSSafeRelease(executable);

    return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::registerIdentifier(void)
{
    bool            result              = false;
    OSKext        * existingKext        = NULL;  // do not release
    bool            existingIsLoaded    = false;
    bool            existingIsPrelinked = false;
    OSKextVersion   newVersion          = -1;
    OSKextVersion   existingVersion     = -1;
    char            newVersionCString[kOSKextVersionMaxLength];
    char            existingVersionCString[kOSKextVersionMaxLength];
    OSData        * newUUID             = NULL;  // must release
    OSData        * existingUUID        = NULL;  // must release

   /* Get the new kext's version for checks & log messages.
    */
    newVersion = getVersion();
    OSKextVersionGetString(newVersion, newVersionCString,
        kOSKextVersionMaxLength);

   /* If we don't have an existing kext with this identifier,
    * just record the new kext and we're done!
    */
    existingKext = OSDynamicCast(OSKext, sKextsByID->getObject(bundleID));
    if (!existingKext) {
        sKextsByID->setObject(bundleID, this);
        result = true;
        goto finish;
    }

   /* Get the existing kext's version for checks & log messages.
    */
    existingVersion = existingKext->getVersion();
    OSKextVersionGetString(existingVersion,
        existingVersionCString, kOSKextVersionMaxLength);

    existingIsLoaded = existingKext->isLoaded();
    existingIsPrelinked = existingKext->isPrelinked();

   /* If we have a kext with this identifier that's already loaded/prelinked,
    * we can't use the new one, but let's be really thorough and check how
    * the two are related for a precise diagnostic log message.
    *
    * Note that user space can't find out about nonloaded prelinked kexts,
    * so in this case we log a message when new & existing are equivalent
    * at the step rather than warning level, because we are always going
    * be getting a copy of the kext in the user load request mkext.
    */
    if (existingIsLoaded || existingIsPrelinked) {
        bool sameVersion = (newVersion == existingVersion);
        bool sameExecutable = true;  // assume true unless we have UUIDs

       /* Only get the UUID if the existing kext is loaded. Doing so
        * might have to uncompress an mkext executable and we shouldn't
        * take that hit when neither kext is loaded.
        */
        newUUID = copyUUID();
        existingUUID = existingKext->copyUUID();

       /* I'm entirely too paranoid about checking equivalence of executables,
        * but I remember nasty problems with it in the past.
        *
        * - If we have UUIDs for both kexts, compare them.
        * - If only one kext has a UUID, they're definitely different.
        */
        if (newUUID && existingUUID) {
            sameExecutable = newUUID->isEqualTo(existingUUID);
        } else if (newUUID || existingUUID) {
            sameExecutable = false;
        }
        
        if (!newUUID && !existingUUID) {

           /* If there are no UUIDs, we can't really tell that the executables
            * are *different* without a lot of work; the loaded kext's
            * unrelocated executable is no longer around (and we never had it
            * in-kernel for a prelinked kext). We certainly don't want to do
            * a whole fake link for the new kext just to compare, either.
            */

            OSKextVersionGetString(version, newVersionCString,
                sizeof(newVersionCString));
            OSKextLog(this,
                kOSKextLogWarningLevel |
                kOSKextLogKextBookkeepingFlag,
                "Notice - new kext %s, v%s matches %s kext "
                "but can't determine if executables are the same (no UUIDs).",
                getIdentifierCString(),
                newVersionCString,
                (existingIsLoaded ? "loaded" : "prelinked"));
        }

        if (sameVersion && sameExecutable) {
            OSKextLog(this,
                (existingIsLoaded ? kOSKextLogWarningLevel : kOSKextLogStepLevel) |
                kOSKextLogKextBookkeepingFlag,
                "Refusing new kext %s, v%s: a %s copy is already present "
                "(same version and executable).",
                getIdentifierCString(), newVersionCString,
                (existingIsLoaded ? "loaded" : "prelinked"));
        } else {
            if (!sameVersion) {
               /* This condition is significant so log it under warnings.
                */
                OSKextLog(this,
                    kOSKextLogWarningLevel |
                    kOSKextLogKextBookkeepingFlag,
                    "Refusing new kext %s, v%s: already have %s v%s.",
                    getIdentifierCString(),
                    newVersionCString,
                    (existingIsLoaded ? "loaded" : "prelinked"),
                    existingVersionCString);
            } else {
               /* This condition is significant so log it under warnings.
                */
                OSKextLog(this,
                    kOSKextLogWarningLevel | kOSKextLogKextBookkeepingFlag,
                    "Refusing new kext %s, v%s: a %s copy with a different "
                    "executable UUID is already present.",
                    getIdentifierCString(), newVersionCString,
                    (existingIsLoaded ? "loaded" : "prelinked"));
            }
        }
        goto finish;
    } /* if (existingIsLoaded || existingIsPrelinked) */

   /* We have two nonloaded/nonprelinked kexts, so our decision depends on whether
    * user loads are happening or if we're still in early boot. User agents are
    * supposed to resolve dependencies topside and include only the exact
    * kexts needed; so we always accept the new kext (in fact we should never
    * see an older unloaded copy hanging around).
    */
    if (sUserLoadsActive) {
        sKextsByID->setObject(bundleID, this);
        result = true;

        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogKextBookkeepingFlag,
            "Dropping old copy of kext %s (v%s) for newly-added (v%s).",
            getIdentifierCString(),
            existingVersionCString,
            newVersionCString);

        goto finish;
    }
    
   /* During early boot, the kext with the highest version always wins out.
    * Prelinked kernels will never hit this, but mkexts and booter-read
    * kexts might have duplicates.
    */
    if (newVersion > existingVersion) {
        sKextsByID->setObject(bundleID, this);
        result = true;

        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogKextBookkeepingFlag,
            "Dropping lower version (v%s) of registered kext %s for higher (v%s).",
            existingVersionCString,
            getIdentifierCString(),
            newVersionCString);

    } else {
        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogKextBookkeepingFlag,
            "Kext %s is already registered with a higher/same version (v%s); "
            "dropping newly-added (v%s).",
            getIdentifierCString(),
            existingVersionCString,
            newVersionCString);
    }

   /* result has been set appropriately by now. */

finish:

    if (result) {
        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogKextBookkeepingFlag,
            "Kext %s, v%s registered and available for loading.",
            getIdentifierCString(), newVersionCString);
    }

    OSSafeRelease(newUUID);
    OSSafeRelease(existingUUID);

    return result;
}

/*********************************************************************
* Does the bare minimum validation to look up a kext.
* All other validation is done on the spot as needed.
*
* No need for lock, only called from init
**********************************************************************/
bool
OSKext::setInfoDictionaryAndPath(
    OSDictionary * aDictionary,
    OSString     * aPath)
{
    bool          result                   = false;
    OSString    * bundleIDString           = NULL;  // do not release
    OSString    * versionString            = NULL;  // do not release
    OSString    * compatibleVersionString  = NULL;  // do not release
    const char  * versionCString           = NULL;  // do not free
    const char  * compatibleVersionCString = NULL;  // do not free
    OSBoolean   * scratchBool              = NULL;  // do not release

    if (infoDict) {
        panic("Attempt to set info dictionary on a kext "
            "that already has one (%s).",
            getIdentifierCString());
    }

    if (!aDictionary || !OSDynamicCast(OSDictionary, aDictionary)) {
        goto finish;
    }

    infoDict = aDictionary;
    infoDict->retain();

   /* Check right away if the info dictionary has any log flags.
    */
    scratchBool = OSDynamicCast(OSBoolean,
        getPropertyForHostArch(kOSBundleEnableKextLoggingKey));
    if (scratchBool == kOSBooleanTrue) {
        flags.loggingEnabled = 1;
    }

   /* The very next thing to get is the bundle identifier. Unlike
    * in user space, a kext with no bundle identifier gets axed
    * immediately.
    */
    bundleIDString = OSDynamicCast(OSString,
        getPropertyForHostArch(kCFBundleIdentifierKey));
    if (!bundleIDString) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag,
            "CFBundleIdentifier missing/invalid type in kext %s.",
            aPath ? aPath->getCStringNoCopy() : "(unknown)");
        goto finish;
    }
    bundleID = OSSymbol::withString(bundleIDString);
    if (!bundleID) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag,
            "Can't copy bundle identifier as symbol for kext %s.",
            bundleIDString->getCStringNoCopy());
        goto finish;
    }

   /* Save the path if we got one (it should always be available but it's
    * just something nice to have for bookkeeping).
    */
    if (aPath) {
        path = aPath;
        path->retain();
    }

   /*****
    * Minimal validation to initialize. We'll do other validation on the spot.
    */
    if (bundleID->getLength() >= KMOD_MAX_NAME) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag,
            "Kext %s error - CFBundleIdentifier over max length %d.",
            getIdentifierCString(), KMOD_MAX_NAME - 1);
        goto finish;
    }

    version = compatibleVersion = -1;

    versionString = OSDynamicCast(OSString,
        getPropertyForHostArch(kCFBundleVersionKey));
    if (!versionString) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag,
            "Kext %s error - CFBundleVersion missing/invalid type.",
            getIdentifierCString());
        goto finish;
    }
    versionCString = versionString->getCStringNoCopy();
    version = OSKextParseVersionString(versionCString);
    if (version < 0) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag,
            "Kext %s error - CFBundleVersion bad value '%s'.",
            getIdentifierCString(), versionCString);
        goto finish;
    }

    compatibleVersion = -1;  // set to illegal value for kexts that don't have

    compatibleVersionString = OSDynamicCast(OSString,
        getPropertyForHostArch(kOSBundleCompatibleVersionKey));
    if (compatibleVersionString) {
        compatibleVersionCString = compatibleVersionString->getCStringNoCopy();
        compatibleVersion = OSKextParseVersionString(compatibleVersionCString);
        if (compatibleVersion < 0) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogValidationFlag,
                "Kext %s error - OSBundleCompatibleVersion bad value '%s'.",
                getIdentifierCString(), compatibleVersionCString);
            goto finish;
        }

        if (compatibleVersion > version) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogValidationFlag,
                "Kext %s error - %s %s > %s %s (must be <=).",
                getIdentifierCString(),
                kOSBundleCompatibleVersionKey, compatibleVersionCString,
                kCFBundleVersionKey,  versionCString);
            goto finish;
        }
    }

   /* Set flags for later use if the infoDict gets flushed. We only
    * check for true values, not false ones(!)
    */
    scratchBool = OSDynamicCast(OSBoolean,
        getPropertyForHostArch(kOSBundleIsInterfaceKey));
    if (scratchBool && scratchBool->isTrue()) {
        flags.interface = 1;
    }
    
    scratchBool = OSDynamicCast(OSBoolean,
        getPropertyForHostArch(kOSKernelResourceKey));
    if (scratchBool && scratchBool->isTrue()) {
        flags.kernelComponent = 1;
        flags.interface = 1;  // xxx - hm. the kernel itself isn't an interface...
        flags.started = 1;
        
       /* A kernel component has one implicit dependency on the kernel.
        */
        flags.hasAllDependencies = 1;
    }

    result = true;

finish:

    return result;
}

/*********************************************************************
* Not used for prelinked kernel boot as there is no unrelocated
* executable.
*********************************************************************/
bool
OSKext::setExecutable(
    OSData * anExecutable,
    OSData * externalData,
    bool     externalDataIsMkext)
{
    bool         result        = false;
    const char * executableKey = NULL;  // do not free

    if (!anExecutable) {
        infoDict->removeObject(_kOSKextExecutableKey);
        infoDict->removeObject(_kOSKextMkextExecutableReferenceKey);
        infoDict->removeObject(_kOSKextExecutableExternalDataKey);
        result = true;
        goto finish;
    }

    if (infoDict->getObject(_kOSKextExecutableKey) ||
        infoDict->getObject(_kOSKextMkextExecutableReferenceKey)) {

        panic("Attempt to set an executable on a kext "
            "that already has one (%s).",
            getIdentifierCString());
        goto finish;
    }

    if (externalDataIsMkext) {
        executableKey = _kOSKextMkextExecutableReferenceKey;
    } else {
        executableKey = _kOSKextExecutableKey;
    }

    if (anExecutable) {
        infoDict->setObject(executableKey, anExecutable);
        if (externalData) {
            infoDict->setObject(_kOSKextExecutableExternalDataKey, externalData);
        }
    }

    result = true;

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
void
OSKext::free(void)
{
    if (isLoaded()) {
        panic("Attempt to free loaded kext %s.", getIdentifierCString());
    }

    OSSafeRelease(infoDict);
    OSSafeRelease(bundleID);
    OSSafeRelease(path);
    OSSafeRelease(dependencies);
    OSSafeRelease(linkState);
    OSSafeRelease(linkedExecutable);
    OSSafeRelease(metaClasses);
    OSSafeRelease(interfaceUUID);

    if (isInterface() && kmod_info) {
        kfree(kmod_info, sizeof(kmod_info_t));
    }

    super::free();
    return;
}

#if PRAGMA_MARK
#pragma mark Mkext files
#endif
/*********************************************************************
*********************************************************************/
OSReturn
OSKext::readMkextArchive(OSData * mkextData,
    uint32_t * checksumPtr)
{
    OSReturn       result       = kOSKextReturnBadData;
    uint32_t       mkextLength  = 0;
    mkext_header * mkextHeader  = 0;   // do not free
    uint32_t       mkextVersion = 0;

   /* Note default return of kOSKextReturnBadData above.
    */
    mkextLength = mkextData->getLength();
    if (mkextLength < sizeof(mkext_basic_header)) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive too small to be valid.");
        goto finish;
    }

    mkextHeader = (mkext_header *)mkextData->getBytesNoCopy();
    
    if (MKEXT_GET_MAGIC(mkextHeader) != MKEXT_MAGIC ||
        MKEXT_GET_SIGNATURE(mkextHeader) != MKEXT_SIGN) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive has invalid magic or signature.");
        goto finish;
    }

    if (MKEXT_GET_LENGTH(mkextHeader) != mkextLength) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive recorded length doesn't match actual file length.");
        goto finish;
    }

    mkextVersion = MKEXT_GET_VERSION(mkextHeader);

    if (mkextVersion == MKEXT_VERS_2) {
        result = OSKext::readMkext2Archive(mkextData, NULL, checksumPtr);
    } else if (mkextVersion == MKEXT_VERS_1) {
        result = OSKext::readMkext1Archive(mkextData, checksumPtr);
    } else {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive of unsupported mkext version 0x%x.", mkextVersion);
        result = kOSKextReturnUnsupported;
    }

finish:
    return result;
}

/*********************************************************************
* Assumes magic, signature, version, length have been checked.
*
* Doesn't do as much bounds-checking as it should, but we're dropping
* mkext1 support from the kernel for SnowLeopard soon.
*
* Should keep track of all kexts created so far, and if we hit a
* fatal error halfway through, remove those kexts. If we've dropped
* an older version that had already been read, whoops! Might want to
* add a level of buffering?
*********************************************************************/
/* static */
OSReturn
OSKext::readMkext1Archive(
    OSData   * mkextData,
    uint32_t * checksumPtr)
{
    OSReturn        result              = kOSReturnError;
    uint32_t        mkextLength;
    mkext1_header * mkextHeader         = 0;  // do not free
    void          * mkextEnd            = 0;  // do not free
    uint32_t        mkextVersion;
    uint8_t       * crc_address         = 0;
    uint32_t        checksum;
    uint32_t        numKexts            = 0;
    
    OSData        * infoDictDataObject  = NULL;  // must release
    OSObject      * parsedXML      = NULL;  // must release
    OSDictionary  * infoDict            = NULL;  // do not release
    OSString      * errorString         = NULL;  // must release
    OSData        * mkextExecutableInfo = NULL;  // must release
    OSKext        * theKext             = NULL;  // must release

    mkextLength = mkextData->getLength();
    mkextHeader = (mkext1_header *)mkextData->getBytesNoCopy();
    mkextEnd = (char *)mkextHeader + mkextLength;
    mkextVersion = OSSwapBigToHostInt32(mkextHeader->version);

    crc_address = (u_int8_t *)&mkextHeader->version;
    checksum = mkext_adler32(crc_address,
        (uintptr_t)mkextHeader +
        OSSwapBigToHostInt32(mkextHeader->length) - (uintptr_t)crc_address);

    if (OSSwapBigToHostInt32(mkextHeader->adler32) != checksum) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
            "Kext archive has a bad checksum.");
        result = kOSKextReturnBadData;
        goto finish;
    }

    if (checksumPtr) {
        *checksumPtr = checksum;
    }

   /* Check that the CPU type & subtype match that of the running kernel. */
    if (OSSwapBigToHostInt32(mkextHeader->cputype) != (UInt32)CPU_TYPE_ANY) {
        if ((UInt32)_mh_execute_header.cputype !=
            OSSwapBigToHostInt32(mkextHeader->cputype)) {

            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
                "Kext archive doesn't contain software "
                "for this computer's CPU type.");
            result = kOSKextReturnArchNotFound;
            goto finish;
        }
    }
    
    numKexts = OSSwapBigToHostInt32(mkextHeader->numkexts);

    for (uint32_t i = 0; i < numKexts; i++) {

        OSSafeReleaseNULL(infoDictDataObject);
        OSSafeReleaseNULL(infoDict);
        OSSafeReleaseNULL(mkextExecutableInfo);
        OSSafeReleaseNULL(errorString);
        OSSafeReleaseNULL(theKext);

        mkext_kext * kextEntry = &mkextHeader->kext[i];
        mkext_file * infoDictPtr = &kextEntry->plist;
        mkext_file * executablePtr = &kextEntry->module;
        if (kextEntry >= mkextEnd) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
                "Mkext file overrun.");
            result = kOSKextReturnBadData;
            goto finish;
        }

       /* Note that we're pretty tolerant of errors in individual entries.
        * As long as we can keep processing, we do.
        */
        infoDictDataObject = OSKext::extractMkext1Entry(
            mkextHeader, infoDictPtr);
        if (!infoDictDataObject) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
                "Can't uncompress info dictionary "
                "from mkext archive entry %d.", i);
            continue;
        }

        parsedXML = OSUnserializeXML(
                (const char *)infoDictDataObject->getBytesNoCopy(),
                &errorString);
        if (parsedXML) {
            infoDict = OSDynamicCast(OSDictionary, parsedXML);
        }
        if (!infoDict) {
            const char * errorCString = "(unknown error)";
            
            if (errorString && errorString->getCStringNoCopy()) {
                errorCString = errorString->getCStringNoCopy();
            } else if (parsedXML) {
                errorCString = "not a dictionary";
            }
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
                "Error: Can't read XML property list "
                  "for mkext archive entry %d: %s.", i, errorCString);
            continue;
        }

        theKext = new OSKext;
        if (!theKext) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
                "Kext allocation failure.");
            continue;
        }

       /*****
        * Prepare an entry to hold the mkext entry info for the
        * compressed binary module, if there is one. If all four fields
        * of the module entry are zero, there isn't one.
        */
        if ((OSSwapBigToHostInt32(executablePtr->offset) ||
            OSSwapBigToHostInt32(executablePtr->compsize) ||
            OSSwapBigToHostInt32(executablePtr->realsize) ||
            OSSwapBigToHostInt32(executablePtr->modifiedsecs))) {

            MkextEntryRef entryRef;

            mkextExecutableInfo = OSData::withCapacity(sizeof(entryRef));
            if (!mkextExecutableInfo) {
                panic("Error: Couldn't allocate data object "
                      "for mkext archive entry %d.\n", i);
            }

            entryRef.mkext = (mkext_basic_header *)mkextHeader;
            entryRef.fileinfo = (uint8_t *)executablePtr;
            if (!mkextExecutableInfo->appendBytes(&entryRef,
                sizeof(entryRef))) {

                OSKextLog(/* kext */ NULL,
                    kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
                    "Couldn't record executable info "
                    "for mkext archive entry %d.", i);
                // we might hit a load error later but oh well
                // xxx - should probably remove theKext
                continue;
            }

        }

       /* Init can fail because of a data/runtime error, or because the
        * kext is a dup. Either way, we don't care here.
        */
        if (!theKext->initWithMkext1Info(infoDict, mkextExecutableInfo,
            mkextData)) {

            // theKext is released at the top of the loop or in the finish block
            continue;
        }

       /* If we got even one kext out of the mkext archive,
        * we have successfully read the archive, in that we
        * have data references into its mapped memory.
        */
        result = kOSReturnSuccess;
    }

finish:

    OSSafeRelease(infoDictDataObject);
    OSSafeRelease(parsedXML);
    OSSafeRelease(errorString);
    OSSafeRelease(mkextExecutableInfo);
    OSSafeRelease(theKext);

    return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::initWithMkext1Info(
    OSDictionary * anInfoDict,
    OSData       * executableWrapper,
    OSData       * mkextData)
{
    bool result = false;
    
    // mkext1 doesn't allow for path (might stuff in info dict)
    if (!setInfoDictionaryAndPath(anInfoDict, /* path */ NULL)) {
        goto finish;
    }

    if (!registerIdentifier()) {
        goto finish;
    }
    
    if (!setExecutable(executableWrapper, mkextData, true)) {
        goto finish;
    }
    
    result = true;
    
finish:

   /* If we can't init, remove the kext from the lookup dictionary.
    * This is safe to call in init because there's an implicit retain.
    */
    if (!result) {
        OSKext::removeKext(this, /* removePersonalities? */ false);
    }

    return result;
}

/*********************************************************************
* xxx - this should take the input data length
*********************************************************************/
/* static */
OSData *
OSKext::extractMkext1Entry(
    const void  * mkextFileBase,
    const void  * entry)
{
    OSData      * result                 = NULL;
    OSData      * uncompressedData       = NULL;  // release on error
    const char  * errmsg                 = NULL;

    mkext_file  * fileinfo;
    uint8_t     * uncompressedDataBuffer = 0; // do not free (panic on alloc. fail)
    size_t        uncompressed_size      = 0;
    kern_return_t kern_result;

    fileinfo = (mkext_file *)entry;

    size_t offset = OSSwapBigToHostInt32(fileinfo->offset);
    size_t compressed_size = OSSwapBigToHostInt32(fileinfo->compsize);
    size_t expected_size = OSSwapBigToHostInt32(fileinfo->realsize);

    // Add 1 for '\0' to terminate XML string (for plists)
    // (we really should have the archive format include that).
    size_t alloc_size = expected_size + 1;
    time_t modifiedsecs = OSSwapBigToHostInt32(fileinfo->modifiedsecs);

   /* If these four fields are zero there's no file, but it's up to
    * the calling context to decide if that's an error.
    */
    if (offset == 0 && compressed_size == 0 &&
        expected_size == 0 && modifiedsecs == 0) {
        goto finish;
    }

    kern_result = kmem_alloc(kernel_map,
        (vm_offset_t *)&uncompressedDataBuffer,
        alloc_size);
    if (kern_result != KERN_SUCCESS) {
        panic(ALLOC_FAIL);
        goto finish;
    }

    uncompressedData = OSData::withBytesNoCopy(uncompressedDataBuffer,
        alloc_size);
    if (uncompressedData == NULL) {
       /* No need to free uncompressedDataBuffer here, either. */
        panic(ALLOC_FAIL);
        goto finish;
    }
    uncompressedData->setDeallocFunction(&osdata_kmem_free);

   /* Do the decompression if necessary. Note that even if the file isn't
    * compressed, we want to make a copy so that we don't have the tie to
    * the larger mkext file buffer any more.
    * xxx - need to detect decompression overflow too
    */
    if (compressed_size != 0) {
        errmsg = "OSKext::uncompressMkext - "
            "uncompressed file shorter than expected";
        uncompressed_size = decompress_lzss(uncompressedDataBuffer,
            expected_size,
            ((uint8_t *)mkextFileBase) + offset,
            compressed_size);
        if (uncompressed_size != expected_size) {
            goto finish;
        }
    } else {
        memcpy(uncompressedDataBuffer,
            ((uint8_t *)mkextFileBase) + offset,
            expected_size);
    }

    // Add a terminating nul character in case the data is XML.
    // (we really should have the archive format include that).
    uncompressedDataBuffer[expected_size] = '\0';

    result = uncompressedData;
    errmsg = NULL;

finish:
    if (!result) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
            "%s", errmsg);

        if (uncompressedData) {
            uncompressedData->release();
        }
    }
    return result;
}

/*********************************************************************
* Assumes magic, signature, version, length have been checked.
* xxx - need to add further bounds checking for each file entry
*
* Should keep track of all kexts created so far, and if we hit a
* fatal error halfway through, remove those kexts. If we've dropped
* an older version that had already been read, whoops! Might want to
* add a level of buffering?
*********************************************************************/
/* static */
OSReturn
OSKext::readMkext2Archive(
    OSData        * mkextData,
    OSDictionary ** mkextPlistOut,
    uint32_t      * checksumPtr)
{
    OSReturn        result                     = kOSReturnError;
    uint32_t        mkextLength;
    mkext2_header * mkextHeader                = NULL;  // do not free
    void          * mkextEnd                   = NULL;  // do not free
    uint32_t        mkextVersion;
    uint8_t       * crc_address                = NULL;
    uint32_t        checksum;
    uint32_t        mkextPlistOffset;
    uint32_t        mkextPlistCompressedSize;
    char          * mkextPlistEnd              = NULL;  // do not free
    uint32_t        mkextPlistFullSize;
    OSString      * errorString                = NULL;  // must release
    OSData        * mkextPlistUncompressedData = NULL;  // must release
    const char    * mkextPlistDataBuffer       = NULL;  // do not free
    OSObject      * parsedXML           = NULL;  // must release
    OSDictionary  * mkextPlist                 = NULL;  // do not release
    OSArray       * mkextInfoDictArray         = NULL;  // do not release
    uint32_t        count, i;

    mkextLength = mkextData->getLength();
    mkextHeader = (mkext2_header *)mkextData->getBytesNoCopy();
    mkextEnd = (char *)mkextHeader + mkextLength;
    mkextVersion = MKEXT_GET_VERSION(mkextHeader);

    crc_address = (u_int8_t *)&mkextHeader->version;
    checksum = mkext_adler32(crc_address,
        (uintptr_t)mkextHeader +
        MKEXT_GET_LENGTH(mkextHeader) - (uintptr_t)crc_address);

    if (MKEXT_GET_CHECKSUM(mkextHeader) != checksum) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive has bad checksum.");
        result = kOSKextReturnBadData;
        goto finish;
    }

    if (checksumPtr) {
        *checksumPtr = checksum;
    }

   /* Check that the CPU type & subtype match that of the running kernel. */
    if (MKEXT_GET_CPUTYPE(mkextHeader) == (UInt32)CPU_TYPE_ANY) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive must have a specific CPU type.");
        result = kOSKextReturnBadData;
        goto finish;
    } else {
        if ((UInt32)_mh_execute_header.cputype !=
            MKEXT_GET_CPUTYPE(mkextHeader)) {

            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Mkext archive does not match the running kernel's CPU type.");
            result = kOSKextReturnArchNotFound;
            goto finish;
        }
    }

    mkextPlistOffset = MKEXT2_GET_PLIST(mkextHeader);
    mkextPlistCompressedSize = MKEXT2_GET_PLIST_COMPSIZE(mkextHeader);
    mkextPlistEnd = (char *)mkextHeader + mkextPlistOffset +
        mkextPlistCompressedSize;
    if (mkextPlistEnd > mkextEnd) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive file overrun.");
        result = kOSKextReturnBadData;
    }

    mkextPlistFullSize = MKEXT2_GET_PLIST_FULLSIZE(mkextHeader);
    if (mkextPlistCompressedSize) {
        mkextPlistUncompressedData = sKernelKext->extractMkext2FileData(
            (UInt8 *)mkextHeader + mkextPlistOffset,
            "plist",
            mkextPlistCompressedSize, mkextPlistFullSize);
        if (!mkextPlistUncompressedData) {
            goto finish;
        }
        mkextPlistDataBuffer = (const char *)
            mkextPlistUncompressedData->getBytesNoCopy();
    } else {
        mkextPlistDataBuffer = (const char *)mkextHeader + mkextPlistOffset;
    }

   /* IOCFSerialize added a nul byte to the end of the string. Very nice of it.
    */
    parsedXML = OSUnserializeXML(mkextPlistDataBuffer, &errorString);
    if (parsedXML) {
        mkextPlist = OSDynamicCast(OSDictionary, parsedXML);
    }
    if (!mkextPlist) {
        const char * errorCString = "(unknown error)";
        
        if (errorString && errorString->getCStringNoCopy()) {
            errorCString = errorString->getCStringNoCopy();
        } else if (parsedXML) {
            errorCString = "not a dictionary";
        }
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Error unserializing mkext plist: %s.", errorCString);
        goto finish;
    }

   /* If the caller needs the plist, hand it back and retain it.
    * (This function releases it at the end.)
    */
    if (mkextPlistOut) {
        *mkextPlistOut = mkextPlist;
        (*mkextPlistOut)->retain();
    }

    mkextInfoDictArray = OSDynamicCast(OSArray,
        mkextPlist->getObject(kMKEXTInfoDictionariesKey));
    if (!mkextInfoDictArray) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Mkext archive contains no kext info dictionaries.");
        goto finish;
    }

    count = mkextInfoDictArray->getCount();
    for (i = 0; i < count; i++) {
        OSDictionary * infoDict;


        infoDict = OSDynamicCast(OSDictionary,
            mkextInfoDictArray->getObject(i));

       /* Create the kext for the entry, then release it, because the
        * kext system keeps them around until explicitly removed.
        * Any creation/registration failures are already logged for us.
        */
        OSKext * newKext = OSKext::withMkext2Info(infoDict, mkextData);
        OSSafeRelease(newKext);
    }

   /* Even if we didn't keep any kexts from the mkext, we may have a load
    * request to process, so we are successful (no errors occurred).
    */
    result = kOSReturnSuccess;

finish:

    OSSafeRelease(parsedXML);
    OSSafeRelease(mkextPlistUncompressedData);
    OSSafeRelease(errorString);

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSKext *
OSKext::withMkext2Info(
    OSDictionary * anInfoDict,
    OSData       * mkextData)
{
    OSKext * newKext = new OSKext;

    if (newKext && !newKext->initWithMkext2Info(anInfoDict, mkextData)) {
        newKext->release();
        return NULL;
    }

    return newKext;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::initWithMkext2Info(
    OSDictionary * anInfoDict,
    OSData       * mkextData)
{
    bool                   result              = false;
    OSString             * kextPath            = NULL;  // do not release
    OSNumber             * executableOffsetNum = NULL;  // do not release
    OSCollectionIterator * iterator            = NULL;  // must release
    OSData               * executable          = NULL;  // must release

    if (!super::init()) {
        goto finish;
    }

   /* Get the path. Don't look for an arch-specific path property.
    */
    kextPath = OSDynamicCast(OSString,
        anInfoDict->getObject(kMKEXTBundlePathKey));

    if (!setInfoDictionaryAndPath(anInfoDict, kextPath)) {
        goto finish;
    }

   /* Don't need the path to be in the info dictionary any more.
    */
    anInfoDict->removeObject(kMKEXTBundlePathKey);

    executableOffsetNum = OSDynamicCast(OSNumber,
        infoDict->getObject(kMKEXTExecutableKey));
    if (executableOffsetNum) {
        executable = createMkext2FileEntry(mkextData,
            executableOffsetNum, "executable");
        infoDict->removeObject(kMKEXTExecutableKey);
        if (!executable) {
            goto finish;
        }
        if (!setExecutable(executable, mkextData, true)) {
            goto finish;
        }
    }

    result = registerIdentifier();

finish:

    OSSafeRelease(executable);
    OSSafeRelease(iterator);
    return result;
}

/*********************************************************************
*********************************************************************/
OSData *
OSKext::createMkext2FileEntry(
    OSData     * mkextData,
    OSNumber   * offsetNum,
    const char * name)
{
    OSData        * result      = NULL;
    MkextEntryRef   entryRef;
    uint8_t       * mkextBuffer = (uint8_t *)mkextData->getBytesNoCopy();
    uint32_t        entryOffset = offsetNum->unsigned32BitValue();

    result = OSData::withCapacity(sizeof(entryRef));
    if (!result) {
        goto finish;
    }

    entryRef.mkext = (mkext_basic_header *)mkextBuffer;
    entryRef.fileinfo = mkextBuffer + entryOffset;
    if (!result->appendBytes(&entryRef, sizeof(entryRef))) {
        OSSafeReleaseNULL(result);
        goto finish;
    }

finish:
    if (!result) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Can't create wrapper for mkext file entry '%s' of kext %s.",
            name, getIdentifierCString());
    }
    return result;
}

/*********************************************************************
*********************************************************************/
extern "C" {
static void * z_alloc(void *, u_int items, u_int size);
static void   z_free(void *, void *ptr);

typedef struct z_mem {
    uint32_t alloc_size;
    uint8_t  data[0];
} z_mem;

/*
 * Space allocation and freeing routines for use by zlib routines.
 */
void *
z_alloc(void * notused __unused, u_int num_items, u_int size)
{
    void     * result = NULL;
    z_mem    * zmem = NULL;
    uint32_t   total = num_items * size;
    uint32_t   allocSize =  total + sizeof(zmem);
    
    zmem = (z_mem *)kalloc(allocSize);
    if (!zmem) {
        goto finish;
    }
    zmem->alloc_size = allocSize;
    result = (void *)&(zmem->data);
finish:
    return result;
}

void
z_free(void * notused __unused, void * ptr)
{
    uint32_t * skipper = (uint32_t *)ptr - 1;
    z_mem    * zmem = (z_mem *)skipper;
    kfree((void *)zmem, zmem->alloc_size);
    return;
}
};

OSData *
OSKext::extractMkext2FileData(
    UInt8      * data,
    const char * name,
    uint32_t     compressedSize,
    uint32_t     fullSize)
{
    OSData      * result = NULL;
    
    OSData      * uncompressedData = NULL;   // release on error

    uint8_t     * uncompressedDataBuffer = 0;    // do not free
    unsigned long uncompressedSize;
    z_stream      zstream;
    bool          zstream_inited = false;
    int           zlib_result;

   /* If the file isn't compressed, we want to make a copy
    * so that we don't have the tie to the larger mkext file buffer any more.
    */
    if (!compressedSize) {
        uncompressedData = OSData::withBytes(data, fullSize);
        // xxx - no check for failure?
        result = uncompressedData;
        goto finish;
    }

    if (KERN_SUCCESS != kmem_alloc(kernel_map,
        (vm_offset_t*)&uncompressedDataBuffer, fullSize)) {

       /* How's this for cheesy? The kernel is only asked to extract
        * kext plists so we tailor the log messages.
        */
        if (this == sKernelKext) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Allocation failure extracting %s from mkext.", name);
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Allocation failure extracting %s from mkext for kext %s.",
                name, getIdentifierCString());
        }

        goto finish;
    }
    uncompressedData = OSData::withBytesNoCopy(uncompressedDataBuffer, fullSize);
    if (!uncompressedData) {
        if (this == sKernelKext) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Allocation failure extracting %s from mkext.", name);
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Allocation failure extracting %s from mkext for kext %s.",
                name, getIdentifierCString());
        }
        goto finish;
    }
    uncompressedData->setDeallocFunction(&osdata_kmem_free);

    if (this == sKernelKext) {
        OSKextLog(this,
            kOSKextLogDetailLevel |
            kOSKextLogArchiveFlag,
            "Kernel extracted %s from mkext - compressed size %d, uncompressed size %d.",
            name, compressedSize, fullSize);
    } else {
        OSKextLog(this,
            kOSKextLogDetailLevel |
            kOSKextLogArchiveFlag,
            "Kext %s extracted %s from mkext - compressed size %d, uncompressed size %d.",
            getIdentifierCString(), name, compressedSize, fullSize);
    }

    bzero(&zstream, sizeof(zstream));
    zstream.next_in   = (UInt8 *)data;
    zstream.avail_in  = compressedSize;

    zstream.next_out  = uncompressedDataBuffer;
    zstream.avail_out = fullSize;

    zstream.zalloc    = z_alloc;
    zstream.zfree     = z_free;

    zlib_result = inflateInit(&zstream);
    if (Z_OK != zlib_result) {
        if (this == sKernelKext) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Mkext error; zlib inflateInit failed (%d) for %s.",
                zlib_result, name);
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s - mkext error; zlib inflateInit failed (%d) for %s .",
                getIdentifierCString(), zlib_result, name);
        }
        goto finish;
    } else {
        zstream_inited = true;
    }

    zlib_result = inflate(&zstream, Z_FINISH);

    if (zlib_result == Z_STREAM_END || zlib_result == Z_OK) {
        uncompressedSize = zstream.total_out;
    } else {
        if (this == sKernelKext) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Mkext error; zlib inflate failed (%d) for %s.",
                zlib_result, name);
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s - mkext error; zlib inflate failed (%d) for %s .",
                getIdentifierCString(), zlib_result, name);
        }
        if (zstream.msg) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "zlib error: %s.", zstream.msg);
        }
        goto finish;
    }

    if (uncompressedSize != fullSize) {
        if (this == sKernelKext) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Mkext error; zlib inflate discrepancy for %s, "
                "uncompressed size != original size.", name);
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogArchiveFlag,
                "Kext %s - mkext error; zlib inflate discrepancy for %s, "
                "uncompressed size != original size.",
                getIdentifierCString(), name);
        }
        goto finish;
    }

    result = uncompressedData;

finish:
   /* Don't bother checking return, nothing we can do on fail.
    */
    if (zstream_inited) inflateEnd(&zstream);

    if (!result) {
        OSSafeRelease(uncompressedData);
    }

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::loadFromMkext(
    OSKextLogSpec   clientLogFilter,
    char          * mkextBuffer,
    uint32_t        mkextBufferLength,
    char         ** logInfoOut,
    uint32_t      * logInfoLengthOut)
{
    OSReturn         result                      = kOSReturnError;
    OSReturn         tempResult                  = kOSReturnError;

    OSData         * mkextData                   = NULL;  // must release
    OSDictionary   * mkextPlist                  = NULL;  // must release

    OSArray        * logInfoArray                = NULL;  // must release
    OSSerialize    * serializer                  = NULL;  // must release

    OSString       * predicate                   = NULL;  // do not release
    OSDictionary   * requestArgs                 = NULL;  // do not release

    OSString       * kextIdentifier              = NULL;  // do not release
    OSNumber       * startKextExcludeNum         = NULL;  // do not release
    OSNumber       * startMatchingExcludeNum     = NULL;  // do not release
    OSBoolean      * delayAutounloadBool         = NULL;  // do not release
    OSArray        * personalityNames            = NULL;  // do not release

   /* Default values for these two options: regular autounload behavior,
    * load all kexts, send no personalities.
    */
    Boolean            delayAutounload           = false;
    OSKextExcludeLevel startKextExcludeLevel     = kOSKextExcludeNone;
    OSKextExcludeLevel startMatchingExcludeLevel = kOSKextExcludeAll;

    IORecursiveLockLock(sKextLock);

    if (logInfoOut) {
        *logInfoOut = NULL;
        *logInfoLengthOut = 0;
    }

    OSKext::setUserSpaceLogFilter(clientLogFilter, logInfoOut ? true : false);

    OSKextLog(/* kext */ NULL,
        kOSKextLogDebugLevel |
        kOSKextLogIPCFlag,
        "Received kext load request from user space.");
    
   /* Regardless of processing, the fact that we have gotten here means some
    * user-space program is up and talking to us, so we'll switch our kext
    * registration to reflect that.
    */
    if (!sUserLoadsActive) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogProgressLevel |
            kOSKextLogGeneralFlag | kOSKextLogLoadFlag,
            "Switching to late startup (user-space) kext loading policy.");

        sUserLoadsActive = true;
    }
  
    if (!sLoadEnabled) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext loading is disabled.");
        result = kOSKextReturnDisabled;
        goto finish;
    }

   /* Note that we do not set a dealloc function on this OSData
    * object! No references to it can remain after the loadFromMkext()
    * call since we are in a MIG function, and will vm_deallocate()
    * the buffer.
    */
    mkextData = OSData::withBytesNoCopy(mkextBuffer,
        mkextBufferLength);
    if (!mkextData) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogIPCFlag,
            "Failed to create wrapper for kext load request.");
        result = kOSKextReturnNoMemory;
        goto finish;
    }

    result = readMkext2Archive(mkextData, &mkextPlist, NULL);
    if (result != kOSReturnSuccess) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Failed to read kext load request.");
        goto finish;
    }

    predicate = _OSKextGetRequestPredicate(mkextPlist);
    if (!predicate || !predicate->isEqualTo(kKextRequestPredicateLoad)) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Received kext load request with no predicate; skipping.");
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    requestArgs = OSDynamicCast(OSDictionary,
        mkextPlist->getObject(kKextRequestArgumentsKey));
    if (!requestArgs || !requestArgs->getCount()) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Received kext load request with no arguments.");
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    kextIdentifier = OSDynamicCast(OSString,
        requestArgs->getObject(kKextRequestArgumentBundleIdentifierKey));
    if (!kextIdentifier) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Received kext load request with no kext identifier.");
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    startKextExcludeNum = OSDynamicCast(OSNumber,
        requestArgs->getObject(kKextKextRequestArgumentStartExcludeKey));
    startMatchingExcludeNum = OSDynamicCast(OSNumber,
        requestArgs->getObject(kKextRequestArgumentStartMatchingExcludeKey));
    delayAutounloadBool = OSDynamicCast(OSBoolean,
        requestArgs->getObject(kKextRequestArgumentDelayAutounloadKey));
    personalityNames = OSDynamicCast(OSArray,
        requestArgs->getObject(kKextRequestArgumentPersonalityNamesKey));

    if (delayAutounloadBool) {
        delayAutounload = delayAutounloadBool->getValue();
    }
    if (startKextExcludeNum) {
        startKextExcludeLevel = startKextExcludeNum->unsigned8BitValue();
    }
    if (startMatchingExcludeNum) {
        startMatchingExcludeLevel = startMatchingExcludeNum->unsigned8BitValue();
    }
    
    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogIPCFlag,
        "Received request from user space to load kext %s.",
        kextIdentifier->getCStringNoCopy());

   /* Load the kext, with no deferral, since this is a load from outside
    * the kernel.
    * xxx - Would like a better way to handle the default values for the
    * xxx - start/match opt args.
    */
    result = OSKext::loadKextWithIdentifier(
        kextIdentifier,
        /* allowDefer */ false,
        delayAutounload,
        startKextExcludeLevel,
        startMatchingExcludeLevel,
        personalityNames);
    if (result != kOSReturnSuccess) {
        goto finish;
    }
   /* If the load came down from kextd, it will shortly inform IOCatalogue
    * for matching via a separate IOKit calldown.
    */

finish:

   /* Gather up the collected log messages for user space. Any
    * error messages past this call will not make it up as log messages
    * but will be in the system log.
    */
    logInfoArray = OSKext::clearUserSpaceLogFilter();

    if (logInfoArray && logInfoOut && logInfoLengthOut) {
        tempResult = OSKext::serializeLogInfo(logInfoArray,
            logInfoOut, logInfoLengthOut);
        if (tempResult != kOSReturnSuccess) {
            result = tempResult;
        }
    }

    OSKext::flushNonloadedKexts(/* flushPrelinkedKexts */ false);

   /* Note: mkextDataObject will have been retained by every kext w/an
    * executable in it. That should all have been flushed out at the
    * and of the load operation, but you never know....
    */
    if (mkextData && mkextData->getRetainCount() > 1) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogIPCFlag,
            "Kext load request buffer from user space still retained by a kext; "
            "probable memory leak.");
    }

    IORecursiveLockUnlock(sKextLock);

    OSSafeRelease(mkextData);
    OSSafeRelease(mkextPlist);
    OSSafeRelease(serializer);
    OSSafeRelease(logInfoArray);

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::serializeLogInfo(
    OSArray   * logInfoArray,
    char     ** logInfoOut,
    uint32_t  * logInfoLengthOut)
{
    OSReturn        result      = kOSReturnError;
    char          * buffer      = NULL;
    kern_return_t   kmem_result = KERN_FAILURE;
    OSSerialize  * serializer   = NULL;  // must release; reused
    char         * logInfo            = NULL;  // returned by reference
    uint32_t       logInfoLength      = 0;

    if (!logInfoArray || !logInfoOut || !logInfoLengthOut) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Internal error; invalid arguments to OSKext::serializeLogInfo().");
       /* Bad programmer. */
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    serializer = OSSerialize::withCapacity(0);
    if (!serializer) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Failed to create serializer on log info for request from user space.");
       /* Incidental error; we're going to (try to) allow the request
        * itself to succeed. */
    }

    if (!logInfoArray->serialize(serializer)) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Failed to serialize log info for request from user space.");
       /* Incidental error; we're going to (try to) allow the request
        * itself to succeed. */
    } else {
        logInfo = serializer->text();
        logInfoLength = serializer->getLength();

        kmem_result = kmem_alloc(kernel_map, (vm_offset_t *)&buffer, logInfoLength);
        if (kmem_result != KERN_SUCCESS) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to copy log info for request from user space.");
           /* Incidental error; we're going to (try to) allow the request
            * to succeed. */
        } else {
            memcpy(buffer, logInfo, logInfoLength);
            *logInfoOut = buffer;
            *logInfoLengthOut = logInfoLength;
        }
    }
    
    result = kOSReturnSuccess;
finish:
    OSSafeRelease(serializer);
    return result;
}

#if PRAGMA_MARK
#pragma mark Instance Management Methods
#endif
/*********************************************************************
*********************************************************************/
OSKext *
OSKext::lookupKextWithIdentifier(const char * kextIdentifier)
{
    OSKext * foundKext = NULL;

    IORecursiveLockLock(sKextLock);
    foundKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier));
    if (foundKext) {
        foundKext->retain();
    }
    IORecursiveLockUnlock(sKextLock);

    return foundKext;
}

/*********************************************************************
*********************************************************************/
OSKext *
OSKext::lookupKextWithIdentifier(OSString * kextIdentifier)
{
    return OSKext::lookupKextWithIdentifier(kextIdentifier->getCStringNoCopy());
}

/*********************************************************************
*********************************************************************/
OSKext *
OSKext::lookupKextWithLoadTag(uint32_t aTag)
{
    OSKext * foundKext = NULL;                 // returned
    uint32_t count, i;

    IORecursiveLockLock(sKextLock);
    
    count = sLoadedKexts->getCount();
    for (i = 0; i < count; i++) {
        OSKext * thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (thisKext->getLoadTag() == aTag) {
            foundKext = thisKext;
            foundKext->retain();
            goto finish;
        }
    }
    
finish:
    IORecursiveLockUnlock(sKextLock);

    return foundKext;
}

/*********************************************************************
*********************************************************************/
OSKext *
OSKext::lookupKextWithAddress(vm_address_t address)
{
    OSKext * foundKext = NULL;                 // returned
    uint32_t count, i;

    IORecursiveLockLock(sKextLock);
    
    count = sLoadedKexts->getCount();
    for (i = 0; i < count; i++) {
        OSKext * thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (thisKext->linkedExecutable) {
            vm_address_t kext_start =
                (vm_address_t)thisKext->linkedExecutable->getBytesNoCopy();
            vm_address_t kext_end = kext_start +
                thisKext->linkedExecutable->getLength();
            
            if ((kext_start <= address) && (address < kext_end)) {
                foundKext = thisKext;
                foundKext->retain();
                goto finish;
            }
        }
    }
    
finish:
    IORecursiveLockUnlock(sKextLock);

    return foundKext;
}

/*********************************************************************
*********************************************************************/
/* static */
bool OSKext::isKextWithIdentifierLoaded(const char * kextIdentifier)
{
    bool result = false;
    OSKext * foundKext = NULL;                 // returned

    IORecursiveLockLock(sKextLock);

    foundKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier));
    if (foundKext && foundKext->isLoaded()) {
        result = true;
    }

    IORecursiveLockUnlock(sKextLock);
    
    return result;
}

/*********************************************************************
* xxx - should spawn a separate thread so a kext can safely have
* xxx - itself unloaded.
*********************************************************************/
/* static */
OSReturn
OSKext::removeKext(
    OSKext * aKext,
    bool     terminateServicesAndRemovePersonalitiesFlag)
 {
    OSReturn result    = kOSKextReturnInUse;
    OSKext * checkKext = NULL;   // do not release

    IORecursiveLockLock(sKextLock);

   /* If the kext has no identifier, it failed to init
    * so isn't in sKextsByID and it isn't loaded.
    */
    if (!aKext->getIdentifier()) {
        result = kOSReturnSuccess;
        goto finish;
    }

    checkKext = OSDynamicCast(OSKext,
        sKextsByID->getObject(aKext->getIdentifier()));
    if (checkKext != aKext) {
        result = kOSKextReturnNotFound;
        goto finish;
    }

    if (aKext->isLoaded()) {
       /* If we are terminating, send the request to the IOCatalogue
        * (which will actually call us right back but that's ok we have
        * a recursive lock don't you know) but do not ask the IOCatalogue
        * to call back with an unload, we'll do that right here.
        */
        if (terminateServicesAndRemovePersonalitiesFlag) {
            result = gIOCatalogue->terminateDriversForModule(
                aKext->getIdentifierCString(), /* unload */ false);
            if (result != kOSReturnSuccess) {
                OSKextLog(aKext,
                    kOSKextLogProgressLevel |
                    kOSKextLogKextBookkeepingFlag,
                    "Can't remove kext %s; services failed to terminate - 0x%x.",
                    aKext->getIdentifierCString(), result);
                goto finish;
            }
        }

        result = aKext->unload();
        if (result != kOSReturnSuccess) {
            goto finish;
        }
    }
    
   /* Remove personalities as requested. This is a bit redundant for a loaded
    * kext as IOCatalogue::terminateDriversForModule() removes driver
    * personalities, but it doesn't restart matching, which we always want
    * coming from here, and OSKext::removePersonalitiesFromCatalog() ensures
    * that happens.
    */
    if (terminateServicesAndRemovePersonalitiesFlag) {
        aKext->removePersonalitiesFromCatalog();
    }

    OSKextLog(aKext,
        kOSKextLogProgressLevel |
        kOSKextLogKextBookkeepingFlag,
        "Removing kext %s.",
        aKext->getIdentifierCString());

    sKextsByID->removeObject(aKext->getIdentifier());
    result = kOSReturnSuccess;

finish:
    IORecursiveLockUnlock(sKextLock);
    return result;
 }

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::removeKextWithIdentifier(
    const char * kextIdentifier,
    bool         terminateServicesAndRemovePersonalitiesFlag)
{
    OSReturn result = kOSReturnError;

    IORecursiveLockLock(sKextLock);
    
    OSKext * aKext = OSDynamicCast(OSKext,
        sKextsByID->getObject(kextIdentifier));
    if (!aKext) {
        result = kOSKextReturnNotFound;
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogKextBookkeepingFlag,
            "Can't remove kext %s - not found.",
            kextIdentifier);
        goto finish;
    }

    result = OSKext::removeKext(aKext,
        terminateServicesAndRemovePersonalitiesFlag);

finish:
    IORecursiveLockUnlock(sKextLock);
    
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::removeKextWithLoadTag(
    OSKextLoadTag loadTag,
    bool          terminateServicesAndRemovePersonalitiesFlag)
{
    OSReturn result    = kOSReturnError;
    OSKext * foundKext = NULL;
    uint32_t count, i;

    IORecursiveLockLock(sKextLock);

    count = sLoadedKexts->getCount();
    for (i = 0; i < count; i++) {
        OSKext * thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (thisKext->loadTag == loadTag) {
            foundKext = thisKext;
            break;
        }
    }
    
    if (!foundKext) {
        result = kOSKextReturnNotFound;
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
            "Can't remove kext with load tag %d - not found.",
            loadTag);
        goto finish;
    }

    result = OSKext::removeKext(foundKext,
        terminateServicesAndRemovePersonalitiesFlag);

finish:
    IORecursiveLockUnlock(sKextLock);
    
    return result;
 }

/*********************************************************************
*********************************************************************/
OSDictionary *
OSKext::copyKexts(void)
{
    OSDictionary * result;

    IORecursiveLockLock(sKextLock);
    result = OSDynamicCast(OSDictionary, sKextsByID->copyCollection());
    IORecursiveLockUnlock(sKextLock);

    return result;
}
 
#if PRAGMA_MARK
#pragma mark Accessors
#endif
/*********************************************************************
*********************************************************************/
const OSSymbol *
OSKext::getIdentifier(void)
{
    return bundleID;
}

/*********************************************************************
* A kext must have a bundle identifier to even survive initialization;
* this is guaranteed to exist past then.
*********************************************************************/
const char *
OSKext::getIdentifierCString(void)
{
    return bundleID->getCStringNoCopy();
}

/*********************************************************************
*********************************************************************/
OSKextVersion
OSKext::getVersion(void)
{
    return version;
}

/*********************************************************************
*********************************************************************/
OSKextVersion
OSKext::getCompatibleVersion(void)
{
    return compatibleVersion;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isCompatibleWithVersion(OSKextVersion aVersion)
{
    if ((compatibleVersion > -1 && version > -1) &&
        (compatibleVersion <= version && aVersion <= version)) {
        return true;
    }
    return false;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::declaresExecutable(void)
{
    if (getPropertyForHostArch(kCFBundleExecutableKey)) {
        return true;
     }
     return false;
}

/*********************************************************************
*********************************************************************/
OSData *
OSKext::getExecutable(void)
{
    OSData * result              = NULL;
    OSData * extractedExecutable = NULL;  // must release
    OSData * mkextExecutableRef  = NULL;  // do not release

    result = OSDynamicCast(OSData, infoDict->getObject(_kOSKextExecutableKey));
    if (result) {
        goto finish;
    }

    mkextExecutableRef = OSDynamicCast(OSData,
        getPropertyForHostArch(_kOSKextMkextExecutableReferenceKey));

    if (mkextExecutableRef) {

        MkextEntryRef * mkextEntryRef = (MkextEntryRef *)
            mkextExecutableRef->getBytesNoCopy();
        uint32_t mkextVersion = MKEXT_GET_VERSION(mkextEntryRef->mkext);
        if (mkextVersion == MKEXT_VERS_2) {
            mkext2_file_entry * fileinfo =
                (mkext2_file_entry *)mkextEntryRef->fileinfo;
            uint32_t compressedSize = MKEXT2_GET_ENTRY_COMPSIZE(fileinfo);
            uint32_t fullSize = MKEXT2_GET_ENTRY_FULLSIZE(fileinfo);
            extractedExecutable = extractMkext2FileData(
                MKEXT2_GET_ENTRY_DATA(fileinfo), "executable",
                compressedSize, fullSize);
        } else if (mkextVersion == MKEXT_VERS_1) {
            extractedExecutable = extractMkext1Entry(
                mkextEntryRef->mkext, mkextEntryRef->fileinfo);
        } else {
            OSKextLog(this, kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
                "Kext %s - unknown mkext version 0x%x for executable.",
                getIdentifierCString(), mkextVersion);
        }

       /* Regardless of success, remove the mkext executable,
        * and drop one reference on the mkext.  (setExecutable() does not
        * replace, it removes, or panics if asked to replace.)
        */        
        infoDict->removeObject(_kOSKextMkextExecutableReferenceKey);
        infoDict->removeObject(_kOSKextExecutableExternalDataKey);

        if (extractedExecutable && extractedExecutable->getLength()) {
            if (!setExecutable(extractedExecutable)) {
                goto finish;
            }
            result = extractedExecutable;
        } else {
            goto finish;
        }
    }

finish:

    OSSafeRelease(extractedExecutable);

    return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isInterface(void)
{
    return flags.interface;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isKernelComponent(void)
{
    return flags.kernelComponent ? true : false;
}

/*********************************************************************
* We might want to check this recursively for all dependencies,
* since a subtree of dependencies could get loaded before we hit
* a dependency that isn't safe-boot-loadable.
*
* xxx - Might want to return false if OSBundleEnableKextLogging or
* OSBundleDebugLevel
* or IOKitDebug is nonzero too (we used to do that, but I don't see
* the point except it's usually development drivers, which might
* cause panics on startup, that have those properties). Heh; could
* use a "kx" boot-arg!
*********************************************************************/
bool
OSKext::isLoadableInSafeBoot(void)
{
    bool       result   = false;
    OSString * required = NULL;  // do not release
    
    
    required = OSDynamicCast(OSString,
        getPropertyForHostArch(kOSBundleRequiredKey));
    if (!required) {
        goto finish;
    }
    if (required->isEqualTo(kOSBundleRequiredRoot)        ||
        required->isEqualTo(kOSBundleRequiredLocalRoot)   ||
        required->isEqualTo(kOSBundleRequiredNetworkRoot) ||
        required->isEqualTo(kOSBundleRequiredSafeBoot)    ||
        required->isEqualTo(kOSBundleRequiredConsole)) {
        
        result = true;
    }
    
finish:
    return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isPrelinked(void)
{
    return flags.prelinked ? true : false;
}

/*********************************************************************
*********************************************************************/
bool OSKext::isLoaded(void)
{
    return flags.loaded ? true : false;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isStarted(void)
{
    return flags.started ? true : false;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isCPPInitialized(void)
{
    return flags.CPPInitialized;
}

/*********************************************************************
*********************************************************************/
void
OSKext::setCPPInitialized(bool initialized)
{
    flags.CPPInitialized = initialized;
}

/*********************************************************************
*********************************************************************/
uint32_t
OSKext::getLoadTag(void)
{
    return loadTag;
}

/*********************************************************************
*********************************************************************/
OSData *
OSKext::copyUUID(void)
{
    OSData                     * result        = NULL;
    OSData                     * theExecutable = NULL;  // do not release
    const kernel_mach_header_t * header        = NULL;
    const struct load_command  * load_cmd      = NULL;
    const struct uuid_command  * uuid_cmd      = NULL;
    uint32_t                     i;

   /* An interface kext doesn't have a linked executable with an LC_UUID,
    * we create one when it's linked.
    */
    if (interfaceUUID) {
        result = interfaceUUID;
        result->retain();
        goto finish;
    }

   /* For real kexts, try to get the UUID from the linked executable,
    * or if is hasn't been linked yet, the unrelocated executable.
    */
    theExecutable = linkedExecutable;
    if (!theExecutable) {
        theExecutable = getExecutable();
    }
    if (!theExecutable) {
        goto finish;
    }

    header = (const kernel_mach_header_t *)theExecutable->getBytesNoCopy();
    load_cmd = (const struct load_command *)&header[1];

    for (i = 0; i < header->ncmds; i++) {
        if (load_cmd->cmd == LC_UUID) {
            uuid_cmd = (struct uuid_command *)load_cmd;
            result = OSData::withBytes(uuid_cmd->uuid, sizeof(uuid_cmd->uuid));
            goto finish;
        }
        load_cmd = (struct load_command *)((caddr_t)load_cmd + load_cmd->cmdsize);
    }

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
#if defined (__ppc__)
#define ARCHNAME "ppc"
#elif defined (__i386__)
#define ARCHNAME "i386"
#elif defined (__x86_64__)
#define ARCHNAME "x86_64"
#else
#error architecture not supported
#endif

#define ARCH_SEPARATOR_CHAR  '_'

static char * makeHostArchKey(const char * key, uint32_t * keySizeOut)
{
    char     * result = NULL;
    uint32_t   keyLength = strlen(key);
    uint32_t   keySize;

   /* Add 1 for the ARCH_SEPARATOR_CHAR, and 1 for the '\0'.
    */
    keySize = 1 + 1 + strlen(key) + strlen(ARCHNAME);
    result = (char *)kalloc(keySize);
    if (!result) {
        goto finish;
    }
    strlcpy(result, key, keySize);
    result[keyLength++] = ARCH_SEPARATOR_CHAR;
    result[keyLength] = '\0';
    strlcat(result, ARCHNAME, keySize);
    *keySizeOut = keySize;

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
OSObject *
OSKext::getPropertyForHostArch(const char * key)
{
    OSObject * result           = NULL;  // do not release
    uint32_t   hostArchKeySize  = 0;
    char     * hostArchKey      = NULL;  // must kfree
    
    if (!key || !infoDict) {
        goto finish;
    }
    
   /* Some properties are not allowed to be arch-variant:
    * - Any CFBundle... property.
    * - OSBundleIsInterface.
    * - OSKernelResource.
    */
    if (STRING_HAS_PREFIX(key, "OS") ||
        STRING_HAS_PREFIX(key, "IO")) {

        hostArchKey = makeHostArchKey(key, &hostArchKeySize);
        if (!hostArchKey) {
            OSKextLog(/* kext (this isn't about a kext) */ NULL,
                kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
                "Allocation failure.");
            goto finish;
        }
        result = infoDict->getObject(hostArchKey);
    }
    
    if (!result) {
        result = infoDict->getObject(key);
    }

finish:
    if (hostArchKey) kfree(hostArchKey, hostArchKeySize);
    return result;
}

#if PRAGMA_MARK
#pragma mark Load/Start/Stop/Unload
#endif
/*********************************************************************
*********************************************************************/
OSReturn
OSKext::loadKextWithIdentifier(
    const char       * kextIdentifierCString,
    Boolean            allowDeferFlag,
    Boolean            delayAutounloadFlag,
    OSKextExcludeLevel startOpt,
    OSKextExcludeLevel startMatchingOpt,
    OSArray          * personalityNames)
{
    OSReturn   result         = kOSReturnError;
    OSString * kextIdentifier = NULL;  // must release

    kextIdentifier = OSString::withCString(kextIdentifierCString);
    if (!kextIdentifier) {
        result = kOSKextReturnNoMemory;
        goto finish;
    }
    result = OSKext::loadKextWithIdentifier(kextIdentifier,
        allowDeferFlag, delayAutounloadFlag,
        startOpt, startMatchingOpt, personalityNames);
        
finish:
    OSSafeRelease(kextIdentifier);
    return result;
}


/*********************************************************************
*********************************************************************/
OSReturn
OSKext::loadKextWithIdentifier(
    OSString          * kextIdentifier,
    Boolean             allowDeferFlag,
    Boolean             delayAutounloadFlag,
    OSKextExcludeLevel  startOpt,
    OSKextExcludeLevel  startMatchingOpt,
    OSArray           * personalityNames)
{
    OSReturn          result               = kOSReturnError;
    OSKext          * theKext              = NULL;  // do not release
    OSDictionary    * loadRequest          = NULL;  // must release
    const OSSymbol  * kextIdentifierSymbol = NULL;  // must release

    IORecursiveLockLock(sKextLock);

    if (!kextIdentifier) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    OSKext::recordIdentifierRequest(kextIdentifier);

    theKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier));
    if (!theKext) {
        if (!allowDeferFlag) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Can't load kext %s - not found.",
                kextIdentifier->getCStringNoCopy());
             goto finish;
        }
        
        if (!sKernelRequestsEnabled) {
            OSKextLog(theKext,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Can't load kext %s - requests to user space are disabled.",
                kextIdentifier->getCStringNoCopy());
            result = kOSKextReturnDisabled;
            goto finish;
        }

       /* Create a new request unless one is already sitting
        * in sKernelRequests for this bundle identifier
        */
        kextIdentifierSymbol = OSSymbol::withString(kextIdentifier);
        if (!sPostedKextLoadIdentifiers->containsObject(kextIdentifierSymbol)) {
            result = _OSKextCreateRequest(kKextRequestPredicateRequestLoad,
                &loadRequest);
            if (result != kOSReturnSuccess) {
                goto finish;
            }
            if (!_OSKextSetRequestArgument(loadRequest,
                kKextRequestArgumentBundleIdentifierKey, kextIdentifier)) {
                
                result = kOSKextReturnNoMemory;
                goto finish;
            }
            if (!sKernelRequests->setObject(loadRequest)) {
                result = kOSKextReturnNoMemory;
                goto finish;
            }
            
            if (!sPostedKextLoadIdentifiers->setObject(kextIdentifierSymbol)) {
                result = kOSKextReturnNoMemory;
                goto finish;
            }

            OSKextLog(theKext,
                kOSKextLogDebugLevel |
                kOSKextLogLoadFlag,
                "Kext %s not found; queued load request to user space.",
                kextIdentifier->getCStringNoCopy());
        }

        if (sKextdActive) {
            OSKextPingKextd();
        } else {
            OSKextLog(/* kext */ NULL,
                ((sPrelinkBoot) ? kOSKextLogDebugLevel : kOSKextLogErrorLevel) |
                kOSKextLogLoadFlag,
                "Not loading kext %s - not found and kextd not available in early boot.",
                kextIdentifier->getCStringNoCopy());
        }

        result = kOSKextReturnDeferred;
        goto finish;
    }

    result = theKext->load(startOpt, startMatchingOpt, personalityNames);

    if (result != kOSReturnSuccess) {
        OSKextLog(theKext,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Failed to load kext %s (error 0x%x).",
            kextIdentifier->getCStringNoCopy(), (int)result);

        OSKext::removeKext(theKext,
            /* terminateService/removePersonalities */ true);
        goto finish;
    }

    if (delayAutounloadFlag) {
        OSKextLog(theKext,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
            "Setting delayed autounload for %s.",
            kextIdentifier->getCStringNoCopy());
        theKext->flags.delayAutounload = 1;
    }

finish:
    OSSafeRelease(loadRequest);
    OSSafeRelease(kextIdentifierSymbol);
    
    IORecursiveLockUnlock(sKextLock);

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::recordIdentifierRequest(
    OSString * kextIdentifier)
{
    const OSSymbol * kextIdentifierSymbol = NULL;  // must release
    bool             fail                 = false;

    if (!sAllKextLoadIdentifiers || !kextIdentifier) {
        goto finish;
    }

    kextIdentifierSymbol = OSSymbol::withString(kextIdentifier);
    if (!kextIdentifierSymbol) {
        // xxx - this is really a basic alloc failure
        fail = true;
        goto finish;
    }

    if (!sAllKextLoadIdentifiers->containsObject(kextIdentifierSymbol)) {
        if (!sAllKextLoadIdentifiers->setObject(kextIdentifierSymbol)) {
            fail = true;
        } else {
            // xxx - need to find a way to associate this whole func w/the kext
            OSKextLog(/* kext */ NULL,
                // xxx - check level
                kOSKextLogStepLevel |
                kOSKextLogArchiveFlag,
                "Recorded kext %s as a candidate for inclusion in prelinked kernel.",
                kextIdentifier->getCStringNoCopy());
        }
    }
finish:

    if (fail) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Failed to record kext %s as a candidate for inclusion in prelinked kernel.",
            kextIdentifier->getCStringNoCopy());
    }
    OSSafeRelease(kextIdentifierSymbol);
    return;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::load(
    OSKextExcludeLevel   startOpt,
    OSKextExcludeLevel   startMatchingOpt,
    OSArray            * personalityNames)
{
    OSReturn             result                       = kOSReturnError;
    kern_return_t        kxldResult;
    OSKextExcludeLevel   dependenciesStartOpt         = startOpt;
    OSKextExcludeLevel   dependenciesStartMatchingOpt = startMatchingOpt;
    unsigned int         i, count;
    Boolean              alreadyLoaded                = false;
    OSKext             * lastLoadedKext               = NULL;

    if (isLoaded()) {
        alreadyLoaded = true;
        result = kOSReturnSuccess;

        OSKextLog(this,
            kOSKextLogDebugLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
            "Kext %s is already loaded.",
            getIdentifierCString());
        goto loaded;
    }

    if (!sLoadEnabled) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext loading is disabled (attempt to load kext %s).",
            getIdentifierCString());
        result = kOSKextReturnDisabled;
        goto finish;
    }

   /* If we've pushed the next available load tag to the invalid value,
    * we can't load any more kexts.
    */
    if (sNextLoadTag == kOSKextInvalidLoadTag) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Can't load kext %s - no more load tags to assign.",
            getIdentifierCString());
        result = kOSKextReturnNoResources;
        goto finish;
    }

   /* This is a bit of a hack, because we shouldn't be handling 
    * personalities within the load function.
    */
    if (!declaresExecutable()) {
        result = kOSReturnSuccess;
        goto loaded;
    }

   /* Are we in safe boot?
    */
    if (sSafeBoot && !isLoadableInSafeBoot()) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Can't load kext %s - not loadable during safe boot.",
            getIdentifierCString());
        result = kOSKextReturnBootLevel;
        goto finish;
    }

    OSKextLog(this,
        kOSKextLogProgressLevel | kOSKextLogLoadFlag,
        "Loading kext %s.",
        getIdentifierCString());


    if (!sKxldContext) {
        kxldResult = kxld_create_context(&sKxldContext, &kern_allocate, 
            &kxld_log_callback, /* Flags */ (KXLDFlags) 0, 
            /* cputype */ 0, /* cpusubtype */ 0);
        if (kxldResult) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag | kOSKextLogLinkFlag,
                "Can't load kext %s - failed to create link context.",
                getIdentifierCString());
            result = kOSKextReturnNoMemory;
            goto finish;
        }
    }
    
    /* We only need to resolve dependencies once for the whole graph, but
     * resolveDependencies will just return if there's no work to do, so it's
     * safe to call it more than once.
     */
    if (!resolveDependencies()) {
        // xxx - check resolveDependencies() for log msg
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogDependenciesFlag,
            "Can't load kext %s - failed to resolve library dependencies.",
            getIdentifierCString());
        result = kOSKextReturnDependencies;
        goto finish;
    }

   /* If we are excluding just the kext being loaded now (and not its
    * dependencies), drop the exclusion level to none so dependencies
    * start and/or add their personalities.
    */
    if (dependenciesStartOpt == kOSKextExcludeKext) {
        dependenciesStartOpt = kOSKextExcludeNone;
    }

    if (dependenciesStartMatchingOpt == kOSKextExcludeKext) {
        dependenciesStartMatchingOpt = kOSKextExcludeNone;
    }

   /* Load the dependencies, recursively.
    */
    count = getNumDependencies();
    for (i = 0; i < count; i++) {
        OSKext * dependency = OSDynamicCast(OSKext,
            dependencies->getObject(i));
        if (dependency == NULL) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag | kOSKextLogDependenciesFlag,
                "Internal error loading kext %s; dependency disappeared.",
                getIdentifierCString());
            result = kOSKextReturnInternalError;
            goto finish;
        }
        
       /* Dependencies must be started accorting to the opt,
        * but not given the personality names of the main kext.
        */
        result = dependency->load(dependenciesStartOpt,
            dependenciesStartMatchingOpt,
            /* personalityNames */ NULL);
        if (result != KERN_SUCCESS) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag | kOSKextLogDependenciesFlag,
                "Dependency %s of kext %s failed to load.",
                dependency->getIdentifierCString(),
                getIdentifierCString());

            OSKext::removeKext(dependency,
                /* terminateService/removePersonalities */ true);
            result = kOSKextReturnDependencyLoadError;

            goto finish;
        }
    }

    result = loadExecutable();
    if (result != KERN_SUCCESS) {
        goto finish;
    }

    flags.loaded = true;

   /* Add the kext to the list of loaded kexts and update the kmod_info
    * struct to point to that of the last loaded kext (which is the way
    * it's always been done, though I'd rather do them in order now).
    */
    lastLoadedKext = OSDynamicCast(OSKext, sLoadedKexts->getLastObject());
    sLoadedKexts->setObject(this);

   /* Keep the kernel itself out of the kmod list.
    */
    if (lastLoadedKext == sKernelKext) {
        lastLoadedKext = NULL;
    }

    if (lastLoadedKext) {
        kmod_info->next = lastLoadedKext->kmod_info;
    }

   /* Make the global kmod list point at the just-loaded kext. Note that the
    * __kernel__ kext isn't in this list, as it wasn't before SnowLeopard,
    * although we do report it in kextstat these days by using the newer
    * OSArray of loaded kexts, which does contain it.
    *
    * (The OSKext object representing the kernel doesn't even have a kmod_info
    * struct, though I suppose we could stick a pointer to it from the
    * static struct in OSRuntime.cpp.)
    */
    kmod = kmod_info;

   /* Save the list of loaded kexts in case we panic.
    */
    clock_get_uptime(&last_loaded_timestamp);
    OSKext::saveLoadedKextPanicList();

loaded:

    if (declaresExecutable() && (startOpt == kOSKextExcludeNone)) {
        result = start();
        if (result != kOSReturnSuccess) {
            OSKextLog(this,
                kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                "Kext %s start failed (result 0x%x).",
                getIdentifierCString(), result);
            result = kOSKextReturnStartStopError;
        }
    }
    
   /* If not excluding matching, send the personalities to the kernel.
    * This never affects the result of the load operation.
    * This is a bit of a hack, because we shouldn't be handling 
    * personalities within the load function.
    */
    if (result == kOSReturnSuccess && startMatchingOpt == kOSKextExcludeNone) {
        result = sendPersonalitiesToCatalog(true, personalityNames);
    }
finish:

   /* More hack! If the kext doesn't declare an executable, even if we
    * "loaded" it, we have to remove any personalities naming it, or we'll
    * never see the registry go quiet. Errors here do not count for the
    * load operation itself.
    *
    * Note that in every other regard it's perfectly ok for a kext to
    * not declare an executable and serve only as a package for personalities
    * naming another kext, so we do have to allow such kexts to be "loaded"
    * so that those other personalities get added & matched.
    */
    if (!declaresExecutable()) {
        OSKextLog(this,
            kOSKextLogStepLevel | kOSKextLogLoadFlag,
            "Kext %s has no executable; removing any personalities naming it.",
            getIdentifierCString());
        removePersonalitiesFromCatalog();
    }

    if (result != kOSReturnSuccess) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s failed to load (0x%x).",
            getIdentifierCString(), (int)result);
    } else if (!alreadyLoaded) {
        OSKextLog(this,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag,
            "Kext %s loaded.",
            getIdentifierCString());
    }
    return result;
}

/*********************************************************************
* called only by load()
*********************************************************************/
OSReturn
OSKext::loadExecutable()
{
    OSReturn              result             = kOSReturnError;
    kern_return_t         kxldResult;
    u_char            **  kxlddeps           = NULL;  // must kfree
    uint32_t              num_kxlddeps       = 0;
    uint32_t              num_kmod_refs      = 0;
    u_char              * linkStateBytes     = NULL;  // do not free
    u_long                linkStateLength    = 0;
    u_char             ** linkStateBytesPtr  = NULL;  // do not free
    u_long              * linkStateLengthPtr = NULL;  // do not free
    struct mach_header ** kxldHeaderPtr      = NULL;  // do not free
    struct mach_header  * kxld_header        = NULL;  // xxx - need to free here?
    OSData              * theExecutable      = NULL;  // do not release
    OSString            * versString         = NULL;  // do not release
    const char          * versCString        = NULL;  // do not free
    const char          * string             = NULL;  // do not free
    unsigned int          i;

   /* We need the version string for a variety of bits below.
    */
    versString = OSDynamicCast(OSString,
        getPropertyForHostArch(kCFBundleVersionKey));
    if (!versString) {
        goto finish;
    }
    versCString = versString->getCStringNoCopy();

    if (isKernelComponent()) {
       if (STRING_HAS_PREFIX(versCString, KERNEL_LIB_PREFIX)) {
           if (strncmp(versCString, KERNEL6_VERSION, strlen(KERNEL6_VERSION))) {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Kernel component %s has incorrect version %s; "
                    "expected %s.",
                    getIdentifierCString(),
                    versCString, KERNEL6_VERSION);
               result = kOSKextReturnInternalError;
               goto finish;
           } else if (strcmp(versCString, osrelease)) {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Kernel component %s has incorrect version %s; "
                    "expected %s.",
                    getIdentifierCString(),
                    versCString, osrelease);
               result = kOSKextReturnInternalError;
               goto finish;
           }
       }
    }

    if (isPrelinked()) {
        goto register_kmod;
    }

    theExecutable = getExecutable();
    if (!theExecutable) {
        if (declaresExecutable()) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Can't load kext %s - executable is missing.",
                getIdentifierCString());
            result = kOSKextReturnValidation;
            goto finish;
        }
        goto register_kmod;
    }

    if (isKernelComponent()) {
        num_kxlddeps = 1; // the kernel itself
    } else {
        num_kxlddeps = getNumDependencies();
    }
    if (!num_kxlddeps) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogDependenciesFlag,
            "Can't load kext %s - it has no library dependencies.",
            getIdentifierCString());
        goto finish;
    }
    kxlddeps = (u_char **)kalloc(num_kxlddeps * sizeof(*kxlddeps));
    if (!kxlddeps) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogLinkFlag,
            "Can't allocate link context to load kext %s.",
            getIdentifierCString());
        goto finish;
    }
    
    if (isKernelComponent()) {
        OSData * kernelLinkState = OSKext::getKernelLinkState();
        kxlddeps[0] = (u_char *)kernelLinkState->getBytesNoCopy();
    } else for (i = 0; i < num_kxlddeps; i++) {
        OSKext * dependency = OSDynamicCast(OSKext, dependencies->getObject(i));
        if (!dependency->linkState) {
            // xxx - maybe we should panic here
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag | kOSKextLogLinkFlag,
                "Can't load kext %s - link state missing.",
                getIdentifierCString());
            goto finish;
        }
        kxlddeps[i] = (u_char *)dependency->linkState->getBytesNoCopy();
        assert(kxlddeps[i]);
    }

   /* We only need link state for a library kext.
    */
    if (compatibleVersion > -1 && (declaresExecutable() || isKernelComponent())) {
        linkStateBytesPtr = &linkStateBytes;
        linkStateLengthPtr = &linkStateLength;
    }

   /* We only need the linked executable for a real kext.
    */
    if (!isInterface()) {
        kxldHeaderPtr = &kxld_header;
    }

#if DEBUG
    OSKextLog(this,
        kOSKextLogExplicitLevel |
        kOSKextLogLoadFlag | kOSKextLogLinkFlag,
        "Kext %s - calling kxld_link_file:\n"
        "    kxld_context: %p\n"
        "    executable: %p    executable_length: %d\n"
        "    user_data: %p\n"
        "    kxld_dependencies: %p    num_dependencies: %d\n"
        "    kxld_header_ptr: %p    kmod_info_ptr: %p\n"
        "    link_state_ptr: %p    link_state_length_ptr: %p",
        getIdentifierCString(), kxldContext,
        theExecutable->getBytesNoCopy(), theExecutable->getLength(),
        this, kxlddeps, num_kxlddeps,
        kxldHeaderPtr, kernelKmodInfoPtr,
        linkStateBytesPtr, linkStateLengthPtr);
#endif

   /* After this call, the linkedExecutable instance variable
    * should exist.
    */
    kxldResult = kxld_link_file(sKxldContext,
        (u_char *)theExecutable->getBytesNoCopy(),
        theExecutable->getLength(),
        getIdentifierCString(), this, kxlddeps, num_kxlddeps,
        (u_char **)kxldHeaderPtr, (kxld_addr_t *)&kmod_info,
        linkStateBytesPtr, linkStateLengthPtr,
        /* symbolFile */ NULL, /* symbolFileSize */ NULL);

    if (kxldResult != KERN_SUCCESS) {
        // xxx - add kxldResult here?
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Can't load kext %s - link failed.",
            getIdentifierCString());
        result = kOSKextReturnLinkError;
        goto finish;
    }

   /* If we got a link state, wrap it in an OSData and keep it
    * around for later use linking other kexts that depend on this kext.
    */
    if (linkStateBytes && linkStateLength > 0) {
        linkState = OSData::withBytesNoCopy(linkStateBytes, linkStateLength);
        assert(linkState);
        linkState->setDeallocFunction(&osdata_kmem_free);
    }
    
   /* If this isn't an interface, We've written data & instructions into kernel 
    * memory, so flush the data cache and invalidate the instruction cache.
    */
    if (!isInterface()) {
        flush_dcache(kmod_info->address, kmod_info->size, false);
        invalidate_icache(kmod_info->address, kmod_info->size, false);
    }

register_kmod:

    if (isInterface()) {

       /* Whip up a fake kmod_info entry for the interface kext.
        */
        kmod_info = (kmod_info_t *)kalloc(sizeof(kmod_info_t));
        if (!kmod_info) {
            result = KERN_MEMORY_ERROR;
            goto finish;
        }

       /* A pseudokext has almost nothing in its kmod_info struct.
        */
        bzero(kmod_info, sizeof(kmod_info_t));

        kmod_info->info_version = KMOD_INFO_VERSION;

       /* An interface kext doesn't have a linkedExecutable, so save a
        * copy of the UUID out of the original executable via copyUUID()
        * while we still have the original executable.
        */
        interfaceUUID = copyUUID();
    }

    kmod_info->id = loadTag = sNextLoadTag++;
    kmod_info->reference_count = 0;  // KMOD_DECL... sets it to -1 (invalid).

   /* Stamp the bundle ID and version from the OSKext over anything
    * resident inside the kmod_info.
    */
    string = getIdentifierCString();
    strlcpy(kmod_info->name, string, sizeof(kmod_info->name));

    string = versCString;
    strlcpy(kmod_info->version, string, sizeof(kmod_info->version));

   /* Add the dependencies' kmod_info structs as kmod_references.
    */
    num_kmod_refs = getNumDependencies();
    if (num_kmod_refs) {
        kmod_info->reference_list = (kmod_reference_t *)kalloc(
            num_kmod_refs * sizeof(kmod_reference_t));
        if (!kmod_info->reference_list) {
            result = KERN_MEMORY_ERROR;
            goto finish;
        }
        bzero(kmod_info->reference_list,
            num_kmod_refs * sizeof(kmod_reference_t));
        for (uint32_t refIndex = 0; refIndex < num_kmod_refs; refIndex++) {
            kmod_reference_t * ref = &(kmod_info->reference_list[refIndex]);
            OSKext * refKext = OSDynamicCast(OSKext, dependencies->getObject(refIndex));
            ref->info = refKext->kmod_info;
            ref->info->reference_count++;

            if (refIndex + 1 < num_kmod_refs) {
                ref->next = kmod_info->reference_list + refIndex + 1;
            }
        }
    }

    if (!isInterface() && linkedExecutable) {
        OSKextLog(this,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag,
            "Kext %s executable loaded; %u pages at 0x%lx (load tag %u).", 
            kmod_info->name,
            (unsigned)kmod_info->size / PAGE_SIZE,
            (unsigned long)kmod_info->address,
            (unsigned)kmod_info->id);
    }

    result = setVMProtections();
    if (result != KERN_SUCCESS) {
        goto finish;
    }

    result = kOSReturnSuccess;

finish:
    if (kxlddeps) kfree(kxlddeps, (num_kxlddeps * sizeof(void *)));

   /* We no longer need the unrelocated executable (which the linker
    * has altered anyhow).
    */
    setExecutable(NULL);

    if (result != kOSReturnSuccess) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Failed to load executable for kext %s.",
            getIdentifierCString());

        if (kmod_info && kmod_info->reference_list) {
            kfree(kmod_info->reference_list,
                num_kmod_refs * sizeof(kmod_reference_t));
        }
        if (isInterface()) {
            kfree(kmod_info, sizeof(kmod_info_t));
        }
        kmod_info = NULL;
        if (linkedExecutable) {
            linkedExecutable->release();
            linkedExecutable = NULL;
        }
    }

    return result;
}

/*********************************************************************
* xxx - initWithPrelinkedInfoDict doesn't use this
*********************************************************************/
void
OSKext::setLinkedExecutable(OSData * anExecutable)
{
    if (linkedExecutable) {
        panic("Attempt to set linked executable on kext "
            "that already has one (%s).\n",
            getIdentifierCString());
    }
    linkedExecutable = anExecutable;
    linkedExecutable->retain();
    return;
}

/*********************************************************************
* called only by loadExecutable()
*********************************************************************/
OSReturn
OSKext::setVMProtections(void)
{
    vm_map_t                    kext_map        = NULL;
    kernel_segment_command_t  * seg             = NULL;
    vm_map_offset_t             start           = 0;
    vm_map_offset_t             end             = 0;
    OSReturn                    result          = kOSReturnError;

    if (!kmod_info->address && !kmod_info->size) {
        result = kOSReturnSuccess;
        goto finish;
    }

    /* Get the kext's vm map */
    kext_map = kext_get_vm_map(kmod_info);
    if (!kext_map) {
        result = KERN_MEMORY_ERROR;
        goto finish;
    }

    /* XXX: On arm, the vme covering the prelinked kernel (really, the whole
     * range from 0xc0000000 to a little over 0xe0000000) has maxprot set to 0
     * so the vm_map_protect calls below fail
     * I believe this happens in the call to vm_map_enter in kmem_init but I 
     * need to confirm.
     */
    /* Protect the headers as read-only; they do not need to be wired */
    result = vm_map_protect(kext_map, kmod_info->address, 
        kmod_info->address + kmod_info->hdr_size, VM_PROT_READ, TRUE);
    if (result != KERN_SUCCESS) {
        goto finish;
    }

    /* Set the VM protections and wire down each of the segments */
    seg = firstsegfromheader((kernel_mach_header_t *)kmod_info->address);
    while (seg) {
        start = round_page(seg->vmaddr);
        end = trunc_page(seg->vmaddr + seg->vmsize);

        result = vm_map_protect(kext_map, start, end, seg->maxprot, TRUE);
        if (result != KERN_SUCCESS) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s failed to set maximum VM protections "
                "for segment %s - 0x%x.", 
                getIdentifierCString(), seg->segname, (int)result);
            goto finish;
        }

        result = vm_map_protect(kext_map, start, end, seg->initprot, FALSE);
        if (result != KERN_SUCCESS) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s failed to set initial VM protections "
                "for segment %s - 0x%x.", 
                getIdentifierCString(), seg->segname, (int)result);
            goto finish;
        }

        result = vm_map_wire(kext_map, start, end, seg->initprot, FALSE);
        if (result != KERN_SUCCESS) {
            goto finish;
        }

        seg = nextsegfromheader((kernel_mach_header_t *) kmod_info->address, seg);
    }

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::validateKextMapping(bool startFlag)
{
    OSReturn                              result      = kOSReturnError;
    const char                          * whichOp = startFlag ? "start" : "stop";
    kern_return_t                         kern_result = 0;
    vm_map_t                              kext_map    = NULL;
    mach_vm_address_t                     address     = 0;
    mach_vm_size_t                        size        = 0;
    uint32_t                              depth       = 0;
    mach_msg_type_number_t                count;
    vm_region_submap_short_info_data_64_t info;

    count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    bzero(&info, sizeof(info));

   // xxx - do we need a distinct OSReturn value for these or is "bad data"
   // xxx - sufficient?

   /* Verify that the kmod_info and start/stop pointers are non-NULL.
    */
    if (!kmod_info) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s - NULL kmod_info pointer.",
            getIdentifierCString());
        result = kOSKextReturnBadData;
        goto finish;
    }

    if (startFlag) {
        address = (mach_vm_address_t)kmod_info->start;
    } else {
        address = (mach_vm_address_t)kmod_info->stop;
    }

    if (!address) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s - NULL module %s pointer.",
            getIdentifierCString(), whichOp);
        result = kOSKextReturnBadData;
        goto finish;
    }

    kext_map = kext_get_vm_map(kmod_info);
    depth = (kernel_map == kext_map) ? 1 : 2;

   /* Verify that the start/stop function lies within the kext's address range.
    */
    if (address < kmod_info->address + kmod_info->hdr_size ||
        kmod_info->address + kmod_info->size <= address)
    {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s module %s pointer is outside of kext range "
            "(%s %p - kext at %p-%p)..",
            getIdentifierCString(),
            whichOp,
            whichOp,
            (void *)address,
            (void *)kmod_info->address,
            (void *)(kmod_info->address + kmod_info->size));
        result = kOSKextReturnBadData;
        goto finish;
    }

   /* Only do these checks before calling the start function;
    * If anything goes wrong with the mapping while the kext is running,
    * we'll likely have panicked well before any attempt to stop the kext.
    */
    if (startFlag) {

       /* Verify that the start/stop function is executable.
        */
        kern_result = mach_vm_region_recurse(kernel_map, &address, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kern_result != KERN_SUCCESS) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s - bad %s pointer %p.",
                getIdentifierCString(),
                whichOp, (void *)address);
            result = kOSKextReturnBadData;
            goto finish;
        }

        if (!(info.protection & VM_PROT_EXECUTE)) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s - memory region containing module %s function "
                "is not executable.",
                getIdentifierCString(), whichOp);
            result = kOSKextReturnBadData;
            goto finish;
        }

       /* Verify that the kext is backed by physical memory.
        */
        for (address = kmod_info->address;
             address < round_page(kmod_info->address + kmod_info->size);
             address += PAGE_SIZE)
        {
            if (!pmap_find_phys(kernel_pmap, (vm_offset_t)address)) {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Kext %s - page %p is not backed by physical memory.",
                    getIdentifierCString(), 
                    (void *)address);
                result = kOSKextReturnBadData;
                goto finish;
            }
        }
    }

    result = kOSReturnSuccess;
finish:
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::start(bool startDependenciesFlag)
{
    OSReturn                            result = kOSReturnError;
    kern_return_t                       (* startfunc)(kmod_info_t *, void *);
    unsigned int                        i, count;
    void                              * kmodStartData      = NULL;  // special handling needed
#if CONFIG_MACF_KEXT
    mach_msg_type_number_t              kmodStartDataCount = 0;
#endif /* CONFIG_MACF_KEXT */

    if (isStarted() || isInterface() || isKernelComponent()) {
        result = kOSReturnSuccess;
        goto finish;
    }

    if (!isLoaded()) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Attempt to start nonloaded kext %s.",
            getIdentifierCString()); 
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    if (!sLoadEnabled) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext loading is disabled (attempt to start kext %s).",
            getIdentifierCString());
        result = kOSKextReturnDisabled;
        goto finish;
    }

    result = validateKextMapping(/* start? */ true);
    if (result != kOSReturnSuccess) {
        goto finish;
    }

    startfunc = kmod_info->start;

    count = getNumDependencies();
    for (i = 0; i < count; i++) {
        OSKext * dependency = OSDynamicCast(OSKext, dependencies->getObject(i));
        if (dependency == NULL) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s start - internal error, dependency disappeared.",
                getIdentifierCString());
            goto finish;
        }
        if (!dependency->isStarted()) {
            if (startDependenciesFlag) {
                OSReturn dependencyResult =
                    dependency->start(startDependenciesFlag);
                if (dependencyResult != KERN_SUCCESS) {
                    OSKextLog(this,
                        kOSKextLogErrorLevel |
                        kOSKextLogLoadFlag,
                        "Kext %s start - dependency %s failed to start (error 0x%x).",
                        getIdentifierCString(),
                        dependency->getIdentifierCString(),
                        dependencyResult);
                    goto finish;
                }
            } else {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Not starting %s - dependency %s not started yet.",
                    getIdentifierCString(),
                    dependency->getIdentifierCString());
                result = kOSKextReturnStartStopError;  // xxx - make new return?
                goto finish;
            }
        }
    }

#if CONFIG_MACF_KEXT
   /* See if the kext has any MAC framework module data in its plist.
    * This is passed in as arg #2 of the kext's start routine,
    * which is otherwise reserved for any other kext.
    */
    kmodStartData = MACFCopyModuleDataForKext(this, &kmodStartDataCount);
#endif /* CONFIG_MACF_KEXT */

    OSKextLog(this,
        kOSKextLogDetailLevel |
        kOSKextLogLoadFlag,
        "Kext %s calling module start function.",
        getIdentifierCString()); 

    flags.starting = 1;

#if !__i386__ && !__ppc__
    result = OSRuntimeInitializeCPP(kmod_info, NULL);
    if (result == KERN_SUCCESS) {
#endif

        result = startfunc(kmod_info, kmodStartData);

#if !__i386__ && !__ppc__
        if (result != KERN_SUCCESS) {
            (void) OSRuntimeFinalizeCPP(kmod_info, NULL);
        }
    }
#endif

    flags.starting = 0;

   /* On success overlap the setting of started/starting. On failure just
    * clear starting.
    */
    if (result == KERN_SUCCESS) {
        flags.started = 1;

        // xxx - log start error from kernel?
        OSKextLog(this,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag,
            "Kext %s is now started.",
            getIdentifierCString()); 
    } else {
        invokeOrCancelRequestCallbacks(
            /* result not actually used */ kOSKextReturnStartStopError,
            /* invokeFlag */ false);
        OSKextLog(this,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag,
            "Kext %s did not start (return code 0x%x).",
            getIdentifierCString(), result); 
    }

finish:
#if CONFIG_MACF_KEXT
   /* Free the module data for a MAC framework kext. When we start using
    * param #2 we'll have to distinguish and free/release appropriately.
    *
    * xxx - I'm pretty sure the old codepath freed the data and that it's
    * xxx - up to the kext to copy it.
    */
    if (kmodStartData) {
        kmem_free(kernel_map, (vm_offset_t)kmodStartData, kmodStartDataCount);
    }
#endif /* CONFIG_MACF_KEXT */

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool OSKext::canUnloadKextWithIdentifier(
    OSString * kextIdentifier,
    bool       checkClassesFlag)
{
    bool     result = false;
    OSKext * aKext  = NULL;  // do not release

    IORecursiveLockLock(sKextLock);

    aKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier));

    if (!aKext) {
        goto finish;  // can't unload what's not loaded
    }

    if (aKext->isLoaded()) {
        if (aKext->getRetainCount() > kOSKextMinLoadedRetainCount) {
            goto finish;
        }
        if (checkClassesFlag && aKext->hasOSMetaClassInstances()) {
            goto finish;
        }
    }

    result = true;

finish:
    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::stop(void)
{
    OSReturn result = kOSReturnError;
    kern_return_t (*stopfunc)(kmod_info_t *, void *);
    
    if (!isStarted() || isInterface()) {
        result = kOSReturnSuccess;
        goto finish;
    }

    if (!isLoaded()) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Attempt to stop nonloaded kext %s.",
            getIdentifierCString());
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

   /* Refuse to stop if we have clients or instances. It is up to
    * the caller to make sure those aren't true.
    */
    if (getRetainCount() > kOSKextMinLoadedRetainCount) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s - C++ instances; can't stop.",
            getIdentifierCString());
        result = kOSKextReturnInUse;
        goto finish;
    }

    if (getRetainCount() > kOSKextMinLoadedRetainCount) {

        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s - has references (linkage or tracking object); "
            "can't stop.",
            getIdentifierCString());
        result = kOSKextReturnInUse;
        goto finish;
    }

   /* Note: If validateKextMapping fails on the stop & unload path,
    * we are in serious trouble and a kernel panic is likely whether
    * we stop & unload the kext or not.
    */
    result = validateKextMapping(/* start? */ false);
    if (result != kOSReturnSuccess) {
        goto finish;
    }

   /* Save the list of loaded kexts in case we panic.
    */
    OSKext::saveUnloadedKextPanicList(this);

    stopfunc = kmod_info->stop;
    if (stopfunc) {
        OSKextLog(this,
            kOSKextLogDetailLevel |
            kOSKextLogLoadFlag,
            "Kext %s calling module stop function.",
            getIdentifierCString()); 

        flags.stopping = 1;

        result = stopfunc(kmod_info, /* userData */ NULL);
#if !__i386__ && !__ppc__
        if (result == KERN_SUCCESS) {
            result = OSRuntimeFinalizeCPP(kmod_info, NULL);
        }
#endif

        flags.stopping = 0;

        if (result == KERN_SUCCESS) {
            flags.started = 0;

            OSKextLog(this,
                kOSKextLogDetailLevel |
                kOSKextLogLoadFlag,
                "Kext %s is now stopped and ready to unload.",
                getIdentifierCString()); 
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s did not stop (return code 0x%x).",
                getIdentifierCString(), result); 
            result = kOSKextReturnStartStopError;
        }
    }

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::unload(void)
{
    OSReturn     result = kOSReturnError;
    unsigned int index;
    uint32_t     num_kmod_refs = 0;

    if (!sUnloadEnabled) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext unloading is disabled (%s).",
            this->getIdentifierCString());

        result = kOSKextReturnDisabled;
        goto finish;
    }

   /* Refuse to unload if we have clients or instances. It is up to
    * the caller to make sure those aren't true.
    */
    if (getRetainCount() > kOSKextMinLoadedRetainCount) {
        // xxx - Don't log under errors? this is more of an info thing
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogKextBookkeepingFlag,
            "Can't unload kext %s; outstanding references (linkage or tracking object).",
            getIdentifierCString());
        result = kOSKextReturnInUse;
        goto finish;
    }


    if (hasOSMetaClassInstances()) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
            "Can't unload kext %s; classes have instances:",
            getIdentifierCString());
        reportOSMetaClassInstances(kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag);
        result = kOSKextReturnInUse;
        goto finish;
    }

    if (!isLoaded()) {
        result = kOSReturnSuccess;
        goto finish;
    }

    if (isKernelComponent()) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }
    
   /* Note that the kext is unloading before running any code that
    * might be in the kext (request callbacks, module stop function).
    * We will deny certain requests made against a kext in the process
    * of unloading.
    */
    flags.unloading = 1;
    
    if (isStarted()) {
        result = stop();
        if (result != KERN_SUCCESS) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s can't unload - module stop returned 0x%x.",
                getIdentifierCString(), (unsigned)result);
            result = kOSKextReturnStartStopError;
            goto finish;
        }
    }

    OSKextLog(this,
        kOSKextLogProgressLevel |
        kOSKextLogLoadFlag,
        "Kext %s unloading.",
        getIdentifierCString());

   /* Even if we don't call the stop function, we want to be sure we
    * have no OSMetaClass references before unloading the kext executable
    * from memory. OSMetaClasses may have pointers into the kext executable
    * and that would cause a panic on OSKext::free() when metaClasses is freed.
    */
    if (metaClasses) {
        metaClasses->flushCollection();
    }

   /* Remove the kext from the list of loaded kexts, patch the gap
    * in the kmod_info_t linked list, and reset "kmod" to point to the
    * last loaded kext that isn't the fake kernel kext (sKernelKext).
    */
    index = sLoadedKexts->getNextIndexOfObject(this, 0);
    if (index != (unsigned int)-1) {

        sLoadedKexts->removeObject(index);

        OSKext * nextKext = OSDynamicCast(OSKext,
            sLoadedKexts->getObject(index));

        if (nextKext) {
            if (index > 0) {
                OSKext * gapKext = OSDynamicCast(OSKext,
                    sLoadedKexts->getObject(index - 1));
                
                nextKext->kmod_info->next = gapKext->kmod_info;

            } else /* index == 0 */ {
                nextKext->kmod_info->next = NULL;
            }
        }

        OSKext * lastKext = OSDynamicCast(OSKext, sLoadedKexts->getLastObject());
        if (lastKext && lastKext != sKernelKext) {
            kmod = lastKext->kmod_info;
        } else {
            kmod = NULL;  // clear the global kmod variable
        }
    }

   /* Clear out the kmod references that we're keeping for compatibility
    * with current panic backtrace code & kgmacros.
    * xxx - will want to update those bits sometime and remove this.
    */
    num_kmod_refs = getNumDependencies();
    if (num_kmod_refs && kmod_info && kmod_info->reference_list) {
        for (uint32_t refIndex = 0; refIndex < num_kmod_refs; refIndex++) {
            kmod_reference_t * ref = &(kmod_info->reference_list[refIndex]);
            ref->info->reference_count--;
        }
        kfree(kmod_info->reference_list,
            num_kmod_refs * sizeof(kmod_reference_t));
    }

   /* If we have a linked executable, release & clear it, and then
    * unwire & deallocate the buffer the OSData wrapped.
    */
    if (linkedExecutable) {
        vm_map_t kext_map;

       /* linkedExecutable is just a wrapper for the executable and doesn't
        * free it.
        */
        linkedExecutable->release();
        linkedExecutable = NULL;

        OSKextLog(this,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag,
            "Kext %s unwiring and unmapping linked executable.",
            getIdentifierCString());

        kext_map = kext_get_vm_map(kmod_info);
        if (kext_map) {
            // xxx - do we have to do this before freeing? Why can't we just free it?
            // xxx - we should be able to set a dealloc func on the linkedExecutable
            result = vm_map_unwire(kext_map,
                kmod_info->address + kmod_info->hdr_size, 
                kmod_info->address + kmod_info->size, FALSE);
            if (result == KERN_SUCCESS) {
                kext_free(kmod_info->address, kmod_info->size);
            }
        }
    }

   /* An interface kext has a fake kmod_info that was allocated,
    * so we have to free it.
    */
    if (isInterface()) {
        kfree(kmod_info, sizeof(kmod_info_t));
    }

    kmod_info = NULL;

    flags.loaded = false;
    flushDependencies();

    OSKextLog(this,
        kOSKextLogProgressLevel | kOSKextLogLoadFlag,
        "Kext %s unloaded.", getIdentifierCString());

finish:
    OSKext::saveLoadedKextPanicList();

    flags.unloading = 0;
    return result;
}

/*********************************************************************
*********************************************************************/
static void
_OSKextConsiderDestroyingLinkContext(
    __unused thread_call_param_t p0,
    __unused thread_call_param_t p1)
{
   /* Once both recursive locks are taken in correct order, we shouldn't
    * have to worry about further recursive lock takes.
    */
    IORecursiveLockLock(sKextLock);
    IORecursiveLockLock(sKextInnerLock);

   /* The first time we destroy the kxldContext is in the first 
    * OSKext::considerUnloads() call, which sets sConsiderUnloadsCalled
    * before calling this function. Thereafter any call to this function
    * will actually destroy the context.
    */
    if (sConsiderUnloadsCalled && sKxldContext) {
        kxld_destroy_context(sKxldContext);
        sKxldContext = NULL;
    }

   /* Free the thread_call that was allocated to execute this function.
    */
    if (sDestroyLinkContextThread) {
        if (!thread_call_free(sDestroyLinkContextThread)) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag,
                "thread_call_free() failed for kext link context.");
        }
        sDestroyLinkContextThread = 0;
    }

    IORecursiveLockUnlock(sKextInnerLock);
    IORecursiveLockUnlock(sKextLock);

    return;
}

/*********************************************************************
* Destroying the kxldContext requires checking variables under both
* sKextInnerLock and sKextLock, so we do it on a separate thread
* to avoid deadlocks with IOService, with which OSKext has a reciprocal
* call relationship.
*
* Do not call any function that takes sKextLock here! This function
* can be invoked with sKextInnerLock, and the two must always
* be taken in the order: sKextLock -> sKextInnerLock.
*********************************************************************/
/* static */
void
OSKext::considerDestroyingLinkContext(void)
{
    IORecursiveLockLock(sKextInnerLock);

   /* If we have already queued a thread to destroy the link context,
    * don't bother resetting; that thread will take care of it.
    */
    if (sDestroyLinkContextThread) {
        goto finish;
    }

   /* The function to be invoked in the thread will deallocate
    * this thread_call, so don't share it around.
    */
    sDestroyLinkContextThread = thread_call_allocate(
        &_OSKextConsiderDestroyingLinkContext, 0);
    if (!sDestroyLinkContextThread) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogGeneralFlag | kOSKextLogLinkFlag,
            "Can't create thread to destroy kext link context.");
        goto finish;
    }

    thread_call_enter(sDestroyLinkContextThread);

finish:
    IORecursiveLockUnlock(sKextInnerLock);
    return;
}

/*********************************************************************
*********************************************************************/
OSData *
OSKext::getKernelLinkState()
{
    kern_return_t   kxldResult;
    u_char        * kernel          = NULL;
    size_t          kernelLength;
    u_char        * linkStateBytes  = NULL;
    u_long          linkStateLength;
    OSData        * linkState       = NULL;

    if (sKernelKext && sKernelKext->linkState) {
        goto finish;
    }

    kernel = (u_char *)&_mh_execute_header;
    kernelLength = getlastaddr() - (vm_offset_t)kernel;

    kxldResult = kxld_link_file(sKxldContext,
        kernel,
        kernelLength,
        kOSKextKernelIdentifier,
        /* callbackData */ NULL,
        /* dependencies */ NULL,
        /* numDependencies */ 0,
        /* linkedObjectOut */ NULL,
        /* kmod_info_kern out */ NULL,
        &linkStateBytes,
        &linkStateLength,
        /* symbolFile */ NULL,
        /* symbolFileSize */ NULL);
    if (kxldResult) {
        panic("Can't generate kernel link state; no kexts can be loaded.");
        goto finish;
    }

    linkState = OSData::withBytesNoCopy(linkStateBytes, linkStateLength);
    linkState->setDeallocFunction(&osdata_kmem_free);
    sKernelKext->linkState = linkState;

finish:
    return sKernelKext->linkState;
}

#if PRAGMA_MARK
#pragma mark Autounload
#endif
/*********************************************************************
* This is a static method because the kext will be deallocated if it
* does unload!
*********************************************************************/
OSReturn
OSKext::autounloadKext(OSKext * aKext)
{
    OSReturn result = kOSKextReturnInUse;

   /* Check for external references to this kext (usu. dependents),
    * instances of defined classes (or classes derived from them),
    * outstanding requests.
    */
    if ((aKext->getRetainCount() > kOSKextMinLoadedRetainCount) ||
        !aKext->flags.autounloadEnabled ||
        aKext->isKernelComponent()) {

        goto finish;
    }

   /* Skip a delay-autounload kext, once.
    */
    if (aKext->flags.delayAutounload) {
        OSKextLog(aKext,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
            "Kext %s has delayed autounload set; skipping and clearing flag.",
            aKext->getIdentifierCString());
        aKext->flags.delayAutounload = 0;
        goto finish;
    }

    if (aKext->hasOSMetaClassInstances() ||
        aKext->countRequestCallbacks()) {
        goto finish;
    }

    result = OSKext::removeKext(aKext);

finish:

    return result;
}

/*********************************************************************
*********************************************************************/
void
_OSKextConsiderUnloads(
    __unused thread_call_param_t p0,
    __unused thread_call_param_t p1)
{
    bool         didUnload = false;
    unsigned int count, i;

   /* Once both recursive locks are taken in correct order, we shouldn't
    * have to worry about further recursive lock takes.
    */
    IORecursiveLockLock(sKextLock);
    IORecursiveLockLock(sKextInnerLock);

    OSKext::flushNonloadedKexts(/* flushPrelinkedKexts */ true);

   /* If the system is powering down, don't try to unload anything.
    */
    if (sSystemSleep) {
        goto finish;
    }

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogLoadFlag,
        "Checking for unused kexts to autounload.");

   /*****
    * Remove any request callbacks marked as stale,
    * and mark as stale any currently in flight.
    */
    count = sRequestCallbackRecords->getCount();
    if (count) {
        i = count - 1;
        do {
            OSDictionary * callbackRecord = OSDynamicCast(OSDictionary,
                sRequestCallbackRecords->getObject(i));
            OSBoolean * stale = OSDynamicCast(OSBoolean,
                callbackRecord->getObject(kKextRequestStaleKey));
            
            if (stale && stale->isTrue()) {
                OSKext::invokeRequestCallback(callbackRecord,
                    kOSKextReturnTimeout);
            } else {
                callbackRecord->setObject(kKextRequestStaleKey,
                    kOSBooleanTrue);
            }
        } while (i--);
    }

   /*****
    * Make multiple passes through the array of loaded kexts until
    * we don't unload any. This handles unwinding of dependency
    * chains. We have to go *backwards* through the array because
    * kexts are removed from it when unloaded, and we cannot make
    * a copy or we'll mess up the retain counts we rely on to
    * check whether a kext will unload. If only we could have
    * nonretaining collections like CF has....
    */
    do {
        didUnload = false;
        
        count = sLoadedKexts->getCount();
        if (count) {
            i = count - 1;
            do {
                OSKext * thisKext = OSDynamicCast(OSKext,
                    sLoadedKexts->getObject(i));
                didUnload = (kOSReturnSuccess == OSKext::autounloadKext(thisKext));
            } while (i--);
        }
    } while (didUnload);

finish:
    sConsiderUnloadsPending = false;
    sConsiderUnloadsExecuted = true;

    (void) OSKext::considerRebuildOfPrelinkedKernel();

    IORecursiveLockUnlock(sKextInnerLock);
    IORecursiveLockUnlock(sKextLock);

    return;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
void OSKext::considerUnloads(Boolean rescheduleOnlyFlag)
{
    AbsoluteTime when;

    IORecursiveLockLock(sKextInnerLock);

    if (!sUnloadCallout) {
        sUnloadCallout = thread_call_allocate(&_OSKextConsiderUnloads, 0);
    }

    if (rescheduleOnlyFlag && !sConsiderUnloadsPending) {
        goto finish;
    }

    thread_call_cancel(sUnloadCallout);
    if (OSKext::getAutounloadEnabled() && !sSystemSleep) {
        clock_interval_to_deadline(sConsiderUnloadDelay,
            1000 * 1000 * 1000, &when);

        OSKextLog(/* kext */ NULL,
            kOSKextLogProgressLevel |
            kOSKextLogLoadFlag,
            "%scheduling %sscan for unused kexts in %lu seconds.",
            sConsiderUnloadsPending ? "Res" : "S",
            sConsiderUnloadsCalled ? "" : "initial ",
            (unsigned long)sConsiderUnloadDelay);

        sConsiderUnloadsPending = true;
        thread_call_enter_delayed(sUnloadCallout, when);
    }

finish:
   /* The kxld context should be reused throughout boot.  We mark the end of
    * period as the first time considerUnloads() is called, and we destroy
    * the first kxld context in that function.  Afterwards, it will be
    * destroyed in flushNonloadedKexts.
    */
    if (!sConsiderUnloadsCalled) {
        sConsiderUnloadsCalled = true;
        OSKext::considerDestroyingLinkContext();
    }

    IORecursiveLockUnlock(sKextInnerLock);
    return;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
extern "C" {

IOReturn OSKextSystemSleepOrWake(UInt32 messageType)
{
    IORecursiveLockLock(sKextInnerLock);

   /* If the system is going to sleep, cancel the reaper thread timer,
    * and note that we're in a sleep state in case it just fired but hasn't
    * taken the lock yet. If we are coming back from sleep, just
    * clear the sleep flag; IOService's normal operation will cause
    * unloads to be considered soon enough.
    */
    if (messageType == kIOMessageSystemWillSleep) {
        if (sUnloadCallout) {
            thread_call_cancel(sUnloadCallout);
        }
        sSystemSleep = true;
    } else if (messageType == kIOMessageSystemHasPoweredOn) {
        sSystemSleep = false;
    }
    IORecursiveLockUnlock(sKextInnerLock);

    return kIOReturnSuccess;
}

};


#if PRAGMA_MARK
#pragma mark Prelinked Kernel
#endif
/*********************************************************************
* Do not access sConsiderUnloads... variables other than
* sConsiderUnloadsExecuted in this function. They are guarded by a
* different lock.
*********************************************************************/
/* static */
void
OSKext::considerRebuildOfPrelinkedKernel(void)
{
    OSReturn       checkResult      = kOSReturnError;
    static bool    requestedPrelink = false;
    OSDictionary * prelinkRequest   = NULL;  // must release

    IORecursiveLockLock(sKextLock);

    if (!sDeferredLoadSucceeded || !sConsiderUnloadsExecuted || 
        sSafeBoot || requestedPrelink) 
    {
        goto finish;
    }

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogArchiveFlag,
        "Requesting build of prelinked kernel.");

    checkResult = _OSKextCreateRequest(kKextRequestPredicateRequestPrelink,
        &prelinkRequest);
    if (checkResult != kOSReturnSuccess) {
        goto finish;
    }

    if (!sKernelRequests->setObject(prelinkRequest)) {
        goto finish;
    }

    OSKextPingKextd();
    requestedPrelink = true;

finish:
    IORecursiveLockUnlock(sKextLock);
    OSSafeRelease(prelinkRequest);
    return;
}

#if PRAGMA_MARK
#pragma mark Dependencies
#endif
/*********************************************************************
*********************************************************************/
bool
OSKext::resolveDependencies(
    OSArray * loopStack)
{
    bool                   result                   = false;
    OSArray              * localLoopStack           = NULL;   // must release
    bool                   addedToLoopStack         = false;
    OSDictionary         * libraries                = NULL;   // do not release
    OSCollectionIterator * libraryIterator          = NULL;   // must release
    OSString             * libraryID                = NULL;   // do not release
    OSString             * infoString               = NULL;   // do not release
    OSString             * readableString           = NULL;   // do not release
    OSKext               * libraryKext              = NULL;   // do not release
    bool                   hasRawKernelDependency   = false;
    bool                   hasKernelDependency      = false;
    bool                   hasKPIDependency         = false;
    bool                   hasPrivateKPIDependency  = false;
    unsigned int           count;

   /* A kernel component will automatically have this flag set,
    * and a loaded kext should also have it set (as should all its
    * loaded dependencies).
    */
    if (flags.hasAllDependencies) {
        result = true;
        goto finish;
    }

   /* Check for loops in the dependency graph.
    */
    if (loopStack) {
        if (loopStack->getNextIndexOfObject(this, 0) != (unsigned int)-1) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s has a dependency loop; can't resolve dependencies.",
                getIdentifierCString());
            goto finish;
        }
    } else {
        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogDependenciesFlag,
            "Kext %s resolving dependencies.",
            getIdentifierCString());

        loopStack = OSArray::withCapacity(6);  // any small capacity will do
        if (!loopStack) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s can't create bookkeeping stack to resolve dependencies.",
                getIdentifierCString());
            goto finish;
        }
        localLoopStack = loopStack;
    }
    if (!loopStack->setObject(this)) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogDependenciesFlag,
            "Kext %s - internal error resolving dependencies.",
            getIdentifierCString());
        goto finish;
    }
    addedToLoopStack = true;

   /* Purge any existing kexts in the dependency list and start over.
    */
    flushDependencies();
    if (dependencies) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogDependenciesFlag,
            "Kext %s - internal error resolving dependencies.",
            getIdentifierCString());
    }

    libraries = OSDynamicCast(OSDictionary,
        getPropertyForHostArch(kOSBundleLibrariesKey));
    if (libraries == NULL || libraries->getCount() == 0) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag | kOSKextLogDependenciesFlag,
            "Kext %s - can't resolve dependencies; %s missing/invalid type.",
            getIdentifierCString(), kOSBundleLibrariesKey);
        goto finish;
    }

   /* Make a new array to hold the dependencies (flush freed the old one).
    */
    dependencies = OSArray::withCapacity(libraries->getCount());
    if (!dependencies) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogDependenciesFlag,
            "Kext %s - can't allocate dependencies array.",
            getIdentifierCString());
        goto finish;
    }

    // xxx - compat: We used to add an implicit dependency on kernel 6.0
    // xxx - compat: if none were declared.

    libraryIterator = OSCollectionIterator::withCollection(libraries);
    if (!libraryIterator) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogDependenciesFlag,
            "Kext %s - can't allocate dependencies iterator.",
            getIdentifierCString());
        goto finish;
    }
    
    while ((libraryID = OSDynamicCast(OSString,
           libraryIterator->getNextObject()))) {
           
       const char * library_id = libraryID->getCStringNoCopy();

        OSString * libraryVersion = OSDynamicCast(OSString,
            libraries->getObject(libraryID));
        if (libraryVersion == NULL) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogValidationFlag | kOSKextLogDependenciesFlag,
                "Kext %s - illegal type in OSBundleLibraries.",
                getIdentifierCString());
            goto finish;
        }
        
        OSKextVersion libraryVers =
            OSKextParseVersionString(libraryVersion->getCStringNoCopy());
        if (libraryVers == -1) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogValidationFlag | kOSKextLogDependenciesFlag,
                "Kext %s - invalid library version %s.",
                getIdentifierCString(),
                libraryVersion->getCStringNoCopy());
            goto finish;
        }

        libraryKext = OSDynamicCast(OSKext, sKextsByID->getObject(libraryID));
        if (libraryKext == NULL) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s - library kext %s not found.",
                getIdentifierCString(), library_id);
            goto finish;
        }
        
        if (!libraryKext->isCompatibleWithVersion(libraryVers)) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s - library kext %s not compatible "
                "with requested version %s.",
                getIdentifierCString(), library_id,
                libraryVersion->getCStringNoCopy());
            goto finish;
        }
        
        if (!libraryKext->resolveDependencies(loopStack)) {
            goto finish;
        }

       /* Add the library directly only if it has an executable to link.
        * Otherwise it's just used to collect other dependencies, so put
        * *its* dependencies on the list for this kext.
        */
        // xxx - We are losing info here; would like to make fake entries or
        // xxx - keep these in the dependency graph for loaded kexts.
        // xxx - I really want to make kernel components not a special case!
        if (libraryKext->declaresExecutable() ||
            libraryKext->isInterface()) {

            if (dependencies->getNextIndexOfObject(libraryKext, 0) == (unsigned)-1) {
                dependencies->setObject(libraryKext);

                OSKextLog(this,
                    kOSKextLogDetailLevel |
                    kOSKextLogDependenciesFlag,
                    "Kext %s added dependency %s.",
                    getIdentifierCString(),
                    libraryKext->getIdentifierCString());
            }
        } else {
            int       numLibDependencies  = libraryKext->getNumDependencies();
            OSArray * libraryDependencies = libraryKext->getDependencies();
            int       index;

            if (numLibDependencies) {
                // xxx - this msg level should be 1 lower than the per-kext one
                OSKextLog(this,
                    kOSKextLogDetailLevel |
                    kOSKextLogDependenciesFlag,
                    "Kext %s pulling %d dependencies from codeless library %s.",
                    getIdentifierCString(),
                    numLibDependencies,
                    libraryKext->getIdentifierCString());
            }
            for (index = 0; index < numLibDependencies; index++) {
                OSKext * thisLibDependency = OSDynamicCast(OSKext,
                    libraryDependencies->getObject(index));
                if (dependencies->getNextIndexOfObject(thisLibDependency, 0) == (unsigned)-1) {
                    dependencies->setObject(thisLibDependency);
                    OSKextLog(this,
                        kOSKextLogDetailLevel |
                        kOSKextLogDependenciesFlag,
                        "Kext %s added dependency %s from codeless library %s.",
                        getIdentifierCString(),
                        thisLibDependency->getIdentifierCString(),
                        libraryKext->getIdentifierCString());
                }
            }
        }

        if ((strlen(library_id) == strlen(KERNEL_LIB)) &&
            0 == strncmp(library_id, KERNEL_LIB, sizeof(KERNEL_LIB)-1)) {

            hasRawKernelDependency = true;
        } else if (STRING_HAS_PREFIX(library_id, KERNEL_LIB_PREFIX)) {
            hasKernelDependency = true;
        } else if (STRING_HAS_PREFIX(library_id, KPI_LIB_PREFIX)) {
            hasKPIDependency = true;
            if (!strncmp(library_id, PRIVATE_KPI, sizeof(PRIVATE_KPI)-1)) {
                hasPrivateKPIDependency = true;
            }
        }
    }
    
#if __LP64__
    if (hasRawKernelDependency || hasKernelDependency) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag | kOSKextLogDependenciesFlag,
            "Error - kext %s declares %s dependencies. "
            "Only %s* dependencies are supported for 64-bit kexts.",
            getIdentifierCString(), KERNEL_LIB, KPI_LIB_PREFIX);
        goto finish;
    }
    if (!hasKPIDependency) {
        OSKextLog(this,
            kOSKextLogWarningLevel |
            kOSKextLogDependenciesFlag,
            "Warning - kext %s declares no %s* dependencies. "
            "If it uses any KPIs, the link may fail with undefined symbols.",
            getIdentifierCString(), KPI_LIB_PREFIX);
    }
#else /* __LP64__ */
    // xxx - will change to flatly disallow "kernel" dependencies at some point
    // xxx - is it invalid to do both "com.apple.kernel" and any
    // xxx - "com.apple.kernel.*"?

    if (hasRawKernelDependency && hasKernelDependency) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag | kOSKextLogDependenciesFlag,
            "Error - kext %s declares dependencies on both "
            "%s and %s.",
            getIdentifierCString(), KERNEL_LIB, KERNEL6_LIB);
        goto finish;
    }
    
    if ((hasRawKernelDependency || hasKernelDependency) && hasKPIDependency) {
        OSKextLog(this,
            kOSKextLogWarningLevel |
            kOSKextLogDependenciesFlag,
            "Warning - kext %s has immediate dependencies on both "
            "%s* and %s* components; use only one style.",
            getIdentifierCString(), KERNEL_LIB, KPI_LIB_PREFIX);
    }

    if (!hasRawKernelDependency && !hasKernelDependency && !hasKPIDependency) {
        // xxx - do we want to use validation flag for these too?
        OSKextLog(this,
            kOSKextLogWarningLevel |
            kOSKextLogDependenciesFlag,
            "Warning - %s declares no kernel dependencies; using %s.",
            getIdentifierCString(), KERNEL6_LIB);
        OSKext * kernelKext = OSDynamicCast(OSKext,
            sKextsByID->getObject(KERNEL6_LIB));
        if (kernelKext) {
            dependencies->setObject(kernelKext);
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Error - Library %s not found for %s.",
                KERNEL6_LIB, getIdentifierCString());
        }
    }

   /* If the kext doesn't have a raw kernel or KPI dependency, then add all of
    * its indirect dependencies to simulate old-style linking.  XXX - Should
    * check for duplicates.
    */
    if (!hasRawKernelDependency && !hasKPIDependency) {
        unsigned int i;

        count = getNumDependencies();
        
       /* We add to the dependencies array in this loop, but do not iterate
        * past its original count.
        */
        for (i = 0; i < count; i++) {
            OSKext * dependencyKext = OSDynamicCast(OSKext,
                dependencies->getObject(i));
            dependencyKext->addBleedthroughDependencies(dependencies);
        }
    }
#endif /* __LP64__ */

    if (hasPrivateKPIDependency) {
        bool hasApplePrefix = false;
        bool infoCopyrightIsValid = false;
        bool readableCopyrightIsValid = false;
        
        hasApplePrefix = STRING_HAS_PREFIX(getIdentifierCString(), 
            APPLE_KEXT_PREFIX);

        infoString = OSDynamicCast(OSString,  
            getPropertyForHostArch("CFBundleGetInfoString"));
        if (infoString) {
            infoCopyrightIsValid = 
                kxld_validate_copyright_string(infoString->getCStringNoCopy());
        }

        readableString = OSDynamicCast(OSString,
            getPropertyForHostArch("NSHumanReadableCopyright"));
        if (readableString) {
            readableCopyrightIsValid = 
                kxld_validate_copyright_string(readableString->getCStringNoCopy());
        }

        if (!hasApplePrefix || (!infoCopyrightIsValid && !readableCopyrightIsValid)) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Error - kext %s declares a dependency on %s. "
                  "Only Apple kexts may declare a dependency on %s.",
                  getIdentifierCString(), PRIVATE_KPI, PRIVATE_KPI);
            goto finish;
        }
    }

    result = true;
    flags.hasAllDependencies = 1;

finish:

    if (addedToLoopStack) {
        count = loopStack->getCount();
        if (count > 0 && (this == loopStack->getObject(count - 1))) {
            loopStack->removeObject(count - 1);            
        } else {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s - internal error resolving dependencies.",
                getIdentifierCString());
        }
    }
    
    if (result && localLoopStack) {
        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogDependenciesFlag,
            "Kext %s successfully resolved dependencies.",
            getIdentifierCString());
    }

    OSSafeRelease(localLoopStack);
    OSSafeRelease(libraryIterator);

    return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::addBleedthroughDependencies(OSArray * anArray)
{
    bool result = false;
    unsigned int dependencyIndex, dependencyCount;
    
    dependencyCount = getNumDependencies();

    for (dependencyIndex = 0;
         dependencyIndex < dependencyCount;
         dependencyIndex++) {

        OSKext * dependency = OSDynamicCast(OSKext,
            dependencies->getObject(dependencyIndex));
        if (!dependency) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s - internal error propagating compatibility dependencies.",
                getIdentifierCString());
            goto finish;
        }
        if (anArray->getNextIndexOfObject(dependency, 0) == (unsigned int)-1) {
            anArray->setObject(dependency);
        }
        dependency->addBleedthroughDependencies(anArray);
    }

    result = true;

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::flushDependencies(bool forceFlag)
{
    bool result = false;

   /* Only clear the dependencies if the kext isn't loaded;
    * we need the info for loaded kexts to track references.
    */
    if (!isLoaded() || forceFlag) {
        if (dependencies) {
            // xxx - check level
            OSKextLog(this,
                kOSKextLogProgressLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s flushing dependencies.",
                getIdentifierCString());
            OSSafeReleaseNULL(dependencies);

        }
        if (!isKernelComponent()) {
            flags.hasAllDependencies = 0;
        }
        result = true;
    }

    return result;
}

/*********************************************************************
*********************************************************************/
uint32_t
OSKext::getNumDependencies(void)
{
    if (!dependencies) {
        return 0;
    }
    return dependencies->getCount();
}

/*********************************************************************
*********************************************************************/
OSArray *
OSKext::getDependencies(void)
{
    return dependencies;
}

#if PRAGMA_MARK
#pragma mark OSMetaClass Support
#endif
/*********************************************************************
*********************************************************************/
OSReturn
OSKext::addClass(
    OSMetaClass * aClass,
    uint32_t      numClasses)
{
    OSReturn result = kOSMetaClassNoInsKModSet;

    if (!metaClasses) {
        metaClasses = OSSet::withCapacity(numClasses);
        if (!metaClasses) {
            goto finish;
        }
    }

    if (metaClasses->containsObject(aClass)) {
        OSKextLog(this,
            kOSKextLogWarningLevel |
            kOSKextLogLoadFlag,
            "Notice - kext %s has already registered class %s.",
            getIdentifierCString(),
            aClass->getClassName());
        result = kOSReturnSuccess;
        goto finish;
    }

    if (!metaClasses->setObject(aClass)) {
        goto finish;
    } else {
        OSKextLog(this,
            kOSKextLogDetailLevel |
            kOSKextLogLoadFlag,
            "Kext %s registered class %s.",
            getIdentifierCString(),
            aClass->getClassName());
    }

    if (!flags.autounloadEnabled) {
        const OSMetaClass * metaScan  = NULL;  // do not release

        for (metaScan = aClass; metaScan; metaScan = metaScan->getSuperClass()) {
            if (metaScan == OSTypeID(IOService)) {

                OSKextLog(this,
                    kOSKextLogProgressLevel |
                    kOSKextLogLoadFlag,
                    "Kext %s has IOService subclass %s; enabling autounload.",
                    getIdentifierCString(),
                    aClass->getClassName());

                flags.autounloadEnabled = 1;
                break;
            }
        }
    }

    result = kOSReturnSuccess;

finish:
    if (result != kOSReturnSuccess) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s failed to register class %s.",
            getIdentifierCString(),
            aClass->getClassName());
    }

    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::removeClass(
    OSMetaClass * aClass)
{
    OSReturn result = kOSMetaClassNoKModSet;

    if (!metaClasses) {
        goto finish;
    }

    if (!metaClasses->containsObject(aClass)) {
        OSKextLog(this,
            kOSKextLogWarningLevel |
            kOSKextLogLoadFlag,
            "Notice - kext %s asked to unregister unknown class %s.",
            getIdentifierCString(),
            aClass->getClassName());
        result = kOSReturnSuccess;
        goto finish;
    }

    OSKextLog(this,
        kOSKextLogDetailLevel |
        kOSKextLogLoadFlag,
        "Kext %s unregistering class %s.",
        getIdentifierCString(),
        aClass->getClassName());

    metaClasses->removeObject(aClass);
    
    result = kOSReturnSuccess;

finish:
    if (result != kOSReturnSuccess) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Failed to unregister kext %s class %s.",
            getIdentifierCString(),
            aClass->getClassName());
    }
    return result;
}

/*********************************************************************
*********************************************************************/
OSSet *
OSKext::getMetaClasses(void)
{
    return metaClasses;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::hasOSMetaClassInstances(void)
{
    bool                   result        = false;
    OSCollectionIterator * classIterator = NULL;  // must release
    OSMetaClass          * checkClass    = NULL;  // do not release

    if (!metaClasses) {
        goto finish;
    }

    classIterator = OSCollectionIterator::withCollection(metaClasses);
    if (!classIterator) {
        // xxx - log alloc failure?
        goto finish;
    }
    while ((checkClass = (OSMetaClass *)classIterator->getNextObject())) {
        if (checkClass->getInstanceCount()) {
            result = true;
            goto finish;
        }
    }

finish:
    
    OSSafeRelease(classIterator);
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::reportOSMetaClassInstances(
    const char     * kextIdentifier,
    OSKextLogSpec    msgLogSpec)
{
    OSKext * theKext = NULL; // must release
    
    theKext = OSKext::lookupKextWithIdentifier(kextIdentifier);
    if (!theKext) {
        goto finish;
    }
    
    theKext->reportOSMetaClassInstances(msgLogSpec);
finish:
    OSSafeRelease(theKext);
    return;
}

/*********************************************************************
*********************************************************************/
void
OSKext::reportOSMetaClassInstances(OSKextLogSpec msgLogSpec)
{
    OSCollectionIterator * classIterator = NULL;  // must release
    OSMetaClass          * checkClass    = NULL;  // do not release

    if (!metaClasses) {
        goto finish;
    }

    classIterator = OSCollectionIterator::withCollection(metaClasses);
    if (!classIterator) {
        goto finish;
    }
    while ((checkClass = (OSMetaClass *)classIterator->getNextObject())) {
        if (checkClass->getInstanceCount()) {
            OSKextLog(this,
                msgLogSpec,
                "    Kext %s class %s has %d instance%s.",
                getIdentifierCString(),
                checkClass->getClassName(),
                checkClass->getInstanceCount(),
                checkClass->getInstanceCount() == 1 ? "" : "s");
        }
    }

finish:
    OSSafeRelease(classIterator);
    return;
}

#if PRAGMA_MARK
#pragma mark User-Space Requests
#endif
/*********************************************************************
* XXX - this function is a big ugly mess
*********************************************************************/
/* static */
OSReturn
OSKext::handleRequest(
    host_priv_t     hostPriv,
    OSKextLogSpec   clientLogFilter,
    char          * requestBuffer,
    uint32_t        requestLength,
    char         ** responseOut,
    uint32_t      * responseLengthOut,
    char         ** logInfoOut,
    uint32_t      * logInfoLengthOut)
{
    OSReturn       result             = kOSReturnError;
    kern_return_t  kmem_result        = KERN_FAILURE;

    char         * response           = NULL;  // returned by reference
    uint32_t       responseLength     = 0;

    OSObject     * parsedXML      = NULL;  // must release
    OSDictionary * requestDict        = NULL;  // do not release
    OSString     * errorString        = NULL;  // must release

    OSData       * responseData       = NULL;  // must release
    OSObject     * responseObject = NULL;  // must release
    
    OSSerialize  * serializer         = NULL;  // must release

    OSArray      * logInfoArray       = NULL;  // must release

    OSString     * predicate          = NULL;  // do not release
    OSString     * kextIdentifier     = NULL;  // do not release
    OSArray      * kextIdentifiers    = NULL;  // do not release
    OSKext       * theKext            = NULL;  // do not release
    OSBoolean    * boolArg            = NULL;  // do not release

    IORecursiveLockLock(sKextLock);

    if (responseOut) {
        *responseOut = NULL;
        *responseLengthOut = 0;
    }
    if (logInfoOut) {
        *logInfoOut = NULL;
        *logInfoLengthOut = 0;
    }

    OSKext::setUserSpaceLogFilter(clientLogFilter, logInfoOut ? true : false);

   /* XML must be nul-terminated.
    */
    if (requestBuffer[requestLength - 1] != '\0') {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Invalid request from user space (not nul-terminated).");
        result = kOSKextReturnBadData;
        goto finish;
    }
    parsedXML = OSUnserializeXML((const char *)requestBuffer, &errorString);
    if (parsedXML) {
        requestDict = OSDynamicCast(OSDictionary, parsedXML);
    }
    if (!requestDict) {
        const char * errorCString = "(unknown error)";
        
        if (errorString && errorString->getCStringNoCopy()) {
            errorCString = errorString->getCStringNoCopy();
        } else if (parsedXML) {
            errorCString = "not a dictionary";
        }
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Error unserializing request from user space: %s.",
            errorCString);
        result = kOSKextReturnSerialization;
        goto finish;
    }

    predicate = _OSKextGetRequestPredicate(requestDict);
    if (!predicate) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Recieved kext request from user space with no predicate.");
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    OSKextLog(/* kext */ NULL,
        kOSKextLogDebugLevel |
        kOSKextLogIPCFlag,
        "Received '%s' request from user space.",
        predicate->getCStringNoCopy());
    
    result = kOSKextReturnNotPrivileged;
    if (hostPriv == HOST_PRIV_NULL) {
        if (!predicate->isEqualTo(kKextRequestPredicateGetLoaded) &&
            !predicate->isEqualTo(kKextRequestPredicateGetKernelLinkState) &&
            !predicate->isEqualTo(kKextRequestPredicateGetKernelLoadAddress)) {

            goto finish;
        }
    }

   /* Get common args in anticipation of use.
    */
    kextIdentifier = OSDynamicCast(OSString, _OSKextGetRequestArgument(
        requestDict, kKextRequestArgumentBundleIdentifierKey));
    kextIdentifiers = OSDynamicCast(OSArray, _OSKextGetRequestArgument(
        requestDict, kKextRequestArgumentBundleIdentifierKey));
    if (kextIdentifier) {
        theKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier));
    }
    boolArg = OSDynamicCast(OSBoolean, _OSKextGetRequestArgument(
        requestDict, kKextRequestArgumentValueKey));

    result = kOSKextReturnInvalidArgument;

    if (predicate->isEqualTo(kKextRequestPredicateStart)) {
        if (!kextIdentifier) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Invalid arguments to kext start request.");
        } else if (!theKext) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Kext %s not found for start request.",
                kextIdentifier->getCStringNoCopy());
            result = kOSKextReturnNotFound;
        } else {
            result = theKext->start();
        }

    } else if (predicate->isEqualTo(kKextRequestPredicateStop)) {
        if (!kextIdentifier) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Invalid arguments to kext stop request.");
        } else if (!theKext) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Kext %s not found for stop request.",
                kextIdentifier->getCStringNoCopy());
            result = kOSKextReturnNotFound;
        } else {
            result = theKext->stop();
        }

    } else if (predicate->isEqualTo(kKextRequestPredicateUnload)) {
        if (!kextIdentifier) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Invalid arguments to kext unload request.");
        } else if (!theKext) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Kext %s not found for unload request.",
                kextIdentifier->getCStringNoCopy());
            result = kOSKextReturnNotFound;
        } else {
            OSBoolean * terminateFlag = OSDynamicCast(OSBoolean,
                _OSKextGetRequestArgument(requestDict,
                    kKextRequestArgumentTerminateIOServicesKey));
            result = OSKext::removeKext(theKext, terminateFlag == kOSBooleanTrue);
        }

    } else if (predicate->isEqualTo(kKextRequestPredicateSendResource)) {
        result = OSKext::dispatchResource(requestDict);

    } else if (predicate->isEqualTo(kKextRequestPredicateGetLoaded)) {
        OSBoolean * delayAutounloadBool = NULL;
        
        delayAutounloadBool = OSDynamicCast(OSBoolean,
            _OSKextGetRequestArgument(requestDict,
                kKextRequestArgumentDelayAutounloadKey));

       /* If asked to delay autounload, reset the timer if it's currently set.
        * (That is, don't schedule an unload if one isn't already pending.
        */
        if (delayAutounloadBool == kOSBooleanTrue) {
            OSKext::considerUnloads(/* rescheduleOnly? */ true);
        }

        responseObject = OSDynamicCast(OSObject,
            OSKext::copyLoadedKextInfo(kextIdentifiers));
        if (!responseObject) {
            result = kOSKextReturnInternalError;
        } else {
            OSKextLog(/* kext */ NULL,
                kOSKextLogDebugLevel |
                kOSKextLogIPCFlag,
                "Returning loaded kext info.");
            result = kOSReturnSuccess;
        }

    } else if (predicate->isEqualTo(kKextRequestPredicateGetKernelLoadAddress)) {
        OSNumber * addressNum = NULL;  // released as responseObject
        kernel_segment_command_t * textseg = getsegbyname("__TEXT");

        if (!textseg) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag | kOSKextLogIPCFlag,
                "Can't find text segment for kernel load address.");
            result = kOSReturnError;
            goto finish;
        }

        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogIPCFlag,
            "Returning kernel load address 0x%llx.",
            (unsigned long long)textseg->vmaddr);
        addressNum = OSNumber::withNumber((long long unsigned int)textseg->vmaddr,
            8 * sizeof(long long unsigned int));
        responseObject = OSDynamicCast(OSObject, addressNum);
        result = kOSReturnSuccess;

    } else if (predicate->isEqualTo(kKextRequestPredicateGetKernelLinkState)) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogIPCFlag,
            "Returning kernel link state.");
        responseData = sKernelKext->linkState;
        responseData->retain();
        result = kOSReturnSuccess;

    } else if (predicate->isEqualTo(kKextRequestPredicateGetKernelRequests)) {

       /* Hand the current sKernelRequests array to the caller
        * (who must release it), and make a new one.
        */
        responseObject = OSDynamicCast(OSObject, sKernelRequests);
        sKernelRequests = OSArray::withCapacity(0);
        sPostedKextLoadIdentifiers->flushCollection();
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogIPCFlag,
            "Returning kernel requests.");
        result = kOSReturnSuccess;

    } else if (predicate->isEqualTo(kKextRequestPredicateGetAllLoadRequests)) {
        
        /* Return the set of all requested bundle identifiers */
        responseObject = OSDynamicCast(OSObject, sAllKextLoadIdentifiers);
        responseObject->retain();
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogIPCFlag,
            "Returning load requests.");
        result = kOSReturnSuccess;
    }

   /**********
    * Now we have handle the request, or not. Gather up the response & logging
    * info to ship to user space.
    *********/
    
   /* Note: Nothing in OSKext is supposed to retain requestDict,
    * but you never know....
    */
    if (requestDict->getRetainCount() > 1) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogWarningLevel |
            kOSKextLogIPCFlag,
            "Request from user space still retained by a kext; "
            "probable memory leak.");
    }

    if (responseData && responseObject) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Mistakenly generated both data & plist responses to user request "
            "(returning only data).");
    } 

    if (responseData && responseData->getLength() && responseOut) {

        response = (char *)responseData->getBytesNoCopy();
        responseLength = responseData->getLength();
    } else if (responseOut && responseObject) {
        serializer = OSSerialize::withCapacity(0);
        if (!serializer) {
            result = kOSKextReturnNoMemory;
            goto finish;
        }

        if (!responseObject->serialize(serializer)) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to serialize response to request from user space.");
            result = kOSKextReturnSerialization;
            goto finish;
        }

        response = (char *)serializer->text();
        responseLength = serializer->getLength();
    }
    
    if (responseOut && response) {
        char * buffer;

       /* This kmem_alloc sets the return value of the function.
        */
        kmem_result = kmem_alloc(kernel_map, (vm_offset_t *)&buffer,
            responseLength);
        if (kmem_result != KERN_SUCCESS) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to copy response to request from user space.");
            result = kmem_result;
            goto finish;
        } else {
            memcpy(buffer, response, responseLength);
            *responseOut = buffer;
            *responseLengthOut = responseLength;
        }
    }

finish:

   /* Gather up the collected log messages for user space. Any messages
    * messages past this call will not make it up as log messages but
    * will be in the system log. Note that we ignore the return of the
    * serialize; it has no bearing on the operation at hand even if we
    * fail to get the log messages.
    */
    logInfoArray = OSKext::clearUserSpaceLogFilter();

    if (logInfoArray && logInfoOut && logInfoLengthOut) {
        (void)OSKext::serializeLogInfo(logInfoArray,
            logInfoOut, logInfoLengthOut);
    }

    IORecursiveLockUnlock(sKextLock);

    OSSafeRelease(requestDict);
    OSSafeRelease(errorString);
    OSSafeRelease(responseData);
    OSSafeRelease(responseObject);
    OSSafeRelease(serializer);
    OSSafeRelease(logInfoArray);

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSArray *
OSKext::copyLoadedKextInfo(OSArray * kextIdentifiers)
{
    OSArray      * result = NULL;
    OSDictionary * kextInfo = NULL;  // must release
    uint32_t       count, i;
    uint32_t       idCount = 0;
    uint32_t       idIndex = 0;

    IORecursiveLockLock(sKextLock);

   /* Empty list of bundle ids is equivalent to no list (get all).
    */
    if (kextIdentifiers && !kextIdentifiers->getCount()) {
        kextIdentifiers = NULL;
    } else if (kextIdentifiers) {
        idCount = kextIdentifiers->getCount();
    }

    count = sLoadedKexts->getCount();
    result = OSArray::withCapacity(count);
    if (!result) {
        goto finish;
    }
    for (i = 0; i < count; i++) {
        OSKext   * thisKext     = NULL;  // do not release
        Boolean    includeThis  = true;

        if (kextInfo) {
            kextInfo->release();
            kextInfo = NULL;
        }
        thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (!thisKext) {
            continue;
        }

       /* Skip current kext if we have a list of bundle IDs and
        * it isn't in the list.
        */
        if (kextIdentifiers) {
            const OSString * thisKextID = thisKext->getIdentifier();

            includeThis = false;

            for (idIndex = 0; idIndex < idCount; idIndex++) {
                const OSString * thisRequestID = OSDynamicCast(OSString,
                    kextIdentifiers->getObject(idIndex));
                if (thisKextID->isEqualTo(thisRequestID)) {
                    includeThis = true;
                    break;
                }
            }
        }
        
        if (!includeThis) {
            continue;
        }

        kextInfo = thisKext->copyInfo();
        result->setObject(kextInfo);
    }
    
finish:
    IORecursiveLockUnlock(sKextLock);

    if (kextInfo) kextInfo->release();

    return result;
}

/*********************************************************************
Load Tag
Bundle ID
Bundle Version
Path
Load Address
Load Size
Wired Size
Version
Dependency Load Tags
# Dependent References
UUID
RetainCount
*********************************************************************/
#define _OSKextLoadInfoDictCapacity   (12)

OSDictionary *
OSKext::copyInfo(void)
{
    OSDictionary         * result             = NULL;
    bool                   success            = false;
    OSNumber             * cpuTypeNumber      = NULL;  // must release
    OSNumber             * cpuSubtypeNumber   = NULL;  // must release
    OSString             * versionString      = NULL;  // do not release
    OSData               * uuid               = NULL;  // must release
    OSNumber             * scratchNumber      = NULL;  // must release
    OSArray              * dependencyLoadTags = NULL;  // must release
    OSCollectionIterator * metaClassIterator  = NULL;  // must release
    OSArray              * metaClassInfo      = NULL;  // must release
    OSDictionary         * metaClassDict      = NULL;  // must release
    OSMetaClass          * thisMetaClass      = NULL;  // do not release
    OSString             * metaClassName      = NULL;  // must release
    OSString             * superclassName     = NULL;  // must release
    uint32_t               count, i;

    result = OSDictionary::withCapacity(_OSKextLoadInfoDictCapacity);
    if (!result) {
        goto finish;
    }

   /* CPU Type & Subtype.
    * Use the CPU type of the kernel for all (loaded) kexts.
    * xxx - should we not include this for the kernel components,
    * xxx - or for any interface? they have mach-o files, they're just weird.
    */
    if (linkedExecutable || (this == sKernelKext)) {

        cpuTypeNumber = OSNumber::withNumber(
            (long long unsigned int)_mh_execute_header.cputype,
            8 * sizeof(_mh_execute_header.cputype));
        if (cpuTypeNumber) {
            result->setObject(kOSBundleCPUTypeKey, cpuTypeNumber);
        }
    }
    
    // I don't want to rely on a mach header for nonkernel kexts, yet
    if (this == sKernelKext) {
        cpuSubtypeNumber = OSNumber::withNumber(
            (long long unsigned int)_mh_execute_header.cputype,
            8 * sizeof(_mh_execute_header.cputype));
        if (cpuSubtypeNumber) {
            result->setObject(kOSBundleCPUSubtypeKey, cpuSubtypeNumber);
        }
    }

   /* CFBundleIdentifier.
    */
    result->setObject(kCFBundleIdentifierKey, bundleID);

   /* CFBundleVersion.
    */
    versionString = OSDynamicCast(OSString,
        getPropertyForHostArch(kCFBundleVersionKey));
    if (versionString) {
        result->setObject(kCFBundleVersionKey, versionString);
    }

   /* OSBundleCompatibleVersion.
    */
    versionString = OSDynamicCast(OSString,
        getPropertyForHostArch(kOSBundleCompatibleVersionKey));
    if (versionString) {
        result->setObject(kOSBundleCompatibleVersionKey, versionString);
    }

   /* Path.
    */
    if (path) {
        result->setObject(kOSBundlePathKey, path);
    }

   /* UUID.
    */
    uuid = copyUUID();
    if (uuid) {
        result->setObject(kOSBundleUUIDKey, uuid);
    }
    
   /*****
    * OSKernelResource, OSBundleIsInterface, OSBundlePrelinked, OSBundleStarted.
    */
    result->setObject(kOSKernelResourceKey,
        isKernelComponent() ? kOSBooleanTrue : kOSBooleanFalse);
    
    result->setObject(kOSBundleIsInterfaceKey,
        isInterface() ? kOSBooleanTrue : kOSBooleanFalse);
    
    result->setObject(kOSBundlePrelinkedKey,
        isPrelinked() ? kOSBooleanTrue : kOSBooleanFalse);
    
    result->setObject(kOSBundleStartedKey,
        isStarted() ? kOSBooleanTrue : kOSBooleanFalse);

   /* LoadTag (Index).
    */
    scratchNumber = OSNumber::withNumber((unsigned long long)loadTag,
        /* numBits */ 8 * sizeof(loadTag));
    if (scratchNumber) {
        result->setObject(kOSBundleLoadTagKey, scratchNumber);
        OSSafeReleaseNULL(scratchNumber);
    }
    
   /* LoadAddress, LoadSize.
    */
    if (isInterface() || linkedExecutable) {
       /* These go to userspace via serialization, so we don't want any doubts
        * about their size.
        */
        uint64_t    loadAddress = 0;
        uint32_t    loadSize    = 0;
        uint32_t    wiredSize   = 0;

       /* Interfaces always report 0 load address & size.
        * Just the way they roll.
        *
        * xxx - leaving in # when we have a linkedExecutable...a kernelcomp
        * xxx - shouldn't have one!
        */
        if (linkedExecutable /* && !isInterface() */) {
            loadAddress = (uint64_t)linkedExecutable->getBytesNoCopy();
            loadSize = linkedExecutable->getLength();
            
           /* If we have a kmod_info struct, calculated the wired size
            * from that. Otherwise it's the full load size.
            */
            if (kmod_info) {
                wiredSize = loadSize - kmod_info->hdr_size;
            } else {
                wiredSize = loadSize;
            }
        }

        scratchNumber = OSNumber::withNumber(
            (unsigned long long)(loadAddress),
            /* numBits */ 8 * sizeof(loadAddress));
        if (scratchNumber) {
            result->setObject(kOSBundleLoadAddressKey, scratchNumber);
            OSSafeReleaseNULL(scratchNumber);
        }
        scratchNumber = OSNumber::withNumber(
            (unsigned long long)(loadSize),
            /* numBits */ 8 * sizeof(loadSize));
        if (scratchNumber) {
            result->setObject(kOSBundleLoadSizeKey, scratchNumber);
            OSSafeReleaseNULL(scratchNumber);
        }
        scratchNumber = OSNumber::withNumber(
            (unsigned long long)(wiredSize),
            /* numBits */ 8 * sizeof(wiredSize));
        if (scratchNumber) {
            result->setObject(kOSBundleWiredSizeKey, scratchNumber);
            OSSafeReleaseNULL(scratchNumber);
        }
    }
    
   /* OSBundleDependencies. In descending order for
    * easy compatibility with kextstat(8).
    */
    if ((count = getNumDependencies())) {
        dependencyLoadTags = OSArray::withCapacity(count);
        result->setObject(kOSBundleDependenciesKey, dependencyLoadTags);

        i = count - 1;
        do {
            OSKext * dependency = OSDynamicCast(OSKext,
                dependencies->getObject(i));

            OSSafeReleaseNULL(scratchNumber);
            
            if (!dependency) {
                continue;
            }
            scratchNumber = OSNumber::withNumber(
                (unsigned long long)dependency->getLoadTag(),
                /* numBits*/ 8 * sizeof(loadTag));
            if (scratchNumber) {
                dependencyLoadTags->setObject(scratchNumber);
            }
        } while (i--);
    }

    OSSafeReleaseNULL(scratchNumber);

   /* OSBundleMetaClasses.
    */
    if (metaClasses && metaClasses->getCount()) {
        metaClassIterator = OSCollectionIterator::withCollection(metaClasses);
        metaClassInfo = OSArray::withCapacity(metaClasses->getCount());
        if (!metaClassIterator || !metaClassInfo) {
            goto finish;
        }
        result->setObject(kOSBundleClassesKey, metaClassInfo);

        while ( (thisMetaClass = OSDynamicCast(OSMetaClass,
            metaClassIterator->getNextObject())) ) {

            OSSafeReleaseNULL(metaClassDict);
            OSSafeReleaseNULL(metaClassName);
            OSSafeReleaseNULL(superclassName);
            OSSafeReleaseNULL(scratchNumber);

            metaClassDict = OSDictionary::withCapacity(3);
            if (!metaClassDict) {
                goto finish;
            }

            metaClassName = OSString::withCString(thisMetaClass->getClassName());
            if (thisMetaClass->getSuperClass()) {
                superclassName = OSString::withCString(
                    thisMetaClass->getSuperClass()->getClassName());
            }
            scratchNumber = OSNumber::withNumber(thisMetaClass->getInstanceCount(),
                8 * sizeof(unsigned int));
            if (!metaClassDict || !metaClassName || !superclassName ||
                !scratchNumber) {

                goto finish;
            }

            metaClassInfo->setObject(metaClassDict);
            metaClassDict->setObject(kOSMetaClassNameKey, metaClassName);
            metaClassDict->setObject(kOSMetaClassSuperclassNameKey, superclassName);
            metaClassDict->setObject(kOSMetaClassTrackingCountKey, scratchNumber);
        }
    }
    
   /* OSBundleRetainCount.
    */
    OSSafeReleaseNULL(scratchNumber);
    {
        int extRetainCount = getRetainCount() - 1;
        if (isLoaded()) {
            extRetainCount--;
        }
        scratchNumber = OSNumber::withNumber(
            (int)extRetainCount,
            /* numBits*/ 8 * sizeof(int));
        if (scratchNumber) {
            result->setObject(kOSBundleRetainCountKey, scratchNumber);
        }
    }

    success = true;
finish:
    OSSafeRelease(cpuTypeNumber);
    OSSafeRelease(cpuSubtypeNumber);
    OSSafeRelease(uuid);
    OSSafeRelease(scratchNumber);
    OSSafeRelease(dependencyLoadTags);
    OSSafeRelease(metaClassIterator);
    OSSafeRelease(metaClassInfo);
    OSSafeRelease(metaClassDict);
    OSSafeRelease(metaClassName);
    OSSafeRelease(superclassName);
    if (!success) {
        OSSafeReleaseNULL(result);
    }
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::requestResource(
    const char                    * kextIdentifierCString,
    const char                    * resourceNameCString,
    OSKextRequestResourceCallback   callback,
    void                          * context,
    OSKextRequestTag              * requestTagOut)
{
    OSReturn           result          = kOSReturnError;
    OSKext           * callbackKext    = NULL;  // must release (looked up)

    OSKextRequestTag   requestTag      = -1;
    OSNumber         * requestTagNum   = NULL;  // must release

    OSDictionary     * requestDict     = NULL;  // must release
    OSString         * kextIdentifier  = NULL;  // must release
    OSString         * resourceName    = NULL;  // must release

    OSDictionary     * callbackRecord  = NULL;  // must release
    OSData           * callbackWrapper = NULL;  // must release

    OSData           * contextWrapper  = NULL;  // must release
            
    IORecursiveLockLock(sKextLock);

    if (requestTagOut) {
        *requestTagOut = kOSKextRequestTagInvalid;
    }

    if (!kextIdentifierCString || !resourceNameCString || !callback) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    callbackKext = OSKext::lookupKextWithAddress((vm_address_t)callback);
    if (!callbackKext) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "Resource request has bad callback address.");
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }
    if (!callbackKext->flags.starting && !callbackKext->flags.started) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "Resource request callback is in a kext that is not started.");
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

   /* Do not allow any new requests to be made on a kext that is unloading.
    */
    if (callbackKext->flags.stopping) {
        result = kOSKextReturnStopping;
        goto finish;
    }

   /* If we're wrapped the next available request tag around to the negative
    * numbers, we can't service any more requests.
    */
    if (sNextRequestTag == kOSKextRequestTagInvalid) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "No more request tags available; restart required.");
        result = kOSKextReturnNoResources;
        goto finish;
    }
    requestTag = sNextRequestTag++;

    result = _OSKextCreateRequest(kKextRequestPredicateRequestResource,
        &requestDict);
    if (result != kOSReturnSuccess) {
        goto finish;
    }
    
    kextIdentifier = OSString::withCString(kextIdentifierCString);
    resourceName   = OSString::withCString(resourceNameCString);
    requestTagNum  = OSNumber::withNumber((long long unsigned int)requestTag,
        8 * sizeof(requestTag));
    if (!kextIdentifier ||
        !resourceName   ||
        !requestTagNum  ||
        !_OSKextSetRequestArgument(requestDict,
            kKextRequestArgumentBundleIdentifierKey, kextIdentifier) ||
        !_OSKextSetRequestArgument(requestDict,
            kKextRequestArgumentNameKey, resourceName) ||
        !_OSKextSetRequestArgument(requestDict,
            kKextRequestArgumentRequestTagKey, requestTagNum)) {

        result = kOSKextReturnNoMemory;
        goto finish;
    }

    callbackRecord = OSDynamicCast(OSDictionary, requestDict->copyCollection());
    if (!callbackRecord) {
        result = kOSKextReturnNoMemory;
        goto finish;
    }
    // we validate callback address at call time
    callbackWrapper = OSData::withBytes((void *)&callback, sizeof(void *));
    if (context) {
        contextWrapper = OSData::withBytes((void *)&context, sizeof(void *));
    }
    if (!callbackWrapper || !_OSKextSetRequestArgument(callbackRecord,
            kKextRequestArgumentCallbackKey, callbackWrapper)) {

        result = kOSKextReturnNoMemory;
        goto finish;
    }

    if (context) {
        if (!contextWrapper || !_OSKextSetRequestArgument(callbackRecord,
            kKextRequestArgumentContextKey, contextWrapper)) {

            result = kOSKextReturnNoMemory;
            goto finish;
        }
    }

   /* Only post the requests after all the other potential failure points
    * have been passed.
    */
    if (!sKernelRequests->setObject(requestDict) ||
        !sRequestCallbackRecords->setObject(callbackRecord)) {

        result = kOSKextReturnNoMemory;
        goto finish;
    }

    OSKextPingKextd();

    result = kOSReturnSuccess;
    if (requestTagOut) {
        *requestTagOut = requestTag;
    }

finish:

   /* If we didn't succeed, yank the request & callback
    * from their holding arrays.
    */
    if (result != kOSReturnSuccess) {
        unsigned int index;
        
        index = sKernelRequests->getNextIndexOfObject(requestDict, 0);
        if (index != (unsigned int)-1) {
            sKernelRequests->removeObject(index);
        }
        index = sRequestCallbackRecords->getNextIndexOfObject(callbackRecord, 0);
        if (index != (unsigned int)-1) {
            sRequestCallbackRecords->removeObject(index);
        }
    }

    OSKext::considerUnloads(/* rescheduleOnly? */ true);

    IORecursiveLockUnlock(sKextLock);

    if (callbackKext)    callbackKext->release();
    if (requestTagNum)   requestTagNum->release();

    if (requestDict)     requestDict->release();
    if (kextIdentifier)  kextIdentifier->release();
    if (resourceName)    resourceName->release();

    if (callbackRecord)  callbackRecord->release();
    if (callbackWrapper) callbackWrapper->release();
    if (contextWrapper)  contextWrapper->release();

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::dequeueCallbackForRequestTag(
    OSKextRequestTag    requestTag,
    OSDictionary     ** callbackRecordOut)
{
    OSReturn   result = kOSReturnError;
    OSNumber * requestTagNum  = NULL;  // must release

    requestTagNum  = OSNumber::withNumber((long long unsigned int)requestTag,
        8 * sizeof(requestTag));
    if (!requestTagNum) {
        goto finish;
    }

    result = OSKext::dequeueCallbackForRequestTag(requestTagNum,
        callbackRecordOut);

finish:
    OSSafeRelease(requestTagNum);

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::dequeueCallbackForRequestTag(
    OSNumber     *    requestTagNum,
    OSDictionary ** callbackRecordOut)
{
    OSReturn        result          = kOSKextReturnInvalidArgument;
    OSDictionary  * callbackRecord  = NULL;  // retain if matched!
    OSNumber      * callbackTagNum  = NULL;  // do not release
    unsigned int    count, i;

    IORecursiveLockLock(sKextLock);

    result = kOSReturnError;
    count = sRequestCallbackRecords->getCount();
    for (i = 0; i < count; i++) {
        callbackRecord = OSDynamicCast(OSDictionary,
            sRequestCallbackRecords->getObject(i));
        if (!callbackRecord) {
            goto finish;
        }

       /* If we don't find a tag, we basically have a leak here. Maybe
        * we should just remove it.
        */
        callbackTagNum = OSDynamicCast(OSNumber, _OSKextGetRequestArgument(
            callbackRecord, kKextRequestArgumentRequestTagKey));
        if (!callbackTagNum) {
            goto finish;
        }

       /* We could be even more paranoid and check that all the incoming
        * args match what's in the callback record.
        */
        if (callbackTagNum->isEqualTo(requestTagNum)) {
            if (callbackRecordOut) {
                *callbackRecordOut = callbackRecord;
                callbackRecord->retain();
            }
            sRequestCallbackRecords->removeObject(i);
            result = kOSReturnSuccess;
            goto finish;
        }
    }
    result = kOSKextReturnNotFound;

finish:
    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::dispatchResource(OSDictionary * requestDict)
{
    OSReturn                        result          = kOSReturnError;
    OSDictionary                  * callbackRecord  = NULL;  // must release
    OSNumber                      * requestTag      = NULL;  // do not release
    OSNumber                      * requestResult   = NULL;  // do not release
    OSData                        * dataObj         = NULL;  // do not release
    uint32_t                        dataLength      = 0;
    const void                    * dataPtr         = NULL;  // do not free
    OSData                        * callbackWrapper = NULL;  // do not release
    OSKextRequestResourceCallback   callback        = NULL;
    OSData                        * contextWrapper  = NULL;  // do not release
    void                          * context         = NULL;  // do not free
    OSKext                        * callbackKext    = NULL;  // must release (looked up)

    IORecursiveLockLock(sKextLock);

   /* Get the args from the request. Right now we need the tag
    * to look up the callback record, and the result for invoking the callback.
    */
    requestTag = OSDynamicCast(OSNumber, _OSKextGetRequestArgument(requestDict,
        kKextRequestArgumentRequestTagKey));
    requestResult = OSDynamicCast(OSNumber, _OSKextGetRequestArgument(requestDict,
        kKextRequestArgumentResultKey));
    if (!requestTag || !requestResult) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

   /* Look for a callback record matching this request's tag.
    */
    result = dequeueCallbackForRequestTag(requestTag, &callbackRecord);
    if (result != kOSReturnSuccess) {
        goto finish;
    }

   /*****
    * Get the context pointer of the callback record (if there is one).
    */
    contextWrapper = OSDynamicCast(OSData, _OSKextGetRequestArgument(callbackRecord,
        kKextRequestArgumentContextKey));
    context = _OSKextExtractPointer(contextWrapper);
    if (contextWrapper && !context) {
        goto finish;
    }

    callbackWrapper = OSDynamicCast(OSData,
        _OSKextGetRequestArgument(callbackRecord,
            kKextRequestArgumentCallbackKey));
    callback = (OSKextRequestResourceCallback)
        _OSKextExtractPointer(callbackWrapper);
    if (!callback) {
        goto finish;
    }

   /* Check for a data obj. We might not have one and that's ok, that means
    * we didn't find the requested resource, and we still have to tell the
    * caller that via the callback.
    */
    dataObj = OSDynamicCast(OSData, _OSKextGetRequestArgument(requestDict,
        kKextRequestArgumentValueKey));
    if (dataObj) {
        dataPtr = dataObj->getBytesNoCopy();
        dataLength = dataObj->getLength();
    }
    
    callbackKext = OSKext::lookupKextWithAddress((vm_address_t)callback);
    if (!callbackKext) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "Can't invoke callback for resource request; "
            "no kext loaded at callback address %p.",
            callback);
        goto finish;
    }
    if (!callbackKext->flags.starting && !callbackKext->flags.started) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "Can't invoke kext resource callback; "
            "kext at callback address %p is not running.",
            callback);
        goto finish;
    }

    (void)callback(requestTag->unsigned32BitValue(),
        (OSReturn)requestResult->unsigned32BitValue(),
        dataPtr, dataLength, context);
        
    result = kOSReturnSuccess;

finish:
    if (callbackKext)   callbackKext->release();
    if (callbackRecord) callbackRecord->release();

    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::invokeRequestCallback(
    OSDictionary * callbackRecord,
    OSReturn       callbackResult)
{
    OSString * predicate  = _OSKextGetRequestPredicate(callbackRecord);
    OSNumber * resultNum  = NULL;  // must release

    if (!predicate) {
        goto finish;
    }

    resultNum  = OSNumber::withNumber((long long unsigned int)callbackResult,
        8 * sizeof(callbackResult));
    if (!resultNum) {
        goto finish;
    }
    
   /* Insert the result into the callback record and dispatch it as if it
    * were the reply coming down from user space.
    */
    _OSKextSetRequestArgument(callbackRecord, kKextRequestArgumentResultKey,
        resultNum);

    if (predicate->isEqualTo(kKextRequestPredicateRequestResource)) {
       /* This removes the pending callback record.
        */
        OSKext::dispatchResource(callbackRecord);
    }

finish:
    if (resultNum) resultNum->release();
    return;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::cancelRequest(
    OSKextRequestTag    requestTag,
    void             ** contextOut)
{
    OSReturn       result         = kOSKextReturnNoMemory;
    OSDictionary * callbackRecord = NULL;  // must release
    OSData       * contextWrapper = NULL;  // do not release

    result = OSKext::dequeueCallbackForRequestTag(requestTag,
        &callbackRecord);
        
    if (result == kOSReturnSuccess && contextOut) {
        contextWrapper = OSDynamicCast(OSData,
            _OSKextGetRequestArgument(callbackRecord,
                kKextRequestArgumentContextKey));
        *contextOut = _OSKextExtractPointer(contextWrapper);
    }
        
    if (callbackRecord) callbackRecord->release();

    return result;
}

/*********************************************************************
*********************************************************************/
void
OSKext::invokeOrCancelRequestCallbacks(
    OSReturn callbackResult,
    bool     invokeFlag)
{
    unsigned int count, i;
    
    IORecursiveLockLock(sKextLock);

    count = sRequestCallbackRecords->getCount();
    if (!count) {
        goto finish;
    }

    i = count - 1;
    do {
        OSDictionary * request = OSDynamicCast(OSDictionary,
            sRequestCallbackRecords->getObject(i));

        if (!request) {
            continue;
        }
        OSData * callbackWrapper = OSDynamicCast(OSData,
            _OSKextGetRequestArgument(request,
                kKextRequestArgumentCallbackKey));
            
        if (!callbackWrapper) {
            sRequestCallbackRecords->removeObject(i);
            continue;
        }

        vm_address_t callbackAddress = (vm_address_t)
            _OSKextExtractPointer(callbackWrapper);

        if ((kmod_info->address <= callbackAddress) &&
            (callbackAddress < (kmod_info->address + kmod_info->size))) {

            if (invokeFlag) {
               /* This removes the callback record.
                */
                invokeRequestCallback(request, callbackResult);
            } else {
                sRequestCallbackRecords->removeObject(i);
            }
        }
    } while (i--);

finish:
    IORecursiveLockUnlock(sKextLock);
    return;
}

/*********************************************************************
*********************************************************************/
uint32_t
OSKext::countRequestCallbacks(void)
{
    uint32_t     result = 0;
    unsigned int count, i;
    
    IORecursiveLockLock(sKextLock);

    count = sRequestCallbackRecords->getCount();
    if (!count) {
        goto finish;
    }

    i = count - 1;
    do {
        OSDictionary * request = OSDynamicCast(OSDictionary,
            sRequestCallbackRecords->getObject(i));

        if (!request) {
            continue;
        }
        OSData * callbackWrapper = OSDynamicCast(OSData,
            _OSKextGetRequestArgument(request,
                kKextRequestArgumentCallbackKey));
            
        if (!callbackWrapper) {
            continue;
        }

        vm_address_t callbackAddress = (vm_address_t)
            _OSKextExtractPointer(callbackWrapper);

        if ((kmod_info->address <= callbackAddress) &&
            (callbackAddress < (kmod_info->address + kmod_info->size))) {

            result++;
        }
    } while (i--);

finish:
    IORecursiveLockUnlock(sKextLock);
    return result;
}

/*********************************************************************
*********************************************************************/
static OSReturn _OSKextCreateRequest(
    const char    * predicate,
    OSDictionary ** requestP)
{
    OSReturn result = kOSKextReturnNoMemory;
    OSDictionary * request = NULL;  // must release on error
    OSDictionary * args = NULL;     // must release
    
    request = OSDictionary::withCapacity(2);
    if (!request) {
        goto finish;
    }
    result = _OSDictionarySetCStringValue(request,
        kKextRequestPredicateKey, predicate);
    if (result != kOSReturnSuccess) {
        goto finish;
    }
    result = kOSReturnSuccess;

finish:
    if (result != kOSReturnSuccess) {
        if (request) request->release();
    } else {
        *requestP = request;
    }
    if (args) args->release();

    return result;
}
    
/*********************************************************************
*********************************************************************/
static OSString * _OSKextGetRequestPredicate(OSDictionary * requestDict)
{
    return OSDynamicCast(OSString,
        requestDict->getObject(kKextRequestPredicateKey));
}

/*********************************************************************
*********************************************************************/
static OSObject * _OSKextGetRequestArgument(
    OSDictionary * requestDict,
    const char   * argName)
{
    OSDictionary * args = OSDynamicCast(OSDictionary,
        requestDict->getObject(kKextRequestArgumentsKey));
    if (args) {
        return args->getObject(argName);
    }
    return NULL;
}

/*********************************************************************
*********************************************************************/
static bool _OSKextSetRequestArgument(
    OSDictionary * requestDict,
    const char   * argName,
    OSObject     * value)
{
    OSDictionary * args = OSDynamicCast(OSDictionary,
        requestDict->getObject(kKextRequestArgumentsKey));
    if (!args) {
        args = OSDictionary::withCapacity(2);
        if (!args) {
            goto finish;
        }
        requestDict->setObject(kKextRequestArgumentsKey, args);
        args->release();
    }
    if (args) {
        return args->setObject(argName, value);
    }
finish:
    return false;
}

/*********************************************************************
*********************************************************************/
static void * _OSKextExtractPointer(OSData * wrapper)
{
    void       * result = NULL;
    const void * resultPtr = NULL;
    
    if (!wrapper) {
        goto finish;
    }
    resultPtr = wrapper->getBytesNoCopy();
    result = *(void **)resultPtr;
finish:
    return result;
}

/*********************************************************************
*********************************************************************/
static OSReturn _OSDictionarySetCStringValue(
    OSDictionary * dict,
    const char   * cKey,
    const char   * cValue)
{
    OSReturn result = kOSKextReturnNoMemory;
    const OSSymbol * key = NULL;  // must release
    OSString * value = NULL;  // must release
    
    key = OSSymbol::withCString(cKey);
    value = OSString::withCString(cValue);
    if (!key || !value) {
        goto finish;
    }
    if (dict->setObject(key, value)) {
        result = kOSReturnSuccess;
    }

finish:
    if (key)   key->release();
    if (value) value->release();

    return result;
}

#if PRAGMA_MARK
#pragma mark Personalities (IOKit Drivers)
#endif
/*********************************************************************
*********************************************************************/
/* static */
OSArray *
OSKext::copyAllKextPersonalities(bool filterSafeBootFlag)
{
    OSArray              * result                = NULL;  // returned
    OSCollectionIterator * kextIterator          = NULL;  // must release
    OSArray              * personalities         = NULL;  // must release
    OSCollectionIterator * personalitiesIterator = NULL;  // must release

    OSString             * kextID                = NULL;  // do not release
    OSKext               * theKext               = NULL;  // do not release
    
    IORecursiveLockLock(sKextLock);

   /* Let's conservatively guess that any given kext has around 3
    * personalities for now.
    */
    result = OSArray::withCapacity(sKextsByID->getCount() * 3);
    if (!result) {
        goto finish;
    }
    
    kextIterator = OSCollectionIterator::withCollection(sKextsByID);
    if (!kextIterator) {
        goto finish;
    }
    
    while ((kextID = OSDynamicCast(OSString, kextIterator->getNextObject()))) {
        if (personalitiesIterator) {
            personalitiesIterator->release();
            personalitiesIterator = NULL;
        }
        if (personalities) {
            personalities->release();
            personalities = NULL;
        }
        
        theKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextID));
        if (!sSafeBoot || !filterSafeBootFlag || theKext->isLoadableInSafeBoot()) {
            personalities = theKext->copyPersonalitiesArray();
            if (!personalities) {
                continue;
            }
            result->merge(personalities);
        } else {
            // xxx - check for better place to put this log msg
            OSKextLog(theKext,
                kOSKextLogWarningLevel |
                kOSKextLogLoadFlag,
                "Kext %s is not loadable during safe boot; "
                "omitting its personalities.",
                theKext->getIdentifierCString());
        }

    }

finish:
    IORecursiveLockUnlock(sKextLock);

    if (kextIterator)          kextIterator->release();
    if (personalitiesIterator) personalitiesIterator->release();
    if (personalities)         personalities->release();

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::sendAllKextPersonalitiesToCatalog(bool startMatching)
{
    int numPersonalities = 0;

    OSKextLog(/* kext */ NULL,
        kOSKextLogStepLevel |
        kOSKextLogLoadFlag,
        "Sending all eligible registered kexts' personalities "
        "to the IOCatalogue %s.",
        startMatching ? "and starting matching" : "but not starting matching");

    OSArray * personalities = OSKext::copyAllKextPersonalities(
        /* filterSafeBootFlag */ true);

    if (personalities) {
        gIOCatalogue->addDrivers(personalities, startMatching);
        numPersonalities = personalities->getCount();
        personalities->release();
    }

    OSKextLog(/* kext */ NULL,
        kOSKextLogStepLevel |
        kOSKextLogLoadFlag,
        "%d kext personalit%s sent to the IOCatalogue; %s.",
        numPersonalities, numPersonalities > 0 ? "ies" : "y",
        startMatching ? "matching started" : "matching not started");
    return;
}

/*********************************************************************
* Do not make a deep copy, just convert the IOKitPersonalities dict
* to an array for sending to the IOCatalogue.
*********************************************************************/
OSArray *
OSKext::copyPersonalitiesArray(void)
{
    OSArray              * result                      = NULL;
    OSDictionary         * personalities               = NULL;  // do not release
    OSCollectionIterator * personalitiesIterator       = NULL;  // must release

    OSString             * personalityName             = NULL;  // do not release    
    OSString             * personalityBundleIdentifier = NULL;  // do not release

    personalities = OSDynamicCast(OSDictionary,
        getPropertyForHostArch(kIOKitPersonalitiesKey));
    if (!personalities) {
        goto finish;
    }

    result = OSArray::withCapacity(personalities->getCount());
    if (!result) {
        goto finish;
    }

    personalitiesIterator =
        OSCollectionIterator::withCollection(personalities);
    if (!personalitiesIterator) {
        goto finish;
    }
    while ((personalityName = OSDynamicCast(OSString,
            personalitiesIterator->getNextObject()))) {
                
        OSDictionary * personality = OSDynamicCast(OSDictionary,
            personalities->getObject(personalityName));

       /******
        * If the personality doesn't have a CFBundleIdentifier, or if it
        * differs from the kext's, insert the kext's ID so we can find it.
        * The publisher ID is used to remove personalities from bundles
        * correctly.
        */
        personalityBundleIdentifier = OSDynamicCast(OSString,
            personality->getObject(kCFBundleIdentifierKey));

        if (!personalityBundleIdentifier) {
            personality->setObject(kCFBundleIdentifierKey, bundleID);
        } else if (!personalityBundleIdentifier->isEqualTo(bundleID)) {
            personality->setObject(kIOPersonalityPublisherKey, bundleID);
        }

        result->setObject(personality);
    }

finish:
    if (personalitiesIterator) personalitiesIterator->release();

    return result;
}

/*********************************************************************
Might want to change this to a bool return?
*********************************************************************/
OSReturn
OSKext::sendPersonalitiesToCatalog(
    bool      startMatching,
    OSArray * personalityNames)
{
    OSReturn       result              = kOSReturnSuccess;
    OSArray      * personalitiesToSend = NULL;  // must release
    OSDictionary * kextPersonalities   = NULL;  // do not release
    int            count, i;

    if (!sLoadEnabled) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext loading is disabled (attempt to start matching for kext %s).",
            getIdentifierCString());
        result = kOSKextReturnDisabled;
        goto finish;
    }

    if (sSafeBoot && !isLoadableInSafeBoot()) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag,
            "Kext %s is not loadable during safe boot; "
            "not sending personalities to the IOCatalogue.",
            getIdentifierCString());
        result = kOSKextReturnNotLoadable;
        goto finish;
    }

    if (!personalityNames || !personalityNames->getCount()) {
        personalitiesToSend = copyPersonalitiesArray();
    } else {
        kextPersonalities = OSDynamicCast(OSDictionary,
            getPropertyForHostArch(kIOKitPersonalitiesKey));
        if (!kextPersonalities || !kextPersonalities->getCount()) {
            // not an error
            goto finish;
        }
        personalitiesToSend = OSArray::withCapacity(0);
        if (!personalitiesToSend) {
            result = kOSKextReturnNoMemory;
            goto finish;
        }
        count = personalityNames->getCount();
        for (i = 0; i < count; i++) {
            OSString * name = OSDynamicCast(OSString,
                personalityNames->getObject(i));
            if (!name) {
                continue;
            }
            OSDictionary * personality = OSDynamicCast(OSDictionary,
                kextPersonalities->getObject(name));
            if (personality) {
                personalitiesToSend->setObject(personality);
            }
        }
    }
    if (personalitiesToSend) {
        unsigned numPersonalities = personalitiesToSend->getCount();
        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogLoadFlag,
            "Kext %s sending %d personalit%s to the IOCatalogue%s.",
            getIdentifierCString(),
            numPersonalities,
            numPersonalities > 1 ? "ies" : "y",
            startMatching ? " and starting matching" : " but not starting matching");
        gIOCatalogue->addDrivers(personalitiesToSend, startMatching);
    }
finish:
    if (personalitiesToSend) {
        personalitiesToSend->release();
    }
    return result;
}

/*********************************************************************
* xxx - We should allow removing the kext's declared personalities,
* xxx - even with other bundle identifiers.
*********************************************************************/
void
OSKext::removePersonalitiesFromCatalog(void)
{
    OSDictionary * personality = NULL;   // do not release

    personality = OSDictionary::withCapacity(1);
    if (!personality) {
        goto finish;
    }
    personality->setObject(kCFBundleIdentifierKey, getIdentifier());

    OSKextLog(this,
        kOSKextLogStepLevel |
        kOSKextLogLoadFlag,
        "Kext %s removing all personalities naming it from the IOCatalogue.",
        getIdentifierCString());

   /* Have the IOCatalog remove all personalities matching this kext's
    * bundle ID and trigger matching anew.
    */
    gIOCatalogue->removeDrivers(personality, /* startMatching */ true);

 finish:
    if (personality) personality->release();

    return;
}


#if PRAGMA_MARK
#pragma mark Logging
#endif
/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
/* static */
OSKextLogSpec
OSKext::setUserSpaceLogFilter(
    OSKextLogSpec   userLogFilter,
    bool            captureFlag)
{
    OSKextLogSpec result;

    IORecursiveLockLock(sKextInnerLock);

    result = sUserSpaceKextLogFilter;
    sUserSpaceKextLogFilter = userLogFilter;

   /* If the config flag itself is changing, log the state change
    * going both ways, before setting up the user-space log arrays,
    * so that this is only logged in the kernel.
    */
    if (sUserSpaceKextLogFilter != result) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogGeneralFlag,
            "User-space log flags changed from 0x%x to 0x%x.",
            result, sUserSpaceKextLogFilter);
    }

    if (userLogFilter && captureFlag &&
        !sUserSpaceLogSpecArray && !sUserSpaceLogMessageArray) {

        // xxx - do some measurements for a good initial capacity?
        sUserSpaceLogSpecArray = OSArray::withCapacity(0);
        sUserSpaceLogMessageArray = OSArray::withCapacity(0);
        
        if (!sUserSpaceLogSpecArray || !sUserSpaceLogMessageArray) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag,
                "Failed to allocate user-space log message arrays.");
            OSSafeReleaseNULL(sUserSpaceLogSpecArray);
            OSSafeReleaseNULL(sUserSpaceLogMessageArray);
        }
    }

    IORecursiveLockUnlock(sKextInnerLock);

    return result;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
/* static */
OSArray *
OSKext::clearUserSpaceLogFilter(void)
{
    OSArray        * result        = NULL;
    OSKextLogSpec   oldLogFilter;

    IORecursiveLockLock(sKextInnerLock);

    result = OSArray::withCapacity(2);
    if (result) {
        result->setObject(sUserSpaceLogSpecArray);
        result->setObject(sUserSpaceLogMessageArray);
    }
    OSSafeReleaseNULL(sUserSpaceLogSpecArray);
    OSSafeReleaseNULL(sUserSpaceLogMessageArray);

    oldLogFilter = sUserSpaceKextLogFilter;
    sUserSpaceKextLogFilter = kOSKextLogSilentFilter;

   /* If the config flag itself is changing, log the state change
    * going both ways, after tearing down the user-space log
    * arrays, so this is only logged within the kernel.
    */
    if (oldLogFilter != sUserSpaceKextLogFilter) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogGeneralFlag,
            "User-space log flags changed from 0x%x to 0x%x.",
            oldLogFilter, sUserSpaceKextLogFilter);
    }

    IORecursiveLockUnlock(sKextInnerLock);

    return result;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
/* static */
OSKextLogSpec
OSKext::getUserSpaceLogFilter(void)
{
    OSKextLogSpec result;

    IORecursiveLockLock(sKextInnerLock);
    result = sUserSpaceKextLogFilter;
    IORecursiveLockUnlock(sKextInnerLock);

    return result;
}

/*********************************************************************
* This function is called by OSMetaClass during kernel C++ setup.
* Be careful what you access here; assume only OSKext::initialize()
* has been called.
*
* Do not call any function that takes sKextLock here!
*********************************************************************/
#define VTRESET   "\033[0m"

#define VTBOLD    "\033[1m"
#define VTUNDER   "\033[4m"

#define VTRED     "\033[31m"
#define VTGREEN   "\033[32m"
#define VTYELLOW  "\033[33m"
#define VTBLUE    "\033[34m"
#define VTMAGENTA "\033[35m"
#define VTCYAN    "\033[36m"

inline const char * colorForFlags(OSKextLogSpec flags)
{
    OSKextLogSpec logLevel = flags & kOSKextLogLevelMask;

    switch (logLevel) {
    case kOSKextLogErrorLevel:
        return VTRED VTBOLD;
        break;
    case kOSKextLogWarningLevel:
        return VTRED;
        break;
    case kOSKextLogBasicLevel:
        return VTYELLOW VTUNDER;
        break;
    case kOSKextLogProgressLevel:
        return VTYELLOW;
        break;
    case kOSKextLogStepLevel:
        return VTGREEN;
        break;
    case kOSKextLogDetailLevel:
        return VTCYAN;
        break;
    case kOSKextLogDebugLevel:
        return VTMAGENTA;
        break;
    default:
        return "";  // white
        break;
    }
    return "";
}

inline bool logSpecMatch(
    OSKextLogSpec msgLogSpec,
    OSKextLogSpec logFilter)
{
    OSKextLogSpec filterKextGlobal  = logFilter & kOSKextLogKextOrGlobalMask;
    OSKextLogSpec filterLevel       = logFilter & kOSKextLogLevelMask;
    OSKextLogSpec filterFlags       = logFilter & kOSKextLogFlagsMask;

    OSKextLogSpec msgKextGlobal    = msgLogSpec & kOSKextLogKextOrGlobalMask;
    OSKextLogSpec msgLevel         = msgLogSpec & kOSKextLogLevelMask;
    OSKextLogSpec msgFlags         = msgLogSpec & kOSKextLogFlagsMask;

   /* Explicit messages always get logged.
    */
    if (msgLevel == kOSKextLogExplicitLevel) {
        return true;
    }

   /* Warnings and errors are logged regardless of the flags.
    */
    if (msgLevel <= kOSKextLogBasicLevel && (msgLevel <= filterLevel)) {
        return true;
    }

   /* A verbose message that isn't for a logging-enabled kext and isn't global
    * does *not* get logged.
    */
    if (!msgKextGlobal && !filterKextGlobal) {
        return false;
    }

   /* Warnings and errors are logged regardless of the flags.
    * All other messages must fit the flags and
    * have a level at or below the filter.
    *
    */
    if ((msgFlags & filterFlags) && (msgLevel <= filterLevel)) {
        return true;
    }
    return false;
}

extern "C" {

void
OSKextLog(
    OSKext         * aKext,
    OSKextLogSpec    msgLogSpec,
    const char     * format, ...)
{
    va_list argList;

    va_start(argList, format);
    OSKextVLog(aKext, msgLogSpec, format, argList);
    va_end(argList);
}

void
OSKextVLog(
    OSKext         * aKext,
    OSKextLogSpec    msgLogSpec,
    const char     * format,
    va_list    srcArgList)
{
    extern int       disableConsoleOutput;

    bool             logForKernel       = false;
    bool             logForUser         = false;
    va_list          argList;
    char             stackBuffer[120];
    uint32_t         length            = 0;
    char           * allocBuffer       = NULL;         // must kfree
    OSNumber       * logSpecNum        = NULL;         // must release
    OSString       * logString         = NULL;         // must release
    char           * buffer            = stackBuffer;  // do not free

    IORecursiveLockLock(sKextInnerLock);

   /* Set the kext/global bit in the message spec if we have no
    * kext or if the kext requests logging.
    */
    if (!aKext || aKext->flags.loggingEnabled) {
        msgLogSpec = msgLogSpec | kOSKextLogKextOrGlobalMask;
    }

    logForKernel = logSpecMatch(msgLogSpec, sKernelLogFilter);
    if (sUserSpaceLogSpecArray && sUserSpaceLogMessageArray) {
        logForUser = logSpecMatch(msgLogSpec, sUserSpaceKextLogFilter);
    }

    if (! (logForKernel || logForUser) ) {
        goto finish;
    }
    
   /* No goto from here until past va_end()!
    */    
    va_copy(argList, srcArgList);
    length = vsnprintf(stackBuffer, sizeof(stackBuffer), format, argList);
    va_end(argList);

    if (length + 1 >= sizeof(stackBuffer)) {
        allocBuffer = (char *)kalloc((length + 1) * sizeof(char));
        if (!allocBuffer) {
            goto finish;
        }

       /* No goto from here until past va_end()!
        */    
        va_copy(argList, srcArgList);
        vsnprintf(allocBuffer, length + 1, format, argList);
        va_end(argList);

        buffer = allocBuffer;
    }

   /* If user space wants the log message, queue it up.
    */
    if (logForUser && sUserSpaceLogSpecArray && sUserSpaceLogMessageArray) {
        logSpecNum = OSNumber::withNumber(msgLogSpec, 8 * sizeof(msgLogSpec));
        logString = OSString::withCString(buffer);
        if (logSpecNum && logString) {
            sUserSpaceLogSpecArray->setObject(logSpecNum);
            sUserSpaceLogMessageArray->setObject(logString);
        }
    }

   /* Always log messages from the kernel according to the kernel's
    * log flags.
    */
    if (logForKernel) {

       /* If we are in console mode and have a custom log filter,
        * colorize the log message.
        */
        if (!disableConsoleOutput && sBootArgLogFilterFound) {
            const char * color = "";  // do not free
            color = colorForFlags(msgLogSpec);
            printf("%s%s%s\n", colorForFlags(msgLogSpec),
                buffer, color[0] ? VTRESET : "");
        } else {
            printf("%s\n", buffer);
        }
    }

finish:
    if (allocBuffer) {
        kfree(allocBuffer, (length + 1) * sizeof(char));
    }
    OSSafeRelease(logString);
    OSSafeRelease(logSpecNum);
    IORecursiveLockUnlock(sKextInnerLock);
    return;
}

}; /* extern "C" */

#if PRAGMA_MARK
#pragma mark Backtrace Dump & kmod_get_info() support
#endif
/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::printKextsInBacktrace(
    vm_offset_t  * addr,
    unsigned int   cnt,
    int         (* printf_func)(const char *fmt, ...),
    bool           lockFlag)
{
    vm_offset_t      * kscan_addr = NULL;
    kmod_info_t      * k = NULL;
    kmod_reference_t * r = NULL;
    unsigned int       i;
    int                found_kmod = 0;

    if (lockFlag) {
        IORecursiveLockLock(sKextLock);
    }

    for (k = kmod; k; k = k->next) {
        if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)k)) == 0) {
            (*printf_func)("         kmod scan stopped due to missing "
                "kmod page: %p\n", k);
            break;
        }
        if (!k->address) {
            continue; // skip fake entries for built-in kernel components
        }
        for (i = 0, kscan_addr = addr; i < cnt; i++, kscan_addr++) {
            if ((*kscan_addr >= k->address) &&
                (*kscan_addr < (k->address + k->size))) {

                if (!found_kmod) {
                    (*printf_func)("      Kernel Extensions in backtrace "
                        "(with dependencies):\n");
                }
                found_kmod = 1;
                (*printf_func)("         %s(%s)@%p->%p\n",
                    k->name, k->version, k->address, k->address + k->size - 1);

                for (r = k->reference_list; r; r = r->next) {
                    kmod_info_t * rinfo;

                    if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)r)) == 0) {
                        (*printf_func)("            kmod dependency scan stopped "
                            "due to missing dependency page: %p\n", r);
                        break;
                    }

                    rinfo = r->info;

                    if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)rinfo)) == 0) {
                        (*printf_func)("            kmod dependency scan stopped "
                            "due to missing kmod page: %p\n", rinfo);
                        break;
                    }

                    if (!rinfo->address) {
                        continue; // skip fake entries for built-ins
                    }

                    (*printf_func)("            dependency: %s(%s)@%p\n",
                        rinfo->name, rinfo->version, rinfo->address);
                }

                break;  // only report this kmod for one backtrace address
            }
        }
    }

    if (lockFlag) {
        IORecursiveLockUnlock(sKextLock);
    }

    return;
}

/*******************************************************************************
* substitute() looks at an input string (a pointer within a larger buffer)
* for a match to a substring, and on match it writes the marker & substitution
* character to an output string, updating the scan (from) and
* output (to) indexes as appropriate.
*******************************************************************************/
static int substitute(
    const char * scan_string,
    char       * string_out,
    uint32_t   * to_index,
    uint32_t   * from_index,
    const char * substring,
    char         marker,
    char         substitution);

/* string_out must be at least KMOD_MAX_NAME bytes.
 */
static int
substitute(
    const char * scan_string,
    char       * string_out,
    uint32_t   * to_index,
    uint32_t   * from_index,
    const char * substring,
    char         marker,
    char         substitution)
{
    uint32_t substring_length = strnlen(substring, KMOD_MAX_NAME - 1);

   /* On a substring match, append the marker (if there is one) and then
    * the substitution character, updating the output (to) index accordingly.
    * Then update the input (from) length by the length of the substring
    * that got replaced.
    */
    if (!strncmp(scan_string, substring, substring_length)) {
        if (marker) {
            string_out[(*to_index)++] = marker;
        }
        string_out[(*to_index)++] = substitution;
        (*from_index) += substring_length;
        return 1;
    }
    return 0;
}

/*******************************************************************************
* compactIdentifier() takes a CFBundleIdentifier in a buffer of at least
* KMOD_MAX_NAME characters and performs various substitutions of common
* prefixes & substrings as defined by tables in kext_panic_report.h.
*******************************************************************************/
static void compactIdentifier(
    const char * identifier,
    char       * identifier_out,
    char      ** identifier_out_end);

static void
compactIdentifier(
    const char * identifier,
    char       * identifier_out,
    char      ** identifier_out_end)
{
    uint32_t       from_index, to_index;
    uint32_t       scan_from_index = 0;
    uint32_t       scan_to_index   = 0;
    subs_entry_t * subs_entry    = NULL;
    int            did_sub       = 0;

    from_index = to_index = 0;
    identifier_out[0] = '\0';

   /* Replace certain identifier prefixes with shorter @+character sequences.
    * Check the return value of substitute() so we only replace the prefix.
    */
    for (subs_entry = &kext_identifier_prefix_subs[0];
         subs_entry->substring && !did_sub;
         subs_entry++) {

        did_sub = substitute(identifier, identifier_out,
            &scan_to_index, &scan_from_index,
            subs_entry->substring, /* marker */ '\0', subs_entry->substitute);
    }
    did_sub = 0;

   /* Now scan through the identifier looking for the common substrings
    * and replacing them with shorter !+character sequences via substitute().
    */
    for (/* see above */;
         scan_from_index < KMOD_MAX_NAME - 1 && identifier[scan_from_index];
         /* see loop */) {
         
        const char   * scan_string = &identifier[scan_from_index];

        did_sub = 0;

        if (scan_from_index) {
            for (subs_entry = &kext_identifier_substring_subs[0];
                 subs_entry->substring && !did_sub;
                 subs_entry++) {

                did_sub = substitute(scan_string, identifier_out,
                    &scan_to_index, &scan_from_index,
                    subs_entry->substring, '!', subs_entry->substitute);
            }
        }

       /* If we didn't substitute, copy the input character to the output.
        */
        if (!did_sub) {
            identifier_out[scan_to_index++] = identifier[scan_from_index++];
        }
    }
    
    identifier_out[scan_to_index] = '\0';
    if (identifier_out_end) {
        *identifier_out_end = &identifier_out[scan_to_index];
    }
    
    return;
}

/*******************************************************************************
* assemble_identifier_and_version() adds to a string buffer a compacted
* bundle identifier followed by a version string.
*******************************************************************************/

/* identPlusVers must be at least 2*KMOD_MAX_NAME in length.
 */
static int assemble_identifier_and_version(
    kmod_info_t * kmod_info, 
    char        * identPlusVers);
static int
assemble_identifier_and_version(
    kmod_info_t * kmod_info, 
    char        * identPlusVers)
{
    int result = 0;

    compactIdentifier(kmod_info->name, identPlusVers, NULL);
    result = strnlen(identPlusVers, KMOD_MAX_NAME - 1);
    identPlusVers[result++] = '\t';  // increment for real char
    identPlusVers[result] = '\0';    // don't increment for nul char
    result = strlcat(identPlusVers, kmod_info->version, KMOD_MAX_NAME);

    return result;
}

/*******************************************************************************
*******************************************************************************/
#define LAST_LOADED " - last loaded "
#define LAST_LOADED_TS_WIDTH  (16)

/* static */
uint32_t
OSKext::saveLoadedKextPanicListTyped(
    const char * prefix,
    int          invertFlag,
    int          libsFlag,
    char       * paniclist,
    uint32_t     list_size,
    uint32_t   * list_length_ptr)
{
    uint32_t      result = 0;
    int           error  = 0;
    unsigned int  count, i;

    count = sLoadedKexts->getCount();
    if (!count) {
        goto finish;
    }

    i = count - 1;
    do {
        OSKext      * theKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        kmod_info_t * kmod_info = theKext->kmod_info;
        int           match;
        char          identPlusVers[2*KMOD_MAX_NAME];
        uint32_t      identPlusVersLength;
        char          timestampBuffer[17]; // enough for a uint64_t

       /* Skip all built-in kexts.
        */
        if (theKext->isKernelComponent()) {
            continue;
        }

       /* Filter for kmod name (bundle identifier).
        */
        match = !strncmp(kmod_info->name, prefix, strnlen(prefix, KMOD_MAX_NAME));
        if ((match && invertFlag) || (!match && !invertFlag)) {
            continue;
        }

       /* Filter for libraries (kexts that have a compatible version).
        */
        if ((libsFlag == 0 && theKext->getCompatibleVersion() > 1) ||
            (libsFlag == 1 && theKext->getCompatibleVersion() < 1)) {

            continue;
        }

        if (!kmod_info ||
            !pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)kmod_info))) {

            printf("kext scan stopped due to missing kmod_info page: %p\n",
                kmod_info);
            error = 1;
            goto finish;
        }

        identPlusVersLength = assemble_identifier_and_version(kmod_info,
            identPlusVers);
        if (!identPlusVersLength) {
            printf("error saving loaded kext info\n");
            goto finish;
        }

       /* We're going to note the last-loaded kext in the list.
        */
        if (i + 1 == count) {
            snprintf(timestampBuffer, sizeof(timestampBuffer), "%llu",
                AbsoluteTime_to_scalar(&last_loaded_timestamp));
            identPlusVersLength += sizeof(LAST_LOADED) - 1 +
                strnlen(timestampBuffer, sizeof(timestampBuffer));
        }

       /* Adding 1 for the newline.
        */
        if (*list_length_ptr + identPlusVersLength + 1 >= list_size) {
            goto finish;
        }
        
        *list_length_ptr = strlcat(paniclist, identPlusVers, list_size);
        if (i + 1 == count) {
            *list_length_ptr = strlcat(paniclist, LAST_LOADED, list_size);
            *list_length_ptr = strlcat(paniclist, timestampBuffer, list_size);
        }
        *list_length_ptr = strlcat(paniclist, "\n", list_size);
        
    } while (i--);
    
finish:
    if (!error) {
        if (*list_length_ptr + 1 <= list_size) {
            result = list_size - (*list_length_ptr + 1);
        }
    }

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::saveLoadedKextPanicList(void)
{
    char     * newlist        = NULL;
    uint32_t   newlist_size   = 0;
    uint32_t   newlist_length = 0;

    IORecursiveLockLock(sKextLock);

    newlist_length = 0;
    newlist_size = KEXT_PANICLIST_SIZE;
    newlist = (char *)kalloc(newlist_size);
    
    if (!newlist) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
            "Couldn't allocate kext panic log buffer.");
        goto finish;
    }
    
    newlist[0] = '\0';

    // non-"com.apple." kexts
    if (!OSKext::saveLoadedKextPanicListTyped("com.apple.", /* invert? */ 1,
        /* libs? */ -1, newlist, newlist_size, &newlist_length)) {
        
        goto finish;
    }
    // "com.apple." nonlibrary kexts
    if (!OSKext::saveLoadedKextPanicListTyped("com.apple.", /* invert? */ 0,
        /* libs? */ 0, newlist, newlist_size, &newlist_length)) {
        
        goto finish;
    }
    // "com.apple." library kexts
    if (!OSKext::saveLoadedKextPanicListTyped("com.apple.", /* invert? */ 0,
        /* libs? */ 1, newlist, newlist_size, &newlist_length)) {
        
        goto finish;
    }

    if (loaded_kext_paniclist) {
        kfree(loaded_kext_paniclist, loaded_kext_paniclist_size);
    }
    loaded_kext_paniclist = newlist;
    loaded_kext_paniclist_size = newlist_size;
    loaded_kext_paniclist_length = newlist_length;

finish:
    IORecursiveLockUnlock(sKextLock);
    return;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::saveUnloadedKextPanicList(OSKext * aKext)
{
    char     * newlist        = NULL;
    uint32_t   newlist_size   = 0;
    uint32_t   newlist_length = 0;
    char       identPlusVers[2*KMOD_MAX_NAME];
    uint32_t   identPlusVersLength;

    if (!aKext->kmod_info) {
        return;  // do not goto finish here b/c of lock
    }

    IORecursiveLockLock(sKextLock);

    clock_get_uptime(&last_unloaded_timestamp);
    last_unloaded_address = (void *)aKext->kmod_info->address;
    last_unloaded_size = aKext->kmod_info->size;


    identPlusVersLength = assemble_identifier_and_version(aKext->kmod_info,
        identPlusVers);
    if (!identPlusVersLength) {
        printf("error saving unloaded kext info\n");
        goto finish;
    }

    newlist_length = identPlusVersLength;
    newlist_size = newlist_length + 1;
    newlist = (char *)kalloc(newlist_size);
    
    if (!newlist) {
        printf("couldn't allocate kext panic log buffer\n");
        goto finish;
    }
    
    newlist[0] = '\0';

    strlcpy(newlist, identPlusVers, newlist_size);

    if (unloaded_kext_paniclist) {
        kfree(unloaded_kext_paniclist, unloaded_kext_paniclist_size);
    }
    unloaded_kext_paniclist = newlist;
    unloaded_kext_paniclist_size = newlist_size;
    unloaded_kext_paniclist_length = newlist_length;

finish:
    IORecursiveLockUnlock(sKextLock);
    return;
}

/*********************************************************************
*********************************************************************/
#if __LP64__
#define __kLoadSizeEscape  "0x%lld"
#else
#define __kLoadSizeEscape  "0x%ld"
#endif /* __LP64__ */

/* static */
void
OSKext::printKextPanicLists(int (*printf_func)(const char *fmt, ...))
{
    printf_func("unloaded kexts:\n");
    if (unloaded_kext_paniclist &&
        pmap_find_phys(kernel_pmap, (addr64_t) (uintptr_t) unloaded_kext_paniclist) &&
        unloaded_kext_paniclist[0]) {

        printf_func(
            "%.*s (addr %p, size " __kLoadSizeEscape ") - last unloaded %llu\n",
            unloaded_kext_paniclist_length, unloaded_kext_paniclist,
            last_unloaded_address, last_unloaded_size,
            AbsoluteTime_to_scalar(&last_unloaded_timestamp));
    } else {
        printf_func("(none)\n");
    }
    printf_func("loaded kexts:\n");
    if (loaded_kext_paniclist &&
        pmap_find_phys(kernel_pmap, (addr64_t) (uintptr_t) loaded_kext_paniclist) &&
        loaded_kext_paniclist[0]) {

        printf_func("%.*s", loaded_kext_paniclist_length, loaded_kext_paniclist);
    } else {
        printf_func("(none)\n");
    }
    return;
}

/*********************************************************************
*********************************************************************/
#if __ppc__ || __i386__
/* static */
kern_return_t
OSKext::getKmodInfo(
    kmod_info_array_t      * kmodList,
    mach_msg_type_number_t * kmodCount)
{
    kern_return_t result = KERN_FAILURE;
    vm_offset_t data;
    kmod_info_t * k, * kmod_info_scan_ptr;
    kmod_reference_t * r, * ref_scan_ptr;
    int ref_count;
    unsigned size = 0;

    *kmodList = (kmod_info_t *)0;
    *kmodCount = 0;

    IORecursiveLockLock(sKextLock);

    k = kmod;
    while (k) {
        size += sizeof(kmod_info_t);
        r = k->reference_list;
        while (r) {
            size +=sizeof(kmod_reference_t);
            r = r->next;
        }
        k = k->next;
    }
    if (!size) {
        result = KERN_SUCCESS;
        goto finish;
    }

    result = kmem_alloc(kernel_map, &data, size);
    if (result != KERN_SUCCESS) {
        goto finish;
    }

   /* Copy each kmod_info struct sequentially into the data buffer.
    * Set each struct's nonzero 'next' pointer back to itself as a sentinel;
    * the kernel space address is used to match refs, and a zero 'next' flags
    * the end of kmod_infos in the data buffer and the beginning of references.
    */
    k = kmod;
    kmod_info_scan_ptr = (kmod_info_t *)data;
    while (k) {
        *kmod_info_scan_ptr = *k;
        if (k->next) {
            kmod_info_scan_ptr->next = k;
        }
        kmod_info_scan_ptr++;
        k = k->next;
    }

   /* Now add references after the kmod_info structs in the same buffer.
    * Update each kmod_info with the ref_count so we can associate
    * references with kmod_info structs.
    */
    k = kmod;
    ref_scan_ptr = (kmod_reference_t *)kmod_info_scan_ptr;
    kmod_info_scan_ptr = (kmod_info_t *)data;
    while (k) {
        r = k->reference_list;
        ref_count = 0;
        while (r) {
           /* Note the last kmod_info in the data buffer has its next == 0.
            * Since there can only be one like that, 
            * this case is handled by the caller.
            */
            *ref_scan_ptr = *r;
            ref_scan_ptr++;
            r = r->next;
            ref_count++;
        }
       /* Stuff the # of refs into the 'reference_list' field of the kmod_info
        * struct for the client to interpret.
        */
        kmod_info_scan_ptr->reference_list = (kmod_reference_t *)(long)ref_count;
        kmod_info_scan_ptr++;
        k = k->next;
    }
    
    result = vm_map_copyin(kernel_map, data, size, TRUE, (vm_map_copy_t *)kmodList);
    if (result != KERN_SUCCESS) {
        goto finish;
    }

    *kmodCount = size;
    result = KERN_SUCCESS;

finish:
    IORecursiveLockUnlock(sKextLock);

    if (result != KERN_SUCCESS && data) {
        kmem_free(kernel_map, data, size);
        *kmodList = (kmod_info_t *)0;
        *kmodCount = 0;
    }
    return result;
}
#endif /* __ppc__ || __i386__ */
#if PRAGMA_MARK
#pragma mark MAC Framework Support
#endif
/*********************************************************************
*********************************************************************/
#if CONFIG_MACF_KEXT
/* MAC Framework support */

/* 
 * define IOC_DEBUG to display run-time debugging information
 * #define IOC_DEBUG 1
 */

#ifdef IOC_DEBUG
#define DPRINTF(x)    printf x
#else
#define IOC_DEBUG
#define DPRINTF(x)
#endif

/*********************************************************************
*********************************************************************/
static bool
MACFObjectIsPrimitiveType(OSObject * obj)
{
    const OSMetaClass * typeID = NULL;  // do not release

    typeID = OSTypeIDInst(obj);
    if (typeID == OSTypeID(OSString) || typeID == OSTypeID(OSNumber) ||
        typeID == OSTypeID(OSBoolean) || typeID == OSTypeID(OSData)) {

        return true;
    }
    return false;
}

/*********************************************************************
*********************************************************************/
static int
MACFLengthForObject(OSObject * obj)
{
    const OSMetaClass * typeID = NULL;  // do not release
    int len;

    typeID = OSTypeIDInst(obj);
    if (typeID == OSTypeID(OSString)) {
        OSString * stringObj = OSDynamicCast(OSString, obj);
        len = stringObj->getLength() + 1;
    } else if (typeID == OSTypeID(OSNumber)) {
        len = sizeof("4294967295");    /* UINT32_MAX */
    } else if (typeID == OSTypeID(OSBoolean)) {
        OSBoolean * boolObj = OSDynamicCast(OSBoolean, obj);
        len = boolObj->isTrue() ? sizeof("true") : sizeof("false");
    } else if (typeID == OSTypeID(OSData)) {
        OSData * dataObj = OSDynamicCast(OSData, obj);
        len = dataObj->getLength();
    } else {
        len = 0;
    }
    return len;
}

/*********************************************************************
*********************************************************************/
static void
MACFInitElementFromObject(
    struct mac_module_data_element * element,
    OSObject                       * value)
{
    const OSMetaClass * typeID = NULL;  // do not release

    typeID = OSTypeIDInst(value);
    if (typeID == OSTypeID(OSString)) {
        OSString * stringObj = OSDynamicCast(OSString, value);
        element->value_type = MAC_DATA_TYPE_PRIMITIVE;
        element->value_size = stringObj->getLength() + 1;
        DPRINTF(("osdict: string %s size %d\n", 
            stringObj->getCStringNoCopy(), element->value_size));
        memcpy(element->value, stringObj->getCStringNoCopy(),
            element->value_size);
    } else if (typeID == OSTypeID(OSNumber)) {
        OSNumber * numberObj = OSDynamicCast(OSNumber, value);
        element->value_type = MAC_DATA_TYPE_PRIMITIVE;
        element->value_size = sprintf(element->value, "%u",
            numberObj->unsigned32BitValue()) + 1;
    } else if (typeID == OSTypeID(OSBoolean)) {
        OSBoolean * boolObj = OSDynamicCast(OSBoolean, value);
        element->value_type = MAC_DATA_TYPE_PRIMITIVE;
        if (boolObj->isTrue()) {
            strcpy(element->value, "true");
            element->value_size = 5;
        } else {
            strcpy(element->value, "false");
            element->value_size = 6;
        }
    } else if (typeID == OSTypeID(OSData)) {
        OSData * dataObj = OSDynamicCast(OSData, value);
        element->value_type = MAC_DATA_TYPE_PRIMITIVE;
        element->value_size = dataObj->getLength();
        DPRINTF(("osdict: data size %d\n", dataObj->getLength()));
        memcpy(element->value, dataObj->getBytesNoCopy(),
            element->value_size);
    }
    return;
}

/*********************************************************************
* This function takes an OSDictionary and returns a struct mac_module_data
* list.
*********************************************************************/
static struct mac_module_data *
MACFEncodeOSDictionary(OSDictionary * dict)
{
    struct mac_module_data         * result      = NULL;  // do not free
    const OSMetaClass              * typeID      = NULL;  // do not release
    OSString                       * key         = NULL;  // do not release
    OSCollectionIterator           * keyIterator = NULL;  // must release
    struct mac_module_data_element * element     = NULL;  // do not free
    unsigned int                     strtabsize  = 0;
    unsigned int                     listtabsize = 0;
    unsigned int                     dicttabsize = 0;
    unsigned int                     nkeys       = 0;
    unsigned int                     datalen     = 0;
    char                           * strtab      = NULL;  // do not free
    char                           * listtab     = NULL;  // do not free
    char                           * dicttab     = NULL;  // do not free
    vm_offset_t                      data_addr   = 0;
    
    keyIterator = OSCollectionIterator::withCollection(dict);
    if (!keyIterator) {
        goto finish;
    }
    
    /* Iterate over OSModuleData to figure out total size */
    while ( (key = OSDynamicCast(OSString, keyIterator->getNextObject())) ) {
        
        // Get the key's value and determine its type
        OSObject * value = dict->getObject(key);
        if (!value) {
            continue;
        }
        
        typeID = OSTypeIDInst(value);
        if (MACFObjectIsPrimitiveType(value)) {
            strtabsize += MACFLengthForObject(value);
        }
        else if (typeID == OSTypeID(OSArray)) {
            unsigned int k, cnt, nents;
            OSArray * arrayObj = OSDynamicCast(OSArray, value);
            
            nents = 0;
            cnt = arrayObj->getCount();
            for (k = 0; k < cnt; k++) {
                value = arrayObj->getObject(k);
                typeID = OSTypeIDInst(value);
                if (MACFObjectIsPrimitiveType(value)) {
                    listtabsize += MACFLengthForObject(value);
                    nents++;
                }
                else if (typeID == OSTypeID(OSDictionary)) {
                    unsigned int           dents = 0;
                    OSDictionary         * dictObj      = NULL;  // do not release
                    OSString             * dictkey      = NULL;  // do not release
                    OSCollectionIterator * dictIterator = NULL;  // must release
                    
                    dictObj = OSDynamicCast(OSDictionary, value);
                    dictIterator = OSCollectionIterator::withCollection(dictObj);
                    if (!dictIterator) {
                        goto finish;
                    }
                    while ((dictkey = OSDynamicCast(OSString,
                        dictIterator->getNextObject()))) {

                        OSObject * dictvalue = NULL;  // do not release
                        
                        dictvalue = dictObj->getObject(dictkey);
                        if (!dictvalue) {
                            continue;
                        }
                        if (MACFObjectIsPrimitiveType(dictvalue)) {
                            strtabsize += MACFLengthForObject(dictvalue);
                        } else {
                            continue; /* Only handle primitive types here. */
                        }
                       /*
                        * Allow for the "arraynnn/" prefix in the key length.
                        */
                        strtabsize += dictkey->getLength() + 1;
                        dents++;
                    }
                    dictIterator->release();
                    if (dents-- > 0) {
                        dicttabsize += sizeof(struct mac_module_data_list) +
                        dents * sizeof(struct mac_module_data_element);
                        nents++;
                    }
                }
                else {
                    continue; /* Skip everything else. */
                }
            }
            if (nents == 0) {
                continue;
            }
            listtabsize += sizeof(struct mac_module_data_list) +
                (nents - 1) * sizeof(struct mac_module_data_element);
        } else {
            continue; /* skip anything else */
        }
        strtabsize += key->getLength() + 1;
        nkeys++;
    }
    if (nkeys == 0) {
        goto finish;
    }
    
   /*
    * Allocate and fill in the module data structures.
    */
    datalen = sizeof(struct mac_module_data) +
        sizeof(mac_module_data_element) * (nkeys - 1) +
    strtabsize + listtabsize + dicttabsize;
    DPRINTF(("osdict: datalen %d strtabsize %d listtabsize %d dicttabsize %d\n", 
        datalen, strtabsize, listtabsize, dicttabsize));
    if (kmem_alloc(kernel_map, &data_addr, datalen) != KERN_SUCCESS) {
        goto finish;
    }
    result = (mac_module_data *)data_addr;
    result->base_addr = data_addr;
    result->size = datalen;
    result->count = nkeys;
    strtab = (char *)&result->data[nkeys];
    listtab = strtab + strtabsize;
    dicttab = listtab + listtabsize;
    DPRINTF(("osdict: data_addr %p strtab %p listtab %p dicttab %p end %p\n", 
        data_addr, strtab, listtab, dicttab, data_addr + datalen));
    
    keyIterator->reset();
    nkeys = 0;
    element = &result->data[0];
    DPRINTF(("osdict: element %p\n", element));
    while ( (key = OSDynamicCast(OSString, keyIterator->getNextObject())) ) {
        
        // Get the key's value and determine its type
        OSObject * value = dict->getObject(key);
        if (!value) {
            continue;
        }
        
        /* Store key */
        DPRINTF(("osdict: element @%p\n", element));
        element->key = strtab;
        element->key_size = key->getLength() + 1;
        DPRINTF(("osdict: key %s size %d @%p\n", key->getCStringNoCopy(),
            element->key_size, strtab));
        memcpy(element->key, key->getCStringNoCopy(), element->key_size);
        
        typeID = OSTypeIDInst(value);
        if (MACFObjectIsPrimitiveType(value)) {
            /* Store value */
            element->value = element->key + element->key_size;
            DPRINTF(("osdict: primitive element value %p\n", element->value));
            MACFInitElementFromObject(element, value);
            strtab += element->key_size + element->value_size;
            DPRINTF(("osdict: new strtab %p\n", strtab));
        } else if (typeID == OSTypeID(OSArray)) {
            unsigned int k, cnt, nents;
            char *astrtab;
            struct mac_module_data_list *arrayhd;
            struct mac_module_data_element *ele;
            OSArray *arrayObj = OSDynamicCast(OSArray, value);
            
            element->value = listtab;
            DPRINTF(("osdict: array element value %p\n", element->value));
            element->value_type = MAC_DATA_TYPE_ARRAY;
            arrayhd = (struct mac_module_data_list *)element->value;
            arrayhd->type = 0;
            DPRINTF(("osdict: arrayhd %p\n", arrayhd));
            nents = 0;
            astrtab = strtab + element->key_size;
            ele = &(arrayhd->list[0]);
            cnt = arrayObj->getCount();
            for (k = 0; k < cnt; k++) {
                value = arrayObj->getObject(k);
                DPRINTF(("osdict: array ele %d @%p\n", nents, ele));
                ele->key = NULL;
                ele->key_size = 0;
                typeID = OSTypeIDInst(value);
                if (MACFObjectIsPrimitiveType(value)) {
                    if (arrayhd->type != 0 &&
                        arrayhd->type != MAC_DATA_TYPE_PRIMITIVE) {

                        continue;
                    }
                    arrayhd->type = MAC_DATA_TYPE_PRIMITIVE;
                    ele->value = astrtab;
                    MACFInitElementFromObject(ele, value);
                    astrtab += ele->value_size;
                    DPRINTF(("osdict: array new astrtab %p\n", astrtab));
                } else if (typeID == OSTypeID(OSDictionary)) {
                    unsigned int                     dents;
                    char                           * dstrtab      = NULL;  // do not free
                    OSDictionary                   * dictObj      = NULL;  // do not release
                    OSString                       * dictkey      = NULL;  // do not release
                    OSCollectionIterator           * dictIterator = NULL;  // must release
                    struct mac_module_data_list    * dicthd       = NULL;  // do not free
                    struct mac_module_data_element * dele         = NULL;  // do not free
                    
                    if (arrayhd->type != 0 &&
                        arrayhd->type != MAC_DATA_TYPE_DICT) {

                        continue;
                    }
                    dictObj = OSDynamicCast(OSDictionary, value);
                    dictIterator = OSCollectionIterator::withCollection(dictObj);
                    if (!dictIterator) {
                        goto finish;
                    }
                    DPRINTF(("osdict: dict\n"));
                    ele->value = dicttab;
                    ele->value_type = MAC_DATA_TYPE_DICT;
                    dicthd = (struct mac_module_data_list *)ele->value;
                    DPRINTF(("osdict: dicthd %p\n", dicthd));
                    dstrtab = astrtab;
                    dents = 0;
                    while ((dictkey = OSDynamicCast(OSString,
                        dictIterator->getNextObject()))) {

                        OSObject * dictvalue = NULL;  // do not release
                        
                        dictvalue = dictObj->getObject(dictkey);
                        if (!dictvalue) {
                            continue;
                        }
                        dele = &(dicthd->list[dents]);
                        DPRINTF(("osdict: dict ele %d @%p\n", dents, dele));
                        if (MACFObjectIsPrimitiveType(dictvalue)) {
                            dele->key = dstrtab;
                            dele->key_size = dictkey->getLength() + 1;
                            DPRINTF(("osdict: dictkey %s size %d @%p\n",
                                dictkey->getCStringNoCopy(), dictkey->getLength(), dstrtab));
                            memcpy(dele->key, dictkey->getCStringNoCopy(),
                                dele->key_size);
                            dele->value = dele->key + dele->key_size;
                            MACFInitElementFromObject(dele, dictvalue);
                            dstrtab += dele->key_size + dele->value_size;
                            DPRINTF(("osdict: dict new dstrtab %p\n", dstrtab));
                        } else {
                            continue;    /* Only handle primitive types here. */
                        }
                        dents++;
                    }
                    dictIterator->release();
                    if (dents == 0) {
                        continue;
                    }
                    arrayhd->type = MAC_DATA_TYPE_DICT;
                    ele->value_size = sizeof(struct mac_module_data_list) +
                        (dents - 1) * sizeof(struct mac_module_data_element);
                    DPRINTF(("osdict: dict ele size %d ents %d\n", ele->value_size, dents));
                    dicttab += ele->value_size;
                    DPRINTF(("osdict: new dicttab %p\n", dicttab));
                    dicthd->count = dents;
                    astrtab = dstrtab;
                } else {
                    continue;        /* Skip everything else. */
                }
                nents++;
                ele++;
            }
            if (nents == 0) {
                continue;
            }
            element->value_size = sizeof(struct mac_module_data_list) +
                (nents - 1) * sizeof(struct mac_module_data_element);
            listtab += element->value_size;
            DPRINTF(("osdict: new listtab %p\n", listtab));
            arrayhd->count = nents;
            strtab = astrtab;
            DPRINTF(("osdict: new strtab %p\n", strtab));
        } else {
            continue;        /* skip anything else */
        }
        element++;
    }
    DPRINTF(("result list @%p, key %p value %p\n",
        result, result->data[0].key, result->data[0].value));
finish:
    if (keyIterator) keyIterator->release();
    return result;
}

/*********************************************************************
* This function takes a plist and looks for an OSModuleData dictionary.
* If it is found, an encoded copy is returned. The value must be
* kmem_free()'d.
*********************************************************************/
static void *
MACFCopyModuleDataForKext(
    OSKext                 * theKext,
    mach_msg_type_number_t * datalen)

{
    struct mac_module_data * result         = NULL;
    OSDictionary           * kextModuleData = NULL;  // do not release
    vm_map_copy_t            copy           = 0;
    
    kextModuleData = OSDynamicCast(OSDictionary,
        theKext->getPropertyForHostArch("OSModuleData"));
    if (!kextModuleData) {
        goto finish;
    }
    
    result = MACFEncodeOSDictionary(kextModuleData);
    if (!result) {
        goto finish;
    }
    *datalen = module_data->size;

finish:
    return (void *)result;
}
#endif /* CONFIG_MACF_KEXT */
