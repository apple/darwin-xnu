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
#include <string.h>
#include <kern/clock.h>
#include <kern/host.h>
#include <kern/kext_alloc.h>
#include <firehose/tracepoint_private.h>
#include <firehose/chunk_private.h>
#include <os/firehose_buffer_private.h>
#include <vm/vm_kern.h>
#include <kextd/kextd_mach.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/kext_panic_report.h>
#include <libkern/kext_request_keys.h>
#include <libkern/mkext.h>
#include <libkern/prelink.h>
#include <libkern/version.h>
#include <libkern/zlib.h>
#include <mach/host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <uuid/uuid.h>
// 04/18/11 - gab: <rdar://problem/9236163>
#include <sys/random.h>

#include <sys/pgo.h>

#if CONFIG_MACF
#include <sys/kauth.h>
#include <security/mac_framework.h>
#endif
};

#include <libkern/OSKextLibPrivate.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSLib.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>

#include <IOKit/IOStatisticsPrivate.h>
#include <IOKit/IOBSD.h>

#include <san/kasan.h>

#if PRAGMA_MARK
#pragma mark External & Internal Function Protos
#endif
/*********************************************************************
*********************************************************************/
extern "C" {
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
static bool _OSKextInPrelinkRebuildWindow(void);
static bool _OSKextInUnloadedPrelinkedKexts(const OSSymbol * theBundleID);
    
// We really should add containsObject() & containsCString to OSCollection & subclasses.
// So few pad slots, though....
static bool _OSArrayContainsCString(OSArray * array, const char * cString);

#if CONFIG_KEC_FIPS
static void * GetAppleTEXTHashForKext(OSKext * theKext, OSDictionary *theInfoDict);
#endif // CONFIG_KEC_FIPS

/* Prelinked arm kexts do not have VM entries because the method we use to
 * fake an entry (see libsa/bootstrap.cpp:readPrelinkedExtensions()) does
 * not work on ARM.  To get around that, we must free prelinked kext
 * executables with ml_static_mfree() instead of kext_free().
 */
#if __i386__ || __x86_64__
#define VM_MAPPED_KEXTS 1
#define KASLR_KEXT_DEBUG 0
#define KASLR_IOREG_DEBUG 0
#elif __arm__ || __arm64__
#define VM_MAPPED_KEXTS 0
#define KASLR_KEXT_DEBUG 0
#else
#error Unsupported architecture
#endif

#if PRAGMA_MARK
#pragma mark Constants & Macros
#endif
/*********************************************************************
* Constants & Macros
*********************************************************************/

/* Use this number to create containers.
 */
#define kOSKextTypicalLoadCount      (150)

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

#define REBUILD_MAX_TIME (60 * 5) // 5 minutes
#define MINIMUM_WAKEUP_SECONDS (30)

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

#define OS_LOG_HDR_VERSION  1
#define NUM_OS_LOG_SECTIONS 2

#define OS_LOG_SECT_IDX     0
#define CSTRING_SECT_IDX    1

#if PRAGMA_MARK
#pragma mark Typedefs
#endif
/*********************************************************************
* Typedefs
*********************************************************************/

/*********************************************************************
* osLogDataHeaderRef describes the header information of an OSData
* object that is returned when querying for kOSBundleLogStringsKey.
* We currently return information regarding 2 sections - os_log and
* cstring. In the case that the os_log section doesn't exist, we just
* return an offset and length of 0 for that section.
*********************************************************************/
typedef struct osLogDataHeader {
    uint32_t version;
    uint32_t sect_count;
    struct {
         uint32_t sect_offset;
         uint32_t sect_size;
    } sections[0];
} osLogDataHeaderRef;

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
static  bool                sKeepSymbols               = false;

/*********************************************************************
* sKextLock is the principal lock for OSKext, and guards all static
* and global variables not owned by other locks (declared further
* below). It must be taken by any entry-point method or function,
* including internal functions called on scheduled threads.
*
* sKextLock and sKextInnerLock are recursive due to multiple functions
* that are called both externally and internally. The other locks are
* nonrecursive.
*
* Which locks are taken depends on what they protect, but if more than
* one must be taken, they must always be locked in this order
* (and unlocked in reverse order) to prevent deadlocks:
*
*    1. sKextLock
*    2. sKextInnerLock
*    3. sKextSummariesLock
*    4. sKextLoggingLock
*/
static IORecursiveLock    * sKextLock                  = NULL;

static OSDictionary       * sKextsByID                 = NULL;
static OSDictionary       * sExcludeListByID           = NULL;
static OSArray            * sLoadedKexts               = NULL;
static OSArray            * sUnloadedPrelinkedKexts    = NULL;

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

#if NO_KEXTD
static bool                 sKernelRequestsEnabled     = false;
#else
static bool                 sKernelRequestsEnabled     = true;
#endif
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
    /* address         */ 0,
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


static char     * loaded_kext_paniclist         = NULL;
static uint32_t   loaded_kext_paniclist_size    = 0;
    
AbsoluteTime      last_loaded_timestamp;
static char       last_loaded_str_buf[2*KMOD_MAX_NAME];
static u_long     last_loaded_strlen            = 0;
static void     * last_loaded_address           = NULL;
static u_long     last_loaded_size              = 0;

AbsoluteTime      last_unloaded_timestamp;
static char       last_unloaded_str_buf[2*KMOD_MAX_NAME];
static u_long     last_unloaded_strlen          = 0;
static void     * last_unloaded_address         = NULL;
static u_long     last_unloaded_size            = 0;

/*********************************************************************
* sKextInnerLock protects against cross-calls with IOService and
* IOCatalogue, and owns the variables declared immediately below.
*
* Note that sConsiderUnloadsExecuted above belongs to sKextLock!
*
* When both sKextLock and sKextInnerLock need to be taken,
* always lock sKextLock first and unlock it second. Never take both
* locks in an entry point to OSKext; if you need to do so, you must
* spawn an independent thread to avoid potential deadlocks for threads
* calling into OSKext.
**********/
static IORecursiveLock *    sKextInnerLock             = NULL;

static bool                 sAutounloadEnabled         = true;
static bool                 sConsiderUnloadsCalled     = false;
static bool                 sConsiderUnloadsPending    = false;

static unsigned int         sConsiderUnloadDelay       = 60;     // seconds
static thread_call_t        sUnloadCallout             = 0;
static thread_call_t        sDestroyLinkContextThread  = 0;      // one-shot, one-at-a-time thread
static bool                 sSystemSleep               = false;  // true when system going to sleep
static AbsoluteTime         sLastWakeTime;                       // last time we woke up   

/*********************************************************************
* Backtraces can be printed at various times so we need a tight lock
* on data used for that. sKextSummariesLock protects the variables
* declared immediately below.
*
* gLoadedKextSummaries is accessed by other modules, but only during
* a panic so the lock isn't needed then.
*
* gLoadedKextSummaries has the "used" attribute in order to ensure
* that it remains visible even when we are performing extremely
* aggressive optimizations, as it is needed to allow the debugger
* to automatically parse the list of loaded kexts.
**********/
static IOLock                 * sKextSummariesLock                = NULL;
extern "C" lck_spin_t           vm_allocation_sites_lock;
static IOSimpleLock           * sKextAccountsLock = &vm_allocation_sites_lock;

void (*sLoadedKextSummariesUpdated)(void) = OSKextLoadedKextSummariesUpdated;
OSKextLoadedKextSummaryHeader * gLoadedKextSummaries __attribute__((used)) = NULL;
uint64_t gLoadedKextSummariesTimestamp __attribute__((used)) = 0;
static size_t sLoadedKextSummariesAllocSize = 0;

static OSKextActiveAccount * sKextAccounts;
static uint32_t                 sKextAccountsCount;
};

/*********************************************************************
* sKextLoggingLock protects the logging variables declared immediately below.
**********/
static IOLock             * sKextLoggingLock           = NULL;

static  const OSKextLogSpec kDefaultKernelLogFilter    = kOSKextLogBasicLevel |
                                                         kOSKextLogVerboseFlagsMask;
static  OSKextLogSpec       sKernelLogFilter           = kDefaultKernelLogFilter;
static  bool                sBootArgLogFilterFound     = false;
SYSCTL_UINT(_debug, OID_AUTO, kextlog, CTLFLAG_RW | CTLFLAG_LOCKED, &sKernelLogFilter,
    0, "kernel kext logging");

static  OSKextLogSpec       sUserSpaceKextLogFilter    = kOSKextLogSilentFilter;
static  OSArray           * sUserSpaceLogSpecArray     = NULL;
static  OSArray           * sUserSpaceLogMessageArray  = NULL;

/*********
* End scope for sKextInnerLock-protected variables.
*********************************************************************/


/*********************************************************************
 helper function used for collecting PGO data upon unload of a kext
 */

static int OSKextGrabPgoDataLocked(OSKext *kext,
                                   bool metadata,
                                   uuid_t instance_uuid,
                                   uint64_t *pSize,
                                   char *pBuffer,
                                   uint64_t bufferSize);

/**********************************************************************/



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

void osdata_kext_free(void * ptr, unsigned int length)
{
    (void)kext_free((vm_offset_t)ptr, length);
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
    linkBuffer->setDeallocFunction(osdata_kext_free);
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

    OSSafeReleaseNULL(linkBuffer);

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
#pragma mark IOStatistics defines
#endif

#if IOKITSTATS

#define notifyKextLoadObservers(kext, kmod_info) \
do { \
    IOStatistics::onKextLoad(kext, kmod_info); \
} while (0)

#define notifyKextUnloadObservers(kext) \
do { \
    IOStatistics::onKextUnload(kext); \
} while (0)

#define notifyAddClassObservers(kext, addedClass, flags) \
do { \
    IOStatistics::onClassAdded(kext, addedClass); \
} while (0)

#define notifyRemoveClassObservers(kext, removedClass, flags) \
do { \
    IOStatistics::onClassRemoved(kext, removedClass); \
} while (0)

#else

#define notifyKextLoadObservers(kext, kmod_info)
#define notifyKextUnloadObservers(kext)
#define notifyAddClassObservers(kext, addedClass, flags)
#define notifyRemoveClassObservers(kext, removedClass, flags)

#endif /* IOKITSTATS */

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
    sKextSummariesLock = IOLockAlloc();
    sKextLoggingLock = IOLockAlloc();
    assert(sKextLock);
    assert(sKextInnerLock);
    assert(sKextSummariesLock);
    assert(sKextLoggingLock);

    sKextsByID = OSDictionary::withCapacity(kOSKextTypicalLoadCount);
    sLoadedKexts = OSArray::withCapacity(kOSKextTypicalLoadCount);
    sUnloadedPrelinkedKexts = OSArray::withCapacity(kOSKextTypicalLoadCount / 10);
    sKernelRequests = OSArray::withCapacity(0);
    sPostedKextLoadIdentifiers = OSSet::withCapacity(0);
    sAllKextLoadIdentifiers = OSSet::withCapacity(kOSKextTypicalLoadCount);
    sRequestCallbackRecords = OSArray::withCapacity(0);
    assert(sKextsByID && sLoadedKexts && sKernelRequests &&
        sPostedKextLoadIdentifiers && sAllKextLoadIdentifiers &&
        sRequestCallbackRecords && sUnloadedPrelinkedKexts);

   /* Read the log flag boot-args and set the log flags.
    */
    if (PE_parse_boot_argn("kextlog", &bootLogFilter, sizeof(bootLogFilter))) {
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

    PE_parse_boot_argn("keepsyms", &sKeepSymbols, sizeof(sKeepSymbols));
#if KASAN_DYNAMIC_BLACKLIST
    /* needed for function lookup */
    sKeepSymbols = true;
#endif

   /* Set up an OSKext instance to represent the kernel itself.
    */
    sKernelKext = new OSKext;
    assert(sKernelKext);

    kernelStart = (u_char *)&_mh_execute_header;
    kernelLength = getlastaddr() - (vm_offset_t)kernelStart;
    kernelExecutable = OSData::withBytesNoCopy(
        kernelStart, kernelLength);
    assert(kernelExecutable);

#if KASLR_KEXT_DEBUG 
    IOLog("kaslr: kernel start 0x%lx end 0x%lx length %lu vm_kernel_slide %llu (0x%016lx) \n",
          (unsigned long)kernelStart, 
          (unsigned long)getlastaddr(),
          kernelLength,
          vm_kernel_slide, vm_kernel_slide);
#endif

    sKernelKext->loadTag = sNextLoadTag++;  // the kernel is load tag 0
    sKernelKext->bundleID = OSSymbol::withCString(kOSKextKernelIdentifier);
    
    sKernelKext->version = OSKextParseVersionString(osrelease);
    sKernelKext->compatibleVersion = sKernelKext->version;
    sKernelKext->linkedExecutable = kernelExecutable;
    
    sKernelKext->flags.hasAllDependencies = 1;
    sKernelKext->flags.kernelComponent = 1;
    sKernelKext->flags.prelinked = 0;
    sKernelKext->flags.loaded = 1;
    sKernelKext->flags.started = 1;
    sKernelKext->flags.CPPInitialized = 0;
    sKernelKext->flags.jettisonLinkeditSeg = 0;

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

    OSSafeReleaseNULL(kernelCPUType);
    OSSafeReleaseNULL(kernelCPUSubtype);

    timestamp = __OSAbsoluteTimePtr(&last_loaded_timestamp);
    *timestamp = 0;
    timestamp = __OSAbsoluteTimePtr(&last_unloaded_timestamp);
    *timestamp = 0;
    timestamp = __OSAbsoluteTimePtr(&sLastWakeTime);
    *timestamp = 0;

    OSKextLog(/* kext */ NULL,
        kOSKextLogProgressLevel |
        kOSKextLogGeneralFlag,
        "Kext system initialized.");

    notifyKextLoadObservers(sKernelKext, sKernelKext->kmod_info);

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

    const char               * dt_kernel_header_name = "Kernel-__HEADER";
    const char               * dt_kernel_symtab_name = "Kernel-__SYMTAB";
    kernel_mach_header_t     * dt_mach_header        = NULL;
    int                        dt_mach_header_size   = 0;
    struct symtab_command    * dt_symtab             = NULL;
    int                        dt_symtab_size        = 0;
    int                        dt_result             = 0;

    kernel_segment_command_t * seg_to_remove         = NULL;

#if __arm__ || __arm64__
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

#if __arm__ || __arm64__
#if !(defined(KERNEL_INTEGRITY_KTRR))
   /* Free the memory that was set up by bootx.
    */
    dt_segment_name = "Kernel-__KLD";
    if (0 == IODTGetLoaderInfo(dt_segment_name, &segment_paddress, &segment_size)) {
       /* We cannot free this with KTRR enabled, as we cannot
        * update the permissions on the KLD range this late
        * in the boot process.
        */
        IODTFreeLoaderInfo(dt_segment_name, (void *)segment_paddress,
            (int)segment_size);
    }
#endif /* !(defined(KERNEL_INTEGRITY_KTRR)) */
#elif __i386__ || __x86_64__
   /* On x86, use the mapping data from the segment load command to
    * unload KLD directly.
    * This may invalidate any assumptions about  "avail_start"
    * defining the lower bound for valid physical addresses.
    */
    if (seg_to_remove && seg_to_remove->vmaddr && seg_to_remove->vmsize) {
        // 04/18/11 - gab: <rdar://problem/9236163>
        // overwrite memory occupied by KLD segment with random data before
        // releasing it.
        read_frandom((void *) seg_to_remove->vmaddr, seg_to_remove->vmsize);
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

    seg_to_remove = (kernel_segment_command_t *)getsegbyname("__LINKEDIT");

    /* kxld always needs the kernel's __LINKEDIT segment, but we can make it
     * pageable, unless keepsyms is set.  To do that, we have to copy it from
     * its booter-allocated memory, free the booter memory, reallocate proper
     * managed memory, then copy the segment back in.
     */
#if CONFIG_KXLD
#if (__arm__ || __arm64__)
#error CONFIG_KXLD not expected for this arch
#endif
    if (!sKeepSymbols) {
        kern_return_t mem_result;
        void *seg_copy = NULL;
        void *seg_data = NULL;
        vm_map_offset_t seg_offset = 0;
        vm_map_offset_t seg_copy_offset = 0;
        vm_map_size_t seg_length = 0;

        seg_data = (void *) seg_to_remove->vmaddr;
        seg_offset = (vm_map_offset_t) seg_to_remove->vmaddr;
        seg_length = (vm_map_size_t) seg_to_remove->vmsize;

       /* Allocate space for the LINKEDIT copy.
        */
        mem_result = kmem_alloc(kernel_map, (vm_offset_t *) &seg_copy,
            seg_length, VM_KERN_MEMORY_KEXT);
        if (mem_result != KERN_SUCCESS) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
                "Can't copy __LINKEDIT segment for VM reassign.");
            goto finish;
        }
        seg_copy_offset = (vm_map_offset_t) seg_copy;

       /* Copy it out.
        */
        memcpy(seg_copy, seg_data, seg_length);

       /* Dump the booter memory.
        */
        ml_static_mfree(seg_offset, seg_length);

       /* Set up the VM region.
        */
        mem_result = vm_map_enter_mem_object(
            kernel_map,
            &seg_offset,
            seg_length, /* mask */ 0, 
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_NONE,
            (ipc_port_t)NULL,
            (vm_object_offset_t) 0,
            /* copy */ FALSE,
            /* cur_protection */ VM_PROT_READ | VM_PROT_WRITE,
            /* max_protection */ VM_PROT_ALL,
            /* inheritance */ VM_INHERIT_DEFAULT);
        if ((mem_result != KERN_SUCCESS) || 
            (seg_offset != (vm_map_offset_t) seg_data))
        {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
                "Can't create __LINKEDIT VM entry at %p, length 0x%llx (error 0x%x).",
                seg_data, seg_length, mem_result);
            goto finish;
        }

       /* And copy it back.
        */
        memcpy(seg_data, seg_copy, seg_length);

       /* Free the copy.
        */
        kmem_free(kernel_map, seg_copy_offset, seg_length);
    }
#else /* we are not CONFIG_KXLD */
#if !(__arm__ || __arm64__)
#error CONFIG_KXLD is expected for this arch
#endif

    /*****
    * Dump the LINKEDIT segment, unless keepsyms is set.
    */
    if (!sKeepSymbols) {
        dt_segment_name = "Kernel-__LINKEDIT";
        if (0 == IODTGetLoaderInfo(dt_segment_name,
            &segment_paddress, &segment_size)) {
#ifdef SECURE_KERNEL
            vm_offset_t vmaddr = ml_static_ptovirt((vm_offset_t)segment_paddress);
            bzero((void*)vmaddr, segment_size);
#endif
            IODTFreeLoaderInfo(dt_segment_name, (void *)segment_paddress,
                (int)segment_size);
        }
    } else {
        OSKextLog(/* kext */ NULL,
           kOSKextLogBasicLevel |
           kOSKextLogGeneralFlag,
           "keepsyms boot arg specified; keeping linkedit segment for symbols.");
    }
#endif /* CONFIG_KXLD */

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

    OSSafeReleaseNULL(prelinkedKexts);
    OSSafeReleaseNULL(kextIterator);
    OSSafeReleaseNULL(prelinkIterator);

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
        OSKext::pingKextd();
    }
    IORecursiveLockUnlock(sKextLock);

    return;
}

/*********************************************************************
* OSKextLib.cpp might need access to this someday but for now it's
* private.
*********************************************************************/
extern "C" {
extern void ipc_port_release_send(ipc_port_t);
};

/* static */
OSReturn
OSKext::pingKextd(void)
{
    OSReturn    result     = kOSReturnError;
#if !NO_KEXTD
    mach_port_t kextd_port = IPC_PORT_NULL;

    if (!sKextdActive) {
        result = kOSKextReturnDisabled;  // basically unavailable
        goto finish;
    }

    result = host_get_kextd_port(host_priv_self(), &kextd_port);
    if (result != KERN_SUCCESS || !IPC_PORT_VALID(kextd_port)) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "Can't get kextd port.");
        goto finish;
    }

    result = kextd_ping(kextd_port);
    if (result != KERN_SUCCESS) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogIPCFlag,
            "kextd ping failed (0x%x).", (int)result);
        goto finish;
    }

finish:
    if (IPC_PORT_VALID(kextd_port)) {
        ipc_port_release_send(kextd_port);
    }
#endif

    return result;
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
#if !NO_KEXTD
    OSReturn       checkResult = kOSReturnError;
#endif
    OSDictionary * exitRequest = NULL;  // must release

    IORecursiveLockLock(sKextLock);

    OSKext::setLoadEnabled(false);
    OSKext::setUnloadEnabled(false);
    OSKext::setAutounloadsEnabled(false);
    OSKext::setKernelRequestsEnabled(false);

#if !NO_KEXTD
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

    OSKext::pingKextd();

finish:
#endif

    IORecursiveLockUnlock(sKextLock);

    OSSafeReleaseNULL(exitRequest);
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
    OSDictionary * anInfoDict,
    bool doCoalesedSlides)
{
    OSKext * newKext = new OSKext;

    if (newKext && !newKext->initWithPrelinkedInfoDict(anInfoDict, doCoalesedSlides)) {
        newKext->release();
        return NULL;
    }

    return newKext;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::initWithPrelinkedInfoDict(
    OSDictionary * anInfoDict,
    bool doCoalesedSlides)
{
    bool            result              = false;
    OSString      * kextPath            = NULL;  // do not release
    OSNumber      * addressNum          = NULL;  // reused; do not release
    OSNumber      * lengthNum           = NULL;  // reused; do not release
    void          * data                = NULL;  // do not free
    void          * srcData             = NULL;  // do not free
    OSData        * prelinkedExecutable = NULL;  // must release
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
#if KASLR_KEXT_DEBUG
    IOLog("kaslr: doCoalesedSlides %d kext %s \n", doCoalesedSlides, getIdentifierCString());
#endif

   /* Also get the executable's bundle-relative path if present.
    * Don't look for an arch-specific path property.
    */
    executableRelPath = OSDynamicCast(OSString,
        anInfoDict->getObject(kPrelinkExecutableRelativePathKey));
    if (executableRelPath) {
        executableRelPath->retain();
    }

   /* Don't need the paths to be in the info dictionary any more.
    */
    anInfoDict->removeObject(kPrelinkBundlePathKey);
    anInfoDict->removeObject(kPrelinkExecutableRelativePathKey);

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

        data = (void *) ((intptr_t) (addressNum->unsigned64BitValue()) + vm_kernel_slide);
        length = (uint32_t) (lengthNum->unsigned32BitValue());

#if KASLR_KEXT_DEBUG
        IOLog("kaslr: unslid 0x%lx slid 0x%lx length %u - prelink executable \n",
              (unsigned long)VM_KERNEL_UNSLIDE(data), 
              (unsigned long)data,
              length);
#endif

        anInfoDict->removeObject(kPrelinkExecutableLoadKey);
        anInfoDict->removeObject(kPrelinkExecutableSizeKey);

        /* If the kext's load address differs from its source address, allocate
         * space in the kext map at the load address and copy the kext over.
         */
        addressNum = OSDynamicCast(OSNumber, anInfoDict->getObject(kPrelinkExecutableSourceKey));
        if (addressNum) {
            srcData = (void *) ((intptr_t) (addressNum->unsigned64BitValue()) + vm_kernel_slide);
            
#if KASLR_KEXT_DEBUG
            IOLog("kaslr: unslid 0x%lx slid 0x%lx - prelink executable source \n",
                  (unsigned long)VM_KERNEL_UNSLIDE(srcData),
                  (unsigned long)srcData);
#endif
            
            if (data != srcData) {
#if __LP64__
                kern_return_t alloc_result;
                
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

        prelinkedExecutable = OSData::withBytesNoCopy(data, length);
        if (!prelinkedExecutable) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
                "Kext %s failed to create executable wrapper.",
                getIdentifierCString());
            goto finish;
        }

#if VM_MAPPED_KEXTS
        prelinkedExecutable->setDeallocFunction(osdata_kext_free);
#else
        prelinkedExecutable->setDeallocFunction(osdata_phys_free);
#endif
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

        if (addressNum->unsigned64BitValue() != 0) {
            kmod_info = (kmod_info_t *) (intptr_t) (addressNum->unsigned64BitValue() + vm_kernel_slide);
            kmod_info->address += vm_kernel_slide;
#if KASLR_KEXT_DEBUG
            IOLog("kaslr: unslid 0x%lx slid 0x%lx - kmod_info \n",
                  (unsigned long)VM_KERNEL_UNSLIDE(kmod_info), 
                  (unsigned long)kmod_info);
            IOLog("kaslr: unslid 0x%lx slid 0x%lx - kmod_info->address \n", 
                  (unsigned long)VM_KERNEL_UNSLIDE(kmod_info->address), 
                  (unsigned long)kmod_info->address);
 #endif
        }

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

    result = slidePrelinkedExecutable(doCoalesedSlides);
    if (result != kOSReturnSuccess) {
        goto finish;
    }

    if (doCoalesedSlides == false) {
        /* set VM protections now, wire later at kext load */
        result = setVMAttributes(true, false);
        if (result != KERN_SUCCESS) {
            goto finish;
        }
    }
    
    flags.prelinked = true;

   /* If we created a kext from prelink info,
    * we must be booting from a prelinked kernel.
    */
    sPrelinkBoot = true;

    result = registerIdentifier();

finish:
    OSSafeReleaseNULL(prelinkedExecutable);

    return result;
}

/*********************************************************************
 *********************************************************************/
/* static */
void OSKext::setAllVMAttributes(void)
{
    OSCollectionIterator * kextIterator     = NULL;  // must release
    const OSSymbol * thisID                 = NULL;  // do not release

    IORecursiveLockLock(sKextLock);

    kextIterator = OSCollectionIterator::withCollection(sKextsByID);
    if (!kextIterator) {
        goto finish;
    }
    
    while ((thisID = OSDynamicCast(OSSymbol, kextIterator->getNextObject()))) {
        OSKext *    thisKext;  // do not release
        
        thisKext = OSDynamicCast(OSKext, sKextsByID->getObject(thisID));
        if (!thisKext || thisKext->isInterface() || !thisKext->declaresExecutable()) {
            continue;
        }
       
        /* set VM protections now, wire later at kext load */
        thisKext->setVMAttributes(true, false);
    }
    
finish:
    IORecursiveLockUnlock(sKextLock);
    OSSafeReleaseNULL(kextIterator);

    return;
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

    OSObject            * parsedXML      = NULL;  // must release
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
    OSSafeReleaseNULL(parsedXML);
    OSSafeReleaseNULL(kextPath);
    OSSafeReleaseNULL(errorString);
    OSSafeReleaseNULL(executable);

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

    IORecursiveLockLock(sKextLock);

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

    IORecursiveLockUnlock(sKextLock);

    if (result) {
        OSKextLog(this,
            kOSKextLogStepLevel |
            kOSKextLogKextBookkeepingFlag,
            "Kext %s, v%s registered and available for loading.",
            getIdentifierCString(), newVersionCString);
    }

    OSSafeReleaseNULL(newUUID);
    OSSafeReleaseNULL(existingUUID);

    return result;
}

/*********************************************************************
* Does the bare minimum validation to look up a kext.
* All other validation is done on the spot as needed.
**********************************************************************/
bool
OSKext::setInfoDictionaryAndPath(
    OSDictionary * aDictionary,
    OSString     * aPath)
{
    bool           result                   = false;
    OSString     * bundleIDString           = NULL;  // do not release
    OSString     * versionString            = NULL;  // do not release
    OSString     * compatibleVersionString  = NULL;  // do not release
    const char   * versionCString           = NULL;  // do not free
    const char   * compatibleVersionCString = NULL;  // do not free
    OSBoolean    * scratchBool              = NULL;  // do not release
    OSDictionary * scratchDict              = NULL;  // do not release

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
    
    /* Check to see if this kext is in exclude list */
    if ( isInExcludeList() ) {
        OSKextLog(this,
                  kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
                  "Kext %s is in exclude list, not loadable",
                  getIdentifierCString());
        goto finish;
    }

   /* Set flags for later use if the infoDict gets flushed. We only
    * check for true values, not false ones(!)
    */
    scratchBool = OSDynamicCast(OSBoolean,
        getPropertyForHostArch(kOSBundleIsInterfaceKey));
    if (scratchBool == kOSBooleanTrue) {
        flags.interface = 1;
    }
    
    scratchBool = OSDynamicCast(OSBoolean,
        getPropertyForHostArch(kOSKernelResourceKey));
    if (scratchBool == kOSBooleanTrue) {
        flags.kernelComponent = 1;
        flags.interface = 1;  // xxx - hm. the kernel itself isn't an interface...
        flags.started = 1;
        
       /* A kernel component has one implicit dependency on the kernel.
        */
        flags.hasAllDependencies = 1;
    }

   /* Make sure common string values in personalities are uniqued to OSSymbols.
    */
    scratchDict = OSDynamicCast(OSDictionary, 
        getPropertyForHostArch(kIOKitPersonalitiesKey));
    if (scratchDict) {
        uniquePersonalityProperties(scratchDict);
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
static void
uniqueStringPlistProperty(OSDictionary * dict, const char * key)
{
    OSString       * stringValue = NULL;  // do not release
    const OSSymbol * symbolValue = NULL;  // must release

    stringValue = OSDynamicCast(OSString, dict->getObject(key));
    if (!stringValue) {
        goto finish;
    }
    
    symbolValue = OSSymbol::withString(stringValue);
    if (!symbolValue) {
        goto finish;
    }

    dict->setObject(key, symbolValue);
    
finish:
    if (symbolValue) symbolValue->release();

    return;
}

/*********************************************************************
*********************************************************************/
static void
uniqueStringPlistProperty(OSDictionary * dict, const OSString * key)
{
    OSString       * stringValue = NULL;  // do not release
    const OSSymbol * symbolValue = NULL;  // must release

    stringValue = OSDynamicCast(OSString, dict->getObject(key));
    if (!stringValue) {
        goto finish;
    }
    
    symbolValue = OSSymbol::withString(stringValue);
    if (!symbolValue) {
        goto finish;
    }

    dict->setObject(key, symbolValue);
    
finish:
    if (symbolValue) symbolValue->release();

    return;
}

/*********************************************************************
* Replace common personality property values with uniqued instances
* to save on wired memory.
*********************************************************************/
/* static */
void
OSKext::uniquePersonalityProperties(OSDictionary * personalityDict)
{
   /* Properties every personality has.
    */
    uniqueStringPlistProperty(personalityDict, kCFBundleIdentifierKey);
    uniqueStringPlistProperty(personalityDict, kIOProviderClassKey);
    uniqueStringPlistProperty(personalityDict, gIOClassKey);
    
   /* Other commonly used properties.
    */
    uniqueStringPlistProperty(personalityDict, gIOMatchCategoryKey);
    uniqueStringPlistProperty(personalityDict, gIOResourceMatchKey);
    uniqueStringPlistProperty(personalityDict, gIOUserClientClassKey);

    uniqueStringPlistProperty(personalityDict, "HIDDefaultBehavior");
    uniqueStringPlistProperty(personalityDict, "HIDPointerAccelerationType");
    uniqueStringPlistProperty(personalityDict, "HIDRemoteControlType");
    uniqueStringPlistProperty(personalityDict, "HIDScrollAccelerationType");
    uniqueStringPlistProperty(personalityDict, "IOPersonalityPublisher"); 
    uniqueStringPlistProperty(personalityDict, "Physical Interconnect");
    uniqueStringPlistProperty(personalityDict, "Physical Interconnect Location");
    uniqueStringPlistProperty(personalityDict, "Vendor");
    uniqueStringPlistProperty(personalityDict, "Vendor Identification");
    uniqueStringPlistProperty(personalityDict, "Vendor Name");
    uniqueStringPlistProperty(personalityDict, "bConfigurationValue");
    uniqueStringPlistProperty(personalityDict, "bInterfaceNumber");
    uniqueStringPlistProperty(personalityDict, "idProduct");

    return;
}

/*********************************************************************
*********************************************************************/
void
OSKext::free(void)
{
    if (isLoaded()) {
        panic("Attempt to free loaded kext %s.", getIdentifierCString());
    }

    OSSafeReleaseNULL(infoDict);
    OSSafeReleaseNULL(bundleID);
    OSSafeReleaseNULL(path);
    OSSafeReleaseNULL(executableRelPath);
    OSSafeReleaseNULL(dependencies);
    OSSafeReleaseNULL(linkedExecutable);
    OSSafeReleaseNULL(metaClasses);
    OSSafeReleaseNULL(interfaceUUID);

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
    OSObject      * parsedXML                  = NULL;  // must release
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
        if (infoDict) {
            OSKext * newKext = OSKext::withMkext2Info(infoDict, mkextData);
            OSSafeReleaseNULL(newKext);
        }
    }

   /* Even if we didn't keep any kexts from the mkext, we may have a load
    * request to process, so we are successful (no errors occurred).
    */
    result = kOSReturnSuccess;

finish:

    OSSafeReleaseNULL(parsedXML);
    OSSafeReleaseNULL(mkextPlistUncompressedData);
    OSSafeReleaseNULL(errorString);

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

    if (anInfoDict == NULL || !super::init()) {
        goto finish;
    }

   /* Get the path. Don't look for an arch-specific path property.
    */
    kextPath = OSDynamicCast(OSString,
                             anInfoDict->getObject(kMKEXTBundlePathKey));

    if (!setInfoDictionaryAndPath(anInfoDict, kextPath)) {
        goto finish;
    }

   /* If we have a path to the executable, save it.
    */
    executableRelPath = OSDynamicCast(OSString,
        anInfoDict->getObject(kMKEXTExecutableRelativePathKey));
    if (executableRelPath) {
        executableRelPath->retain();
    }

   /* Don't need the paths to be in the info dictionary any more.
    */
    anInfoDict->removeObject(kMKEXTBundlePathKey);
    anInfoDict->removeObject(kMKEXTExecutableRelativePathKey);

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

    OSSafeReleaseNULL(executable);
    OSSafeReleaseNULL(iterator);
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

    uint64_t   total = ((uint64_t)num_items) * ((uint64_t)size);
    //Check for overflow due to multiplication 
    if (total > UINT32_MAX){
        panic("z_alloc(%p, %x, %x): overflow caused by %x * %x\n",
               notused, num_items, size, num_items, size);
    }
    
    uint64_t   allocSize64 =  total + ((uint64_t)sizeof(zmem));
    //Check for overflow due to addition
    if (allocSize64 > UINT32_MAX){
        panic("z_alloc(%p, %x, %x): overflow caused by %x + %lx\n",
               notused, num_items, size, (uint32_t)total, sizeof(zmem));
    }
    uint32_t allocSize = (uint32_t)allocSize64;

    zmem = (z_mem *)kalloc_tag(allocSize, VM_KERN_MEMORY_OSKEXT);
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
        (vm_offset_t*)&uncompressedDataBuffer, fullSize, VM_KERN_MEMORY_OSKEXT)) {

       /* How's this for cheesy? The kernel is only asked to extract
        * kext plists so we tailor the log messages.
        */
        if (isKernel()) {
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
        if (isKernel()) {
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

    if (isKernel()) {
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
        if (isKernel()) {
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
        if (isKernel()) {
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
        if (isKernel()) {
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
        OSSafeReleaseNULL(uncompressedData);
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
        requestArgs->getObject(kKextRequestArgumentStartExcludeKey));
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

    OSSafeReleaseNULL(mkextData);
    OSSafeReleaseNULL(mkextPlist);
    OSSafeReleaseNULL(serializer);
    OSSafeReleaseNULL(logInfoArray);

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

        kmem_result = kmem_alloc(kernel_map, (vm_offset_t *)&buffer, round_page(logInfoLength), VM_KERN_MEMORY_OSKEXT);
        if (kmem_result != KERN_SUCCESS) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to copy log info for request from user space.");
           /* Incidental error; we're going to (try to) allow the request
            * to succeed. */
        } else {
            /* 11981737 - clear uninitialized data in last page */
            bzero((void *)(buffer + logInfoLength),
                  (round_page(logInfoLength) - logInfoLength));
            memcpy(buffer, logInfo, logInfoLength);
            *logInfoOut = buffer;
            *logInfoLengthOut = logInfoLength;
        }
    }
    
    result = kOSReturnSuccess;
finish:
    OSSafeReleaseNULL(serializer);
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

OSData *
OSKext::copyKextUUIDForAddress(OSNumber *address)
{
	OSData *uuid = NULL;

	if (!address) {
		return NULL;
	}

	uintptr_t addr = (uintptr_t)address->unsigned64BitValue() + vm_kernel_slide;

#if CONFIG_MACF
	/* Is the calling process allowed to query kext info? */
	if (current_task() != kernel_task) {
		int macCheckResult = 0;
		kauth_cred_t cred = NULL;

		cred = kauth_cred_get_with_ref();
		macCheckResult = mac_kext_check_query(cred);
		kauth_cred_unref(&cred);

		if (macCheckResult != 0) {
			OSKextLog(/* kext */ NULL,
					kOSKextLogErrorLevel | kOSKextLogLoadFlag,
					"Failed to query kext UUID (MAC policy error 0x%x).",
					macCheckResult);
			return NULL;
		}
	}
#endif

	if (((vm_offset_t)addr >= vm_kernel_stext) && ((vm_offset_t)addr < vm_kernel_etext)) {
		/* address in xnu proper */
		unsigned long uuid_len = 0;
		uuid = OSData::withBytes(getuuidfromheader(&_mh_execute_header, &uuid_len), uuid_len);
	} else {
		IOLockLock(sKextSummariesLock);
		OSKextLoadedKextSummary *summary = OSKext::summaryForAddress(addr);
		if (summary) {
			uuid = OSData::withBytes(summary->uuid, sizeof(uuid_t));
		}
		IOLockUnlock(sKextSummariesLock);
	}

	return uuid;
}

/*********************************************************************
*********************************************************************/
OSKext *
OSKext::lookupKextWithUUID(uuid_t wanted)
{
    OSKext * foundKext = NULL;                 // returned
    uint32_t count, i;

    IORecursiveLockLock(sKextLock);

    count = sLoadedKexts->getCount();

    for (i = 0; i < count; i++) {
        OSKext   * thisKext     = NULL;

        thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (!thisKext) {
            continue;
        }

        OSData *uuid_data = thisKext->copyUUID();
        if (!uuid_data) {
            continue;
        }

        uuid_t uuid;
        memcpy(&uuid, uuid_data->getBytesNoCopy(), sizeof(uuid));
        uuid_data->release();

        if (0 == uuid_compare(wanted, uuid)) {
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
#if CONFIG_EMBEDDED
    __unused
#endif
    bool     terminateServicesAndRemovePersonalitiesFlag)
 {
#if CONFIG_EMBEDDED
    OSKextLog(aKext,
        kOSKextLogErrorLevel |
        kOSKextLogKextBookkeepingFlag,
        "removeKext() called for %s, not supported on embedded",
        aKext->getIdentifier() ? aKext->getIdentifierCString() : "unknown kext");

    return kOSReturnSuccess;
#else /* CONFIG_EMBEDDED */

    OSReturn result    = kOSKextReturnInUse;
    OSKext * checkKext = NULL;   // do not release
#if CONFIG_MACF
    int macCheckResult = 0;
    kauth_cred_t cred  = NULL;
#endif

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
#if CONFIG_MACF
        if (current_task() != kernel_task) {
            cred = kauth_cred_get_with_ref();
            macCheckResult = mac_kext_check_unload(cred, aKext->getIdentifierCString());
            kauth_cred_unref(&cred);
        }

        if (macCheckResult != 0) {
            result = kOSReturnError;
            OSKextLog(aKext,
                kOSKextLogErrorLevel |
                kOSKextLogKextBookkeepingFlag,
                "Failed to remove kext %s (MAC policy error 0x%x).",
                aKext->getIdentifierCString(), macCheckResult);
            goto finish;
        }
#endif

        /* make sure there are no resource requests in flight - 17187548 */
        if (aKext->countRequestCallbacks()) {
            goto finish;
        }

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
                    kOSKextLogErrorLevel |
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
#endif /* CONFIG_EMBEDDED */
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

/*********************************************************************
 *********************************************************************/
#define BOOTER_KEXT_PREFIX   "Driver-"

typedef struct _DeviceTreeBuffer {
    uint32_t paddr;
    uint32_t length;
} _DeviceTreeBuffer;

/*********************************************************************
 * Create a dictionary of excluded kexts from the given booter data.
 *********************************************************************/
/* static */
void
OSKext::createExcludeListFromBooterData(
                                        OSDictionary *          theDictionary,
                                        OSCollectionIterator *  theIterator )
{
    OSString                  * deviceTreeName      = NULL;  // do not release
    const _DeviceTreeBuffer   * deviceTreeBuffer    = NULL;  // do not release
    char                      * booterDataPtr       = NULL;  // do not release
    _BooterKextFileInfo       * kextFileInfo        = NULL;  // do not release
    char                      * infoDictAddr        = NULL;  // do not release
    OSObject                  * parsedXML           = NULL;  // must release
    OSDictionary              * theInfoDict         = NULL;  // do not release
    
    theIterator->reset();
    
    /* look for AppleKextExcludeList.kext */
    while ( (deviceTreeName =
             OSDynamicCast(OSString, theIterator->getNextObject())) ) {
        
        const char *    devTreeNameCString;
        OSData *        deviceTreeEntry;
        OSString *      myBundleID;    // do not release
        
        OSSafeReleaseNULL(parsedXML);
        
        deviceTreeEntry = 
        OSDynamicCast(OSData, theDictionary->getObject(deviceTreeName));
        if (!deviceTreeEntry) {
            continue;
        }
        
        /* Make sure it is a kext */
        devTreeNameCString = deviceTreeName->getCStringNoCopy();
        if (strncmp(devTreeNameCString, BOOTER_KEXT_PREFIX,
                    (sizeof(BOOTER_KEXT_PREFIX) - 1)) != 0) {
            OSKextLog(NULL,
                      kOSKextLogErrorLevel | kOSKextLogGeneralFlag, 
                      "\"%s\" not a kext",
                      devTreeNameCString);
            continue;
        }
        
        deviceTreeBuffer = (const _DeviceTreeBuffer *)
        deviceTreeEntry->getBytesNoCopy(0, sizeof(deviceTreeBuffer));
        if (!deviceTreeBuffer) {
            continue;
        }
        
        booterDataPtr = (char *)ml_static_ptovirt(deviceTreeBuffer->paddr);
        if (!booterDataPtr) {
            continue;
        }
        
        kextFileInfo = (_BooterKextFileInfo *) booterDataPtr;
        if (!kextFileInfo->infoDictPhysAddr || 
            !kextFileInfo->infoDictLength)       {
            continue;
        }
        
        infoDictAddr = (char *)
        ml_static_ptovirt(kextFileInfo->infoDictPhysAddr);
        if (!infoDictAddr) {
            continue;
        }
        
        parsedXML = OSUnserializeXML(infoDictAddr);
        if (!parsedXML) {
            continue;
        }
        
        theInfoDict = OSDynamicCast(OSDictionary, parsedXML);
        if (!theInfoDict) {
            continue;
        }
        
        myBundleID = 
        OSDynamicCast(OSString, 
                      theInfoDict->getObject(kCFBundleIdentifierKey));
        if ( myBundleID && 
            strcmp( myBundleID->getCStringNoCopy(), "com.apple.driver.KextExcludeList" ) == 0 ) {
            
            /* get copy of exclusion list dictionary */
            OSDictionary *      myTempDict;     // do not free
            
            myTempDict = OSDynamicCast(
                                       OSDictionary,
                                       theInfoDict->getObject("OSKextExcludeList"));
            if ( NULL == myTempDict ) {
                /* 25322874 */
                panic("Missing OSKextExcludeList dictionary\n");
            }
            
            IORecursiveLockLock(sKextLock);
            
            /* get rid of old exclusion list */
            if (sExcludeListByID) {
                OSSafeReleaseNULL(sExcludeListByID);
            }
            sExcludeListByID = OSDictionary::withDictionary(myTempDict, 0);
            IORecursiveLockUnlock(sKextLock);

            break;
        }
        
    } // while ( (deviceTreeName = ...) )
    
    OSSafeReleaseNULL(parsedXML);
    return;
}

/*********************************************************************
 * Create a dictionary of excluded kexts from the given prelink 
 * info (kernelcache).
 *********************************************************************/
/* static */
void
OSKext::createExcludeListFromPrelinkInfo( OSArray * theInfoArray )
{
    OSDictionary *  myInfoDict = NULL;  // do not release
    OSString *      myBundleID;         // do not release
    u_int           i;
    
    /* Find com.apple.driver.KextExcludeList. */
    for (i = 0; i < theInfoArray->getCount(); i++) {
        myInfoDict = OSDynamicCast(OSDictionary, theInfoArray->getObject(i));
        if (!myInfoDict) {
            continue;
        }
        myBundleID = 
        OSDynamicCast(OSString, 
                      myInfoDict->getObject(kCFBundleIdentifierKey));
        if ( myBundleID && 
            strcmp( myBundleID->getCStringNoCopy(), "com.apple.driver.KextExcludeList" ) == 0 ) {
            // get copy of exclude list dictionary
            OSDictionary *      myTempDict;     // do not free
            myTempDict = OSDynamicCast(OSDictionary,
                                       myInfoDict->getObject("OSKextExcludeList"));
            if ( NULL == myTempDict ) {
                /* 25322874 */
                panic("Missing OSKextExcludeList dictionary\n");
            }
            
            IORecursiveLockLock(sKextLock);
            // get rid of old exclude list
            if (sExcludeListByID) {
                OSSafeReleaseNULL(sExcludeListByID);
            }
            
            sExcludeListByID = OSDictionary::withDictionary(myTempDict, 0);
            IORecursiveLockUnlock(sKextLock);
            break;
        }
    } // for (i = 0; i < theInfoArray->getCount()...
    
    return;
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
OSKext::isLibrary(void)
{
    return (getCompatibleVersion() > 0);
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
    return (getPropertyForHostArch(kCFBundleExecutableKey) != NULL);
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

    OSSafeReleaseNULL(extractedExecutable);

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
OSKext::isKernel(void)
{
    return (this == sKernelKext);
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isKernelComponent(void)
{
    return flags.kernelComponent ? true : false;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::isExecutable(void)
{
    return (!isKernel() && !isInterface() && declaresExecutable());
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
    
    if (isKernel()) {
        result = true;
        goto finish;
    }
    
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
void OSKext::getSizeInfo(uint32_t *loadSize, uint32_t *wiredSize)
{
    if (linkedExecutable) {
        *loadSize = linkedExecutable->getLength();
           
        /* If we have a kmod_info struct, calculated the wired size
         * from that. Otherwise it's the full load size.
         */
        if (kmod_info) {
            *wiredSize = *loadSize - kmod_info->hdr_size;
        } else {
            *wiredSize = *loadSize;
        }
    }
    else {
        *wiredSize = 0;
        *loadSize = 0;
    }
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
        
    if (header->magic != MH_MAGIC_KERNEL) {
        OSKextLog(NULL,
                  kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
                  "%s: bad header %p",
                  __func__,
                  header);
        goto finish;
    }
    
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
#if defined (__arm__)
#include <arm/arch.h>
#endif

#if   defined (__x86_64__)
#define ARCHNAME "x86_64"
#elif defined (__arm64__)
#define ARCHNAME "arm64"
#elif defined (__arm__)

#if defined (__ARM_ARCH_7S__)
#define ARCHNAME "armv7s"
#elif defined (__ARM_ARCH_7F__)
#define ARCHNAME "armv7f"
#elif defined (__ARM_ARCH_7K__)
#define ARCHNAME "armv7k"
#elif defined (_ARM_ARCH_7) /* umbrella for all remaining */
#define ARCHNAME "armv7"
#elif defined (_ARM_ARCH_6) /* umbrella for all armv6 */
#define ARCHNAME "armv6"
#endif

#elif defined (__arm64__)
#define ARCHNAME "arm64"
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
    result = (char *)kalloc_tag(keySize, VM_KERN_MEMORY_OSKEXT);
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

#define isWhiteSpace(c)	((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == ',' || (c) == '\n')

/*********************************************************************
 * sExcludeListByID is a dictionary with keys / values of:
 *  key = bundleID string of kext we will not allow to load
 *  value = version string(s) of the kext that is to be denied loading.
 *      The version strings can be comma delimited.  For example if kext
 *      com.foocompany.fookext has two versions that we want to deny
 *      loading then the version strings might look like:
 *      1.0.0, 1.0.1
 *      If the current fookext has a version of 1.0.0 OR 1.0.1 we will
 *      not load the kext.
 *
 *      Value may also be in the form of "LE 2.0.0" (version numbers
 *      less than or equal to 2.0.0 will not load) or "LT 2.0.0" (version 
 *      number less than 2.0.0 will not load)
 *
 *      NOTE - we cannot use the characters "<=" or "<" because we have code 
 *      that serializes plists and treats '<' as a special character.
 *********************************************************************/
bool 
OSKext::isInExcludeList(void)
{
    OSString *      versionString           = NULL;  // do not release
    char *          versionCString          = NULL;  // do not free
    size_t          i;
    boolean_t       wantLessThan = false;
    boolean_t       wantLessThanEqualTo = false;
    char            myBuffer[32];
    
    if (!sExcludeListByID) {
        return(false);
    }
    /* look up by bundleID in our exclude list and if found get version
     * string (or strings) that we will not allow to load
     */
    versionString = OSDynamicCast(OSString, sExcludeListByID->getObject(bundleID));
    if (versionString == NULL || versionString->getLength() > (sizeof(myBuffer) - 1)) {
        return(false);
    }
    
    /* parse version strings */
    versionCString = (char *) versionString->getCStringNoCopy();
    
    /* look for "LT" or "LE" form of version string, must be in first two
     * positions.
     */
    if (*versionCString == 'L' && *(versionCString + 1) == 'T') {
        wantLessThan = true;
        versionCString +=2; 
    }
    else if (*versionCString == 'L' && *(versionCString + 1) == 'E') {
        wantLessThanEqualTo = true;
        versionCString +=2;
    }

    for (i = 0; *versionCString != 0x00; versionCString++) {
        /* skip whitespace */
        if (isWhiteSpace(*versionCString)) {
            continue;
        }
        
        /* peek ahead for version string separator or null terminator */
        if (*(versionCString + 1) == ',' || *(versionCString + 1) == 0x00) {
            
            /* OK, we have a version string */
            myBuffer[i++] = *versionCString;
            myBuffer[i] = 0x00;

            OSKextVersion excludeVers;
            excludeVers = OSKextParseVersionString(myBuffer);
                
            if (wantLessThanEqualTo) {
                if (version <= excludeVers) {
                    return(true);
                }
            }
            else if (wantLessThan) {
                if (version < excludeVers) {
                    return(true);
                }
            }
            else if ( version == excludeVers )  {
                return(true);
            }
            
            /* reset for the next (if any) version string */
            i = 0;
            wantLessThan = false;
            wantLessThanEqualTo = false;
        }
        else {
            /* save valid version character */
            myBuffer[i++] = *versionCString;
            
            /* make sure bogus version string doesn't overrun local buffer */
            if ( i >= sizeof(myBuffer) ) {
                break;
            }
        }
    }
    
    return(false);
} 

/*********************************************************************
*********************************************************************/
/* static */
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
    OSSafeReleaseNULL(kextIdentifier);
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
    OSReturn          pingResult           = kOSReturnError;
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

        pingResult = OSKext::pingKextd();
        if (pingResult == kOSKextReturnDisabled) {
            OSKextLog(/* kext */ NULL,
                ((sPrelinkBoot) ? kOSKextLogDebugLevel : kOSKextLogErrorLevel) |
                kOSKextLogLoadFlag,
                "Kext %s might not load - kextd is currently unavailable.",
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
    OSSafeReleaseNULL(loadRequest);
    OSSafeReleaseNULL(kextIdentifierSymbol);
    
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

    IORecursiveLockLock(sKextLock);
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
    IORecursiveLockUnlock(sKextLock);

finish:

    if (fail) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogArchiveFlag,
            "Failed to record kext %s as a candidate for inclusion in prelinked kernel.",
            kextIdentifier->getCStringNoCopy());
    }
    OSSafeReleaseNULL(kextIdentifierSymbol);
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

    if (isInExcludeList()) {
        OSKextLog(this,
                  kOSKextLogErrorLevel | kOSKextLogGeneralFlag |
                  kOSKextLogLoadFlag,
                  "Kext %s is in exclude list, not loadable",
                  getIdentifierCString());
        
        result = kOSKextReturnNotLoadable;
        goto finish;
    }

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
    
#if CONFIG_MACF
    if (current_task() != kernel_task) {
        int                 macCheckResult      = 0;
        kauth_cred_t        cred                = NULL;

        cred = kauth_cred_get_with_ref();
        macCheckResult = mac_kext_check_load(cred, getIdentifierCString());
        kauth_cred_unref(&cred);
        
        if (macCheckResult != 0) {
            result = kOSReturnError;
            OSKextLog(this,
                      kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                      "Failed to load kext %s (MAC policy error 0x%x).",
                      getIdentifierCString(), macCheckResult);
            goto finish;
        }
   }
#endif

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
            /* cputype */ 0, /* cpusubtype */ 0, /* page size */ 0);
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

    pendingPgoHead.next = &pendingPgoHead;
    pendingPgoHead.prev = &pendingPgoHead;

    uuid_generate(instance_uuid);
    account = IONew(OSKextAccount, 1);
    if (!account) {
    	result = KERN_MEMORY_ERROR;
	goto finish;
    }
    bzero(account, sizeof(*account));
    account->loadTag = kmod_info->id;
    account->site.refcount = 0;
    account->site.flags = VM_TAG_KMOD;
    account->kext = this;

    flags.loaded = true;

   /* Add the kext to the list of loaded kexts and update the kmod_info
    * struct to point to that of the last loaded kext (which is the way
    * it's always been done, though I'd rather do them in order now).
    */
    lastLoadedKext = OSDynamicCast(OSKext, sLoadedKexts->getLastObject());
    sLoadedKexts->setObject(this);

   /* Keep the kernel itself out of the kmod list.
    */
    if (lastLoadedKext->isKernel()) {
        lastLoadedKext = NULL;
    }

    if (lastLoadedKext) {
        kmod_info->next = lastLoadedKext->kmod_info;
    }

    notifyKextLoadObservers(this, kmod_info);

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
    OSKext::saveLoadedKextPanicList();

    if (isExecutable()) {
        OSKext::updateLoadedKextSummaries();
        savePanicString(/* isLoading */ true);

#if CONFIG_DTRACE
        registerWithDTrace();
#else
        jettisonLinkeditSegment();
#endif /* CONFIG_DTRACE */

#if !VM_MAPPED_KEXTS
        /* If there is a page (or more) worth of padding after the end
         * of the last data section but before the end of the data segment
         * then free it in the same manner the LinkeditSegment is freed
         */
        jettisonDATASegmentPadding();
#endif
    }

loaded:
    if (isExecutable() && !flags.started) {
        if (startOpt == kOSKextExcludeNone) {
            result = start();
            if (result != kOSReturnSuccess) {
                OSKextLog(this,
                    kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                    "Kext %s start failed (result 0x%x).",
                    getIdentifierCString(), result);
                result = kOSKextReturnStartStopError;
            }
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

        queueKextNotification(kKextRequestPredicateLoadNotification,
            OSDynamicCast(OSString, bundleID));
    }
    return result;
}

/*********************************************************************
* 
*********************************************************************/
static char * strdup(const char * string)
{
    char * result = NULL;
    size_t size;
    
    if (!string) {
        goto finish;
    }
    
    size = 1 + strlen(string);
    result = (char *)kalloc_tag(size, VM_KERN_MEMORY_OSKEXT);
    if (!result) {
        goto finish;
    }
    
    memcpy(result, string, size);

finish:
    return result;
}

/*********************************************************************
* 
*********************************************************************/

kernel_section_t *
OSKext::lookupSection(const char *segname, const char *secname)
{
    kernel_section_t         * found_section = NULL;
    kernel_mach_header_t     * mh            = NULL;
    kernel_segment_command_t * seg           = NULL;
    kernel_section_t         * sec           = NULL;

    mh = (kernel_mach_header_t *)linkedExecutable->getBytesNoCopy();

    for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {

        if (0 != strcmp(seg->segname, segname)) {
            continue;
        }

        for (sec = firstsect(seg); sec != NULL; sec = nextsect(seg, sec)) {

            if (0 == strcmp(sec->sectname, secname)) {
                found_section = sec;
                goto out;
            }
        }
    }

 out:
    return found_section;
}

/*********************************************************************
*
*********************************************************************/

OSReturn
OSKext::slidePrelinkedExecutable(bool doCoalesedSlides)
{
    OSReturn                       result           = kOSKextReturnBadData;
    kernel_mach_header_t         * mh               = NULL;
    kernel_segment_command_t     * seg              = NULL;
    kernel_segment_command_t     * linkeditSeg      = NULL;
    kernel_section_t             * sec              = NULL;
    char                         * linkeditBase     = NULL;
    bool                           haveLinkeditBase = false;
    char                         * relocBase        = NULL;
    bool                           haveRelocBase    = false;
    struct dysymtab_command      * dysymtab         = NULL;
    struct linkedit_data_command * segmentSplitInfo = NULL;
    struct symtab_command        * symtab           = NULL;
    kernel_nlist_t               * sym              = NULL;
    struct relocation_info       * reloc            = NULL;
    uint32_t                       i                = 0;
    int                            reloc_size;
    vm_offset_t                    new_kextsize;

    if (linkedExecutable == NULL || vm_kernel_slide == 0) {
        result = kOSReturnSuccess;
        goto finish;
    }

    mh = (kernel_mach_header_t *)linkedExecutable->getBytesNoCopy();
    segmentSplitInfo = (struct linkedit_data_command *) getcommandfromheader(mh, LC_SEGMENT_SPLIT_INFO);

    for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
        if (!seg->vmaddr) {
            continue;
        }
        seg->vmaddr += vm_kernel_slide;
                
#if KASLR_KEXT_DEBUG
        IOLog("kaslr: segname %s unslid 0x%lx slid 0x%lx \n",
              seg->segname,
              (unsigned long)VM_KERNEL_UNSLIDE(seg->vmaddr), 
              (unsigned long)seg->vmaddr);
#endif
       
        if (!haveRelocBase) {
            relocBase = (char *) seg->vmaddr;
            haveRelocBase = true;
        }
        if (!strcmp(seg->segname, "__LINKEDIT")) {
            linkeditBase = (char *) seg->vmaddr - seg->fileoff;
            haveLinkeditBase = true;
            linkeditSeg = seg;
        }
        for (sec = firstsect(seg); sec != NULL; sec = nextsect(seg, sec)) {
            sec->addr += vm_kernel_slide;

#if KASLR_KEXT_DEBUG
            IOLog("kaslr: sectname %s unslid 0x%lx slid 0x%lx \n",
                  sec->sectname,
                  (unsigned long)VM_KERNEL_UNSLIDE(sec->addr), 
                  (unsigned long)sec->addr);
#endif
        }
    }

    dysymtab = (struct dysymtab_command *) getcommandfromheader(mh, LC_DYSYMTAB);

    symtab = (struct symtab_command *) getcommandfromheader(mh, LC_SYMTAB);

    if (symtab != NULL && doCoalesedSlides == false) {
      /* Some pseudo-kexts have symbol tables without segments.
       * Ignore them. */
        if (symtab->nsyms > 0 && haveLinkeditBase) {
            sym = (kernel_nlist_t *) (linkeditBase + symtab->symoff);
            for (i = 0; i < symtab->nsyms; i++) {
                if (sym[i].n_type & N_STAB) {
                    continue;
                }
                sym[i].n_value += vm_kernel_slide;
                
#if KASLR_KEXT_DEBUG
#define MAX_SYMS_TO_LOG 5
                if ( i < MAX_SYMS_TO_LOG ) {
                    IOLog("kaslr: LC_SYMTAB unslid 0x%lx slid 0x%lx \n", 
                          (unsigned long)VM_KERNEL_UNSLIDE(sym[i].n_value), 
                          (unsigned long)sym[i].n_value);
                }
#endif
            }
        }
    }
    
    if (dysymtab != NULL && doCoalesedSlides == false) {
        if (dysymtab->nextrel > 0) {
            OSKextLog(this,
                kOSKextLogErrorLevel | kOSKextLogLoadFlag |
                kOSKextLogLinkFlag,
                "Sliding kext %s: External relocations found.",
                getIdentifierCString());
            goto finish;
        }

        if (dysymtab->nlocrel > 0) {
            if (!haveLinkeditBase) {
                OSKextLog(this,
                    kOSKextLogErrorLevel | kOSKextLogLoadFlag |
                    kOSKextLogLinkFlag,
                    "Sliding kext %s: No linkedit segment.",
                    getIdentifierCString());
                goto finish;
            }

            if (!haveRelocBase) {
                OSKextLog(this,
                    kOSKextLogErrorLevel | kOSKextLogLoadFlag |
                    kOSKextLogLinkFlag,
#if __x86_64__
                    "Sliding kext %s: No writable segments.",
#else
                    "Sliding kext %s: No segments.",
#endif
                    getIdentifierCString());
                goto finish;
            }

            reloc = (struct relocation_info *) (linkeditBase + dysymtab->locreloff);
            reloc_size = dysymtab->nlocrel * sizeof(struct relocation_info);
            
            for (i = 0; i < dysymtab->nlocrel; i++) {
                if (   reloc[i].r_extern != 0
                    || reloc[i].r_type != 0
                    || reloc[i].r_length != (sizeof(void *) == 8 ? 3 : 2)
                    ) {
                    OSKextLog(this,
                        kOSKextLogErrorLevel | kOSKextLogLoadFlag |
                        kOSKextLogLinkFlag,
                        "Sliding kext %s: Unexpected relocation found.",
                        getIdentifierCString());
                    goto finish;
                }
                if (reloc[i].r_pcrel != 0) {
                    continue;
                }
                *((uintptr_t *)(relocBase + reloc[i].r_address)) += vm_kernel_slide;

#if KASLR_KEXT_DEBUG
#define MAX_DYSYMS_TO_LOG 5
                if ( i < MAX_DYSYMS_TO_LOG ) {
                    IOLog("kaslr: LC_DYSYMTAB unslid 0x%lx slid 0x%lx \n", 
                          (unsigned long)VM_KERNEL_UNSLIDE(*((uintptr_t *)(relocBase + reloc[i].r_address))), 
                          (unsigned long)*((uintptr_t *)(relocBase + reloc[i].r_address)));
                }
#endif
            }

            /* We should free these relocations, not just delete the reference to them.
             * <rdar://problem/10535549> Free relocations from PIE kexts.
             *
             * For now, we do not free LINKEDIT for kexts with split segments.
             */
            new_kextsize = round_page(kmod_info->size - reloc_size);
            if (((kmod_info->size - new_kextsize) > PAGE_SIZE) && (!segmentSplitInfo)) {
                vm_offset_t     endofkext = kmod_info->address + kmod_info->size;
                vm_offset_t     new_endofkext = kmod_info->address + new_kextsize;
                vm_offset_t     endofrelocInfo = (vm_offset_t) (((uint8_t *)reloc) + reloc_size);
                int             bytes_remaining = endofkext - endofrelocInfo;
                OSData *        new_osdata = NULL;

                /* fix up symbol offsets if they are after the dsymtab local relocs */
                if (symtab) {
                    if (dysymtab->locreloff < symtab->symoff){
                        symtab->symoff -= reloc_size;
                    }
                    if (dysymtab->locreloff < symtab->stroff) {
                        symtab->stroff -= reloc_size;
                    }
                }
                if (dysymtab->locreloff < dysymtab->extreloff) {
                    dysymtab->extreloff -= reloc_size;
                }
                
                /* move data behind reloc info down to new offset */
                if (endofrelocInfo < endofkext) {
                   memcpy(reloc, (void *)endofrelocInfo, bytes_remaining);
                }
                               
                /* Create a new OSData for the smaller kext object and reflect 
                 * new linkedit segment size.
                 */
                linkeditSeg->vmsize = round_page(linkeditSeg->vmsize - reloc_size);
                linkeditSeg->filesize = linkeditSeg->vmsize;
                
                new_osdata = OSData::withBytesNoCopy((void *)kmod_info->address, new_kextsize);
                if (new_osdata) {
                    /* Fix up kmod info and linkedExecutable.
                     */
                    kmod_info->size = new_kextsize;
#if VM_MAPPED_KEXTS
                    new_osdata->setDeallocFunction(osdata_kext_free);
#else
                    new_osdata->setDeallocFunction(osdata_phys_free);
#endif
                    linkedExecutable->setDeallocFunction(NULL);
                    linkedExecutable->release();
                    linkedExecutable = new_osdata;
                    
#if VM_MAPPED_KEXTS
                    kext_free(new_endofkext, (endofkext - new_endofkext));
#else
                    ml_static_mfree(new_endofkext, (endofkext - new_endofkext));
#endif
                }
            }
            dysymtab->nlocrel = 0;
            dysymtab->locreloff = 0;
        }
    }
                
    result = kOSReturnSuccess;
finish:
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
    KXLDDependency     *  kxlddeps           = NULL;  // must kfree
    uint32_t              num_kxlddeps       = 0;
    OSArray            *  linkDependencies   = NULL;  // must release
    uint32_t              numDirectDependencies   = 0;
    uint32_t              num_kmod_refs      = 0;
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

    /* <rdar://problem/21444003> all callers must be entitled */
    if (FALSE == IOTaskHasEntitlement(current_task(), "com.apple.rootless.kext-management")) {
        OSKextLog(this,
                  kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                  "Not entitled to link kext '%s'",
                  getIdentifierCString());
        result = kOSKextReturnNotPrivileged;
        goto finish;
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

    if (isInterface()) {
        OSData *executableCopy = OSData::withData(theExecutable);
        setLinkedExecutable(executableCopy);
        executableCopy->release();
        goto register_kmod;
    }

    numDirectDependencies = getNumDependencies();

    if (flags.hasBleedthrough) {
        linkDependencies = dependencies;
        linkDependencies->retain();
    } else {
        linkDependencies = OSArray::withArray(dependencies);
        if (!linkDependencies) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag | kOSKextLogLinkFlag,
                "Can't allocate link dependencies to load kext %s.",
                getIdentifierCString());
            goto finish;
        }

        for (i = 0; i < numDirectDependencies; ++i) {
            OSKext * dependencyKext = OSDynamicCast(OSKext,
                dependencies->getObject(i));
            dependencyKext->addBleedthroughDependencies(linkDependencies);
        }
    } 

    num_kxlddeps = linkDependencies->getCount();
    if (!num_kxlddeps) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogDependenciesFlag,
            "Can't load kext %s - it has no library dependencies.",
            getIdentifierCString());
        goto finish;
    }

    kxlddeps = (KXLDDependency *)kalloc_tag(num_kxlddeps * sizeof(*kxlddeps), VM_KERN_MEMORY_OSKEXT);
    if (!kxlddeps) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogLoadFlag | kOSKextLogLinkFlag,
            "Can't allocate link context to load kext %s.",
            getIdentifierCString());
        goto finish;
    }
    bzero(kxlddeps, num_kxlddeps * sizeof(*kxlddeps));

    for (i = 0; i < num_kxlddeps; ++i ) {
        OSKext * dependency = OSDynamicCast(OSKext, linkDependencies->getObject(i));

        if (dependency->isInterface()) {
            OSKext *interfaceTargetKext = NULL;
            OSData * interfaceTarget = NULL;

            if (dependency->isKernelComponent()) {
                interfaceTargetKext = sKernelKext;
                interfaceTarget = sKernelKext->linkedExecutable;
            } else {
                interfaceTargetKext = OSDynamicCast(OSKext, 
                    dependency->dependencies->getObject(0));

                interfaceTarget = interfaceTargetKext->linkedExecutable;
            }

            if (!interfaceTarget) {
                // panic?
                goto finish;
            }

           /* The names set here aren't actually logged yet <rdar://problem/7941514>,
            * it will be useful to have them in the debugger.
            * strdup() failing isn't critical right here so we don't check that.
            */
            kxlddeps[i].kext = (u_char *) interfaceTarget->getBytesNoCopy();
            kxlddeps[i].kext_size = interfaceTarget->getLength();
            kxlddeps[i].kext_name = strdup(interfaceTargetKext->getIdentifierCString());

            kxlddeps[i].interface = (u_char *) dependency->linkedExecutable->getBytesNoCopy();
            kxlddeps[i].interface_size = dependency->linkedExecutable->getLength();
            kxlddeps[i].interface_name = strdup(dependency->getIdentifierCString());
        } else {
            kxlddeps[i].kext = (u_char *) dependency->linkedExecutable->getBytesNoCopy();
            kxlddeps[i].kext_size = dependency->linkedExecutable->getLength();
            kxlddeps[i].kext_name = strdup(dependency->getIdentifierCString());
        }

        kxlddeps[i].is_direct_dependency = (i < numDirectDependencies);
    }

    kxldHeaderPtr = &kxld_header;

#if DEBUG
    OSKextLog(this,
        kOSKextLogExplicitLevel |
        kOSKextLogLoadFlag | kOSKextLogLinkFlag,
        "Kext %s - calling kxld_link_file:\n"
        "    kxld_context: %p\n"
        "    executable: %p    executable_length: %d\n"
        "    user_data: %p\n"
        "    kxld_dependencies: %p    num_dependencies: %d\n"
        "    kxld_header_ptr: %p    kmod_info_ptr: %p\n",
        getIdentifierCString(), sKxldContext,
        theExecutable->getBytesNoCopy(), theExecutable->getLength(),
        this, kxlddeps, num_kxlddeps,
        kxldHeaderPtr, &kmod_info);
#endif

   /* After this call, the linkedExecutable instance variable
    * should exist.
    */
    kxldResult = kxld_link_file(sKxldContext,
        (u_char *)theExecutable->getBytesNoCopy(),
        theExecutable->getLength(),
        getIdentifierCString(), this, kxlddeps, num_kxlddeps,
        (u_char **)kxldHeaderPtr, (kxld_addr_t *)&kmod_info);

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
    
   /* We've written data & instructions into kernel memory, so flush the data
    * cache and invalidate the instruction cache.
    * I/D caches are coherent on x86
    */
#if !defined(__i386__) && !defined(__x86_64__)
    flush_dcache(kmod_info->address, kmod_info->size, false);
    invalidate_icache(kmod_info->address, kmod_info->size, false);
#endif
register_kmod:

    if (isInterface()) {

       /* Whip up a fake kmod_info entry for the interface kext.
        */
        kmod_info = (kmod_info_t *)kalloc_tag(sizeof(kmod_info_t), VM_KERN_MEMORY_OSKEXT);
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
        kmod_info->reference_list = (kmod_reference_t *)kalloc_tag(
            num_kmod_refs * sizeof(kmod_reference_t), VM_KERN_MEMORY_OSKEXT);
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
            (unsigned long)VM_KERNEL_UNSLIDE(kmod_info->address),
            (unsigned)kmod_info->id);
    }

    /* if prelinked, VM protections are already set */
    result = setVMAttributes(!isPrelinked(), true);
    if (result != KERN_SUCCESS) {
        goto finish;
    }

#if KASAN
    kasan_load_kext((vm_offset_t)linkedExecutable->getBytesNoCopy(),
                    linkedExecutable->getLength(), getIdentifierCString());
#else
    if (lookupSection(KASAN_GLOBAL_SEGNAME, KASAN_GLOBAL_SECTNAME)) {
        OSKextLog(this,
                kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                "KASAN: cannot load KASAN-ified kext %s on a non-KASAN kernel\n",
                getIdentifierCString()
                );
        result = KERN_FAILURE;
        goto finish;
    }
#endif

    result = kOSReturnSuccess;

finish:
    OSSafeReleaseNULL(linkDependencies);

   /* Clear up locally allocated dependency info.
    */
    for (i = 0; i < num_kxlddeps; ++i ) {
        size_t size;

        if (kxlddeps[i].kext_name) {
            size = 1 + strlen(kxlddeps[i].kext_name);
            kfree(kxlddeps[i].kext_name, size);
        }
        if (kxlddeps[i].interface_name) {
            size = 1 + strlen(kxlddeps[i].interface_name);
            kfree(kxlddeps[i].interface_name, size);
        }
    }
    if (kxlddeps) kfree(kxlddeps, (num_kxlddeps * sizeof(*kxlddeps)));

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
* The linkedit segment is used by the kext linker for dependency
* resolution, and by dtrace for probe initialization. We can free it
* for non-library kexts, since no kexts depend on non-library kexts
* by definition, once dtrace has been initialized.
*********************************************************************/
void
OSKext::jettisonLinkeditSegment(void)
{
    kernel_mach_header_t     * machhdr = (kernel_mach_header_t *)kmod_info->address;
    kernel_segment_command_t * linkedit = NULL;
    vm_offset_t                start;
    vm_size_t                  linkeditsize, kextsize;
    OSData                   * data = NULL;

#if NO_KEXTD
    /* We can free symbol tables for all embedded kexts because we don't
     * support runtime kext linking.
     */
    if (sKeepSymbols || !isExecutable() || !linkedExecutable || flags.jettisonLinkeditSeg) {
#else
    if (sKeepSymbols || isLibrary() || !isExecutable() || !linkedExecutable || flags.jettisonLinkeditSeg) {
#endif
        goto finish;
    }

   /* Find the linkedit segment.  If it's not the last segment, then freeing
    * it will fragment the kext into multiple VM regions, which OSKext is not
    * designed to handle, so we'll have to skip it.
    */
    linkedit = getsegbynamefromheader(machhdr, SEG_LINKEDIT);
    if (!linkedit) {
        goto finish;
    }

    if (round_page(kmod_info->address + kmod_info->size) !=
        round_page(linkedit->vmaddr + linkedit->vmsize))
    {
        goto finish;
    }

   /* Create a new OSData for the smaller kext object.
    */
    linkeditsize = round_page(linkedit->vmsize);
    kextsize = kmod_info->size - linkeditsize;
    start = linkedit->vmaddr;

    data = OSData::withBytesNoCopy((void *)kmod_info->address, kextsize);
    if (!data) {
        goto finish;
    }

   /* Fix the kmod info and linkedExecutable.
    */
    kmod_info->size = kextsize;
        
#if VM_MAPPED_KEXTS
    data->setDeallocFunction(osdata_kext_free);
#else
    data->setDeallocFunction(osdata_phys_free);
#endif
    linkedExecutable->setDeallocFunction(NULL);
    linkedExecutable->release();
    linkedExecutable = data;
    flags.jettisonLinkeditSeg = 1;
        
   /* Free the linkedit segment.
    */
#if VM_MAPPED_KEXTS
    kext_free(start, linkeditsize);
#else
    ml_static_mfree(start, linkeditsize);
#endif

finish:
    return;
}

/*********************************************************************
* If there are whole pages that are unused betweem the last section
* of the DATA segment and the end of the DATA segment then we can free
* them
*********************************************************************/
void
OSKext::jettisonDATASegmentPadding(void)
{
    kernel_mach_header_t * mh;
    kernel_segment_command_t * dataSeg;
    kernel_section_t * sec, * lastSec;
    vm_offset_t dataSegEnd, lastSecEnd;
    vm_size_t padSize;

    mh = (kernel_mach_header_t *)kmod_info->address;

    dataSeg = getsegbynamefromheader(mh, SEG_DATA);
    if (dataSeg == NULL) {
        return;
    }

    lastSec = NULL;
    sec = firstsect(dataSeg);
    while (sec != NULL) {
        lastSec = sec;
        sec = nextsect(dataSeg, sec);
    } 

    if (lastSec == NULL) {
        return;
    }

    if ((dataSeg->vmaddr != round_page(dataSeg->vmaddr)) ||
        (dataSeg->vmsize != round_page(dataSeg->vmsize))) {
        return;
    }

    dataSegEnd = dataSeg->vmaddr + dataSeg->vmsize;
    lastSecEnd = round_page(lastSec->addr + lastSec->size);

    if (dataSegEnd <= lastSecEnd) {
        return;
    }

    padSize = dataSegEnd - lastSecEnd;

    if (padSize >= PAGE_SIZE) {
#if VM_MAPPED_KEXTS
        kext_free(lastSecEnd, padSize);
#else
        ml_static_mfree(lastSecEnd, padSize);
#endif
    }
}

/*********************************************************************
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

#if CONFIG_DTRACE
/*********************************************************************
* Go through all loaded kexts and tell them to register with dtrace.
* The instance method only registers if necessary.
*********************************************************************/
/* static */
void
OSKext::registerKextsWithDTrace(void)
{
    uint32_t count = sLoadedKexts->getCount();
    uint32_t i;

    IORecursiveLockLock(sKextLock);

    for (i = 0; i < count; i++) {
        OSKext   * thisKext     = NULL;  // do not release

        thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (!thisKext || !thisKext->isExecutable()) {
            continue;
        }

        thisKext->registerWithDTrace();
    }

    IORecursiveLockUnlock(sKextLock);

    return;
}

extern "C" {
    extern int (*dtrace_modload)(struct kmod_info *, uint32_t);
    extern int (*dtrace_modunload)(struct kmod_info *);
};

/*********************************************************************
*********************************************************************/
void
OSKext::registerWithDTrace(void)
{
   /* Register kext with dtrace. A dtrace_modload failure should not
    * prevent a kext from loading, so we ignore the return code.
    */
    if (!flags.dtraceInitialized && (dtrace_modload != NULL)) {
        uint32_t modflag = 0;
        OSObject * forceInit = getPropertyForHostArch("OSBundleForceDTraceInit");
        if (forceInit == kOSBooleanTrue) {
            modflag |= KMOD_DTRACE_FORCE_INIT;
        }

        (void)(*dtrace_modload)(kmod_info, modflag);
        flags.dtraceInitialized = true;
        jettisonLinkeditSegment();
    }
    return;
}
/*********************************************************************
*********************************************************************/
void
OSKext::unregisterWithDTrace(void)
{
   /* Unregister kext with dtrace. A dtrace_modunload failure should not
    * prevent a kext from loading, so we ignore the return code.
    */
    if (flags.dtraceInitialized && (dtrace_modunload != NULL)) {
        (void)(*dtrace_modunload)(kmod_info);
        flags.dtraceInitialized = false;
    }
    return;
}
#endif /* CONFIG_DTRACE */


/*********************************************************************
* called only by loadExecutable()
*********************************************************************/
#if !VM_MAPPED_KEXTS
#if defined(__arm__) || defined(__arm64__)
static inline kern_return_t
OSKext_protect(
    vm_map_t   map,
    vm_map_offset_t    start,
    vm_map_offset_t    end,
    vm_prot_t  new_prot,
    boolean_t  set_max)
{
#pragma unused(map)
    assert(map == kernel_map); // we can handle KEXTs arising from the PRELINK segment and no others
    assert(start <= end);
    if (start >= end)
        return KERN_SUCCESS; // Punt segments of length zero (e.g., headers) or less (i.e., blunders)
    else if (set_max)
        return KERN_SUCCESS; // Punt set_max, as there's no mechanism to record that state
    else
        return ml_static_protect(start, end - start, new_prot);
}

static inline kern_return_t
OSKext_wire(
    vm_map_t   map,
    vm_map_offset_t    start,
    vm_map_offset_t    end,
    vm_prot_t  access_type,
    boolean_t       user_wire)
{
#pragma unused(map,start,end,access_type,user_wire)
	return KERN_SUCCESS; // No-op as PRELINK kexts are cemented into physical memory at boot
}
#else
#error Unrecognized architecture 
#endif
#else
static inline kern_return_t
OSKext_protect(
    vm_map_t   map,
    vm_map_offset_t    start,
    vm_map_offset_t    end,
    vm_prot_t  new_prot,
    boolean_t  set_max)
{
    if (start == end) { // 10538581
        return(KERN_SUCCESS);
    }
    return vm_map_protect(map, start, end, new_prot, set_max);
}

static inline kern_return_t
OSKext_wire(
    vm_map_t   map,
    vm_map_offset_t    start,
    vm_map_offset_t    end,
    vm_prot_t  access_type,
    boolean_t       user_wire)
{
	return vm_map_wire_kernel(map, start, end, access_type, VM_KERN_MEMORY_KEXT, user_wire);
}
#endif

OSReturn
OSKext::setVMAttributes(bool protect, bool wire)
{
    vm_map_t                    kext_map        = NULL;
    kernel_segment_command_t  * seg             = NULL;
    vm_map_offset_t             start           = 0;
    vm_map_offset_t             end             = 0;
    OSReturn                    result          = kOSReturnError;

    if (isInterface() || !declaresExecutable()) {
        result = kOSReturnSuccess;
        goto finish;
    }

    /* Get the kext's vm map */
    kext_map = kext_get_vm_map(kmod_info);
    if (!kext_map) {
        result = KERN_MEMORY_ERROR;
        goto finish;
    }

#if !VM_MAPPED_KEXTS
    if (getcommandfromheader((kernel_mach_header_t *)kmod_info->address, LC_SEGMENT_SPLIT_INFO)) {
         /* This is a split kext in a prelinked kernelcache; we'll let the
          * platform code take care of protecting it.  It is already wired.
          */
         /* TODO: Should this still allow protections for the first segment
          * to go through, in the event that we have a mix of split and
          * unsplit kexts?
          */
        result = KERN_SUCCESS;
        goto finish;
    }
#endif

    /* Protect the headers as read-only; they do not need to be wired */
    result = (protect) ? OSKext_protect(kext_map, kmod_info->address, 
        kmod_info->address + kmod_info->hdr_size, VM_PROT_READ, TRUE)
            : KERN_SUCCESS;
    if (result != KERN_SUCCESS) {
        goto finish;
    }

    /* Set the VM protections and wire down each of the segments */
    seg = firstsegfromheader((kernel_mach_header_t *)kmod_info->address);
    while (seg) {

#if __arm__
        /* We build all ARM kexts, so we can ensure they are aligned */
        assert((seg->vmaddr & PAGE_MASK) == 0);
        assert((seg->vmsize & PAGE_MASK) == 0);
#endif

        start = round_page(seg->vmaddr);
        end = trunc_page(seg->vmaddr + seg->vmsize);

        if (protect) {
            result = OSKext_protect(kext_map, start, end, seg->maxprot, TRUE);
            if (result != KERN_SUCCESS) {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Kext %s failed to set maximum VM protections "
                    "for segment %s - 0x%x.",
                    getIdentifierCString(), seg->segname, (int)result);
                goto finish;
            }

            result = OSKext_protect(kext_map, start, end, seg->initprot, FALSE);
            if (result != KERN_SUCCESS) {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Kext %s failed to set initial VM protections "
                    "for segment %s - 0x%x.",
                    getIdentifierCString(), seg->segname, (int)result);
                goto finish;
            }
        }

        if (segmentShouldBeWired(seg) && wire) {
            result = OSKext_wire(kext_map, start, end, seg->initprot, FALSE);
            if (result != KERN_SUCCESS) {
                goto finish;
            }
        }

        seg = nextsegfromheader((kernel_mach_header_t *) kmod_info->address, seg);
    }

finish:
    return result;
}

/*********************************************************************
*********************************************************************/
boolean_t 
OSKext::segmentShouldBeWired(kernel_segment_command_t *seg)
{
    return (sKeepSymbols || strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)));
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
    kernel_segment_command_t            * seg         = NULL;
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
    if (getcommandfromheader((kernel_mach_header_t *)kmod_info->address, LC_SEGMENT_SPLIT_INFO)) { 
       /* This will likely be how we deal with split kexts; walk the segments to
        * check that the function lies inside one of the segments of this kext.
        */
        for (seg = firstsegfromheader((kernel_mach_header_t *)kmod_info->address);
             seg != NULL;
             seg = nextsegfromheader((kernel_mach_header_t *)kmod_info->address, seg)) {
            if ((address >= seg->vmaddr) && address < (seg->vmaddr + seg->vmsize)) {
                break;
            }
        }

        if (!seg) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s module %s pointer is outside of kext range "
                "(%s %p - kext starts at %p).",
                getIdentifierCString(),
                whichOp,
                whichOp,
                (void *)VM_KERNEL_UNSLIDE(address),
                (void *)VM_KERNEL_UNSLIDE(kmod_info->address));
            result = kOSKextReturnBadData;
            goto finish;
        }

        seg = NULL;
    } else {
        if (address < kmod_info->address + kmod_info->hdr_size ||
            kmod_info->address + kmod_info->size <= address)
        {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s module %s pointer is outside of kext range "
                "(%s %p - kext at %p-%p).",
                getIdentifierCString(),
                whichOp,
                whichOp,
                (void *)VM_KERNEL_UNSLIDE(address),
                (void *)VM_KERNEL_UNSLIDE(kmod_info->address),
                (void *)(VM_KERNEL_UNSLIDE(kmod_info->address) + kmod_info->size));
            result = kOSKextReturnBadData;
            goto finish;
        }
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
                whichOp, (void *)VM_KERNEL_UNSLIDE(address)); 
            result = kOSKextReturnBadData;
            goto finish;
        }

#if VM_MAPPED_KEXTS
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
#endif

       /* Verify that the kext's segments are backed by physical memory.
        */
        seg = firstsegfromheader((kernel_mach_header_t *)kmod_info->address);
        while (seg) {
            if (!verifySegmentMapping(seg)) {
                result = kOSKextReturnBadData;
                goto finish;
            }

            seg = nextsegfromheader((kernel_mach_header_t *) kmod_info->address, seg);
        }

    }

    result = kOSReturnSuccess;
finish:
    return result;
}

/*********************************************************************
*********************************************************************/
boolean_t
OSKext::verifySegmentMapping(kernel_segment_command_t *seg)
{
    mach_vm_address_t address = 0;

    if (!segmentShouldBeWired(seg)) return true;

    for (address = seg->vmaddr;
         address < round_page(seg->vmaddr + seg->vmsize);
         address += PAGE_SIZE)
    {
        if (!pmap_find_phys(kernel_pmap, (vm_offset_t)address)) {
            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogLoadFlag,
                "Kext %s - page %p is not backed by physical memory.",
                getIdentifierCString(), 
                (void *)address);
            return false;
        }
    }

    return true;
}

/*********************************************************************
*********************************************************************/
static void
OSKextLogKextInfo(OSKext *aKext, uint64_t address, uint64_t size, firehose_tracepoint_code_t code)
{

    uint64_t                            stamp = 0;
    firehose_tracepoint_id_u            trace_id;
    struct firehose_trace_uuid_info_s   uuid_info_s;
    firehose_trace_uuid_info_t          uuid_info = &uuid_info_s;
    size_t                              uuid_info_len = sizeof(struct firehose_trace_uuid_info_s);
    OSData                              *uuid_data;

    stamp = firehose_tracepoint_time(firehose_activity_flags_default);
    trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_metadata, _firehose_tracepoint_type_metadata_kext, (firehose_tracepoint_flags_t)0, code);

    uuid_data = aKext->copyUUID();
    if (uuid_data) {
        memcpy(uuid_info->ftui_uuid, uuid_data->getBytesNoCopy(), sizeof(uuid_info->ftui_uuid));
        OSSafeReleaseNULL(uuid_data);
    }

    uuid_info->ftui_size    = size;
    uuid_info->ftui_address = VM_KERNEL_UNSLIDE(address);

    firehose_trace_metadata(firehose_stream_metadata, trace_id, stamp, uuid_info, uuid_info_len);
    return;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::start(bool startDependenciesFlag)
{
    OSReturn                            result = kOSReturnError;
    kern_return_t                       (* startfunc)(kmod_info_t *, void *);
    unsigned int                        i, count;
    void                              * kmodStartData = NULL; 

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

    OSKextLog(this,
        kOSKextLogDetailLevel |
        kOSKextLogLoadFlag,
        "Kext %s calling module start function.",
        getIdentifierCString()); 

    flags.starting = 1;

    // Drop a log message so logd can grab the needed information to decode this kext
    OSKextLogKextInfo(this, kmod_info->address, kmod_info->size, firehose_tracepoint_code_load);

#if !CONFIG_STATIC_CPPINIT
    result = OSRuntimeInitializeCPP(kmod_info, NULL);
    if (result == KERN_SUCCESS) {
#endif

#if CONFIG_KEC_FIPS
        kmodStartData = GetAppleTEXTHashForKext(this, this->infoDict);
        
#if 0
        if (kmodStartData) {
            OSKextLog(this,
                      kOSKextLogErrorLevel |
                      kOSKextLogGeneralFlag,
                      "Kext %s calling module start function. kmodStartData %p. arch %s",
                      getIdentifierCString(), kmodStartData, ARCHNAME); 
        }
#endif
#endif // CONFIG_KEC_FIPS 
        result = startfunc(kmod_info, kmodStartData);

#if !CONFIG_STATIC_CPPINIT
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

    stopfunc = kmod_info->stop;
    if (stopfunc) {
        OSKextLog(this,
            kOSKextLogDetailLevel |
            kOSKextLogLoadFlag,
            "Kext %s calling module stop function.",
            getIdentifierCString()); 

        flags.stopping = 1;

        result = stopfunc(kmod_info, /* userData */ NULL);
#if !CONFIG_STATIC_CPPINIT
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
    // Drop a log message so logd can update this kext's metadata
    OSKextLogKextInfo(this, kmod_info->address, kmod_info->size, firehose_tracepoint_code_unload);
    return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::unload(void)
{
    OSReturn        result = kOSReturnError;
    unsigned int    index;
    uint32_t        num_kmod_refs = 0;
    OSKextAccount * freeAccount;

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

    if (!isLoaded()) {
        result = kOSReturnSuccess;
        goto finish;
    }

    if (isKernelComponent()) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

    if (metaClasses && !OSMetaClass::removeClasses(metaClasses)) {
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
    
   /* Note that the kext is unloading before running any code that
    * might be in the kext (request callbacks, module stop function).
    * We will deny certain requests made against a kext in the process
    * of unloading.
    */
    flags.unloading = 1;

   /* Update the string describing the last kext to unload in case we panic.
    */
    savePanicString(/* isLoading */ false);
    
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

    {
        struct list_head *p;
        struct list_head *prev;
        struct list_head *next;
        for (p = pendingPgoHead.next; p != &pendingPgoHead; p = next) {
            OSKextGrabPgoStruct *s = container_of(p, OSKextGrabPgoStruct, list_head);
            s->err = OSKextGrabPgoDataLocked(this, s->metadata, instance_uuid, s->pSize, s->pBuffer, s->bufferSize);
            prev = p->prev;
            next = p->next;
            prev->next = next;
            next->prev = prev;
            p->prev = p;
            p->next = p;
            IORecursiveLockWakeup(sKextLock, s, false);
        }
    }


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
        if (lastKext && !lastKext->isKernel()) {
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

#if CONFIG_DTRACE
    unregisterWithDTrace();
#endif /* CONFIG_DTRACE */

    notifyKextUnloadObservers(this);

    freeAccount = NULL;
    IOSimpleLockLock(sKextAccountsLock);
    account->kext = NULL;
    if (account->site.tag) account->site.flags |= VM_TAG_UNLOAD;
    else                   freeAccount = account;
    IOSimpleLockUnlock(sKextAccountsLock);
    if (freeAccount) IODelete(freeAccount, OSKextAccount, 1);

    /* Unwire and free the linked executable.
     */
    if (linkedExecutable) {
#if KASAN
        kasan_unload_kext((vm_offset_t)linkedExecutable->getBytesNoCopy(), linkedExecutable->getLength());
#endif

#if VM_MAPPED_KEXTS
        if (!isInterface()) {
            kernel_segment_command_t *seg = NULL;
            vm_map_t kext_map = kext_get_vm_map(kmod_info);

            if (!kext_map) {
                OSKextLog(this,
                    kOSKextLogErrorLevel |
                    kOSKextLogLoadFlag,
                    "Failed to free kext %s; couldn't find the kext map.",
                    getIdentifierCString());
                result = kOSKextReturnInternalError;
                goto finish;
            }

            OSKextLog(this,
                kOSKextLogProgressLevel |
                kOSKextLogLoadFlag,
                "Kext %s unwiring and unmapping linked executable.",
                getIdentifierCString());

            seg = firstsegfromheader((kernel_mach_header_t *)kmod_info->address);
            while (seg) {
                if (segmentShouldBeWired(seg)) {
                    result = vm_map_unwire(kext_map, seg->vmaddr, 
                        seg->vmaddr + seg->vmsize, FALSE);
                    if (result != KERN_SUCCESS) {
                        OSKextLog(this,
                            kOSKextLogErrorLevel |
                            kOSKextLogLoadFlag,
                            "Failed to unwire kext %s.",
                            getIdentifierCString());
                        result = kOSKextReturnInternalError;
                        goto finish;
                    }
                }

                seg = nextsegfromheader((kernel_mach_header_t *) kmod_info->address, seg);
            }
        }
#endif
        OSSafeReleaseNULL(linkedExecutable);
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

    /* save a copy of the bundle ID for us to check when deciding to 
     * rebuild the kernel cache file.  If a kext was already in the kernel 
     * cache and unloaded then later loaded we do not need to rebuild the 
     * kernel cache.  9055303
     */
    if (isPrelinked()) {
        if (!_OSKextInUnloadedPrelinkedKexts(bundleID)) {
            IORecursiveLockLock(sKextLock);
            if (sUnloadedPrelinkedKexts) {
                sUnloadedPrelinkedKexts->setObject(bundleID);
            }
            IORecursiveLockUnlock(sKextLock);
        }
    }

    OSKextLog(this,
        kOSKextLogProgressLevel | kOSKextLogLoadFlag,
        "Kext %s unloaded.", getIdentifierCString());

    queueKextNotification(kKextRequestPredicateUnloadNotification,
        OSDynamicCast(OSString, bundleID));

finish:
    OSKext::saveLoadedKextPanicList();
    OSKext::updateLoadedKextSummaries();

    flags.unloading = 0;
    return result;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::queueKextNotification(
    const char * notificationName,
    OSString   * kextIdentifier)
{
    OSReturn          result               = kOSReturnError;
    OSDictionary    * loadRequest          = NULL;  // must release

    if (!kextIdentifier) {
        result = kOSKextReturnInvalidArgument;
        goto finish;
    }

   /* Create a new request unless one is already sitting
    * in sKernelRequests for this bundle identifier
    */
    result = _OSKextCreateRequest(notificationName, &loadRequest);
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

   /* We might want to only queue the notification if kextd is active,
    * but that wouldn't work for embedded. Note that we don't care if
    * the ping immediately succeeds here so don't do anything with the
    * result of this call.
    */
    OSKext::pingKextd();

    result = kOSReturnSuccess;

finish:
    OSSafeReleaseNULL(loadRequest);

    return result;
}

/*********************************************************************
*********************************************************************/
static void
_OSKextConsiderDestroyingLinkContext(
    __unused thread_call_param_t p0,
    __unused thread_call_param_t p1)
{
   /* Take multiple locks in the correct order.
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
* This function must be invoked with sKextInnerLock held.
* Do not call any function that takes sKextLock here!
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

#if PRAGMA_MARK
#pragma mark Autounload
#endif
/*********************************************************************
* This is a static method because the kext will be deallocated if it
* does unload!
*********************************************************************/
/* static */
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

   /* Take multiple locks in the correct order
    * (note also sKextSummaries lock further down).
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
              kOSKextLogProgressLevel | kOSKextLogLoadFlag,
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
            
            if (stale == kOSBooleanTrue) {
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
                didUnload |= (kOSReturnSuccess == OSKext::autounloadKext(thisKext));
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

    /* we only reset delay value for unloading if we already have something
     * pending.  rescheduleOnlyFlag should not start the count down.
     */
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

IOReturn OSKextSystemSleepOrWake(UInt32 messageType);
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
        AbsoluteTime_to_scalar(&sLastWakeTime) = 0;
    } else if (messageType == kIOMessageSystemHasPoweredOn) {
        sSystemSleep = false;
        clock_get_uptime(&sLastWakeTime);
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
    static bool     requestedPrelink        = false;
    OSReturn        checkResult             = kOSReturnError;
    OSDictionary *  prelinkRequest          = NULL;  // must release
    OSCollectionIterator * kextIterator     = NULL;  // must release
    const OSSymbol * thisID                 = NULL;  // do not release
    bool            doRebuild               = false;
    AbsoluteTime    my_abstime;
    UInt64          my_ns;
    SInt32          delta_secs;
    
    /* Only one auto rebuild per boot and only on boot from prelinked kernel */
    if (requestedPrelink || !sPrelinkBoot) {
        return;
    }
    
    /* no direct return from this point */
    IORecursiveLockLock(sKextLock);
    
    /* We need to wait for kextd to get up and running with unloads already done
     * and any new startup kexts loaded.   
     */
    if (!sConsiderUnloadsExecuted ||
        !sDeferredLoadSucceeded) {
        goto finish;
    }
    
    /* we really only care about boot / system start up related kexts so bail 
     * if we're here after REBUILD_MAX_TIME.
     */
    if (!_OSKextInPrelinkRebuildWindow()) {
        OSKextLog(/* kext */ NULL,
                  kOSKextLogArchiveFlag,
                  "%s prebuild rebuild has expired",
                  __FUNCTION__);
        requestedPrelink = true;
        goto finish;
    }
    
    /* we do not want to trigger a rebuild if we get here too close to waking
     * up.  (see radar 10233768)
     */
    IORecursiveLockLock(sKextInnerLock);
    
    clock_get_uptime(&my_abstime);
    delta_secs = MINIMUM_WAKEUP_SECONDS + 1;
    if (AbsoluteTime_to_scalar(&sLastWakeTime) != 0) {
        SUB_ABSOLUTETIME(&my_abstime, &sLastWakeTime);
        absolutetime_to_nanoseconds(my_abstime, &my_ns);
        delta_secs = (SInt32)(my_ns / NSEC_PER_SEC);
    }
    IORecursiveLockUnlock(sKextInnerLock);
    
    if (delta_secs < MINIMUM_WAKEUP_SECONDS) {
        /* too close to time of last wake from sleep */
        goto finish;
    }
    requestedPrelink = true;
    
    /* Now it's time to see if we have a reason to rebuild.  We may have done 
     * some loads and unloads but the kernel cache didn't actually change.
     * We will rebuild if any kext is not marked prelinked AND is not in our
     * list of prelinked kexts that got unloaded.  (see radar 9055303)
     */
    kextIterator = OSCollectionIterator::withCollection(sKextsByID);
    if (!kextIterator) {
        goto finish;
    }
    
    while ((thisID = OSDynamicCast(OSSymbol, kextIterator->getNextObject()))) {
        OSKext *    thisKext;  // do not release
        
        thisKext = OSDynamicCast(OSKext, sKextsByID->getObject(thisID));
        if (!thisKext || thisKext->isPrelinked() || thisKext->isKernel()) {
            continue;
        }
        
        if (_OSKextInUnloadedPrelinkedKexts(thisKext->bundleID)) {
            continue;
        }
        /* kext is loaded and was not in current kernel cache so let's rebuild
         */
        doRebuild = true;
        OSKextLog(/* kext */ NULL,
                  kOSKextLogArchiveFlag,
                  "considerRebuildOfPrelinkedKernel %s triggered rebuild",
                  thisKext->bundleID->getCStringNoCopy());
        break;
    }
    sUnloadedPrelinkedKexts->flushCollection();
    
    if (!doRebuild) {
        goto finish;
    }
    
    checkResult = _OSKextCreateRequest(kKextRequestPredicateRequestPrelink,
                                       &prelinkRequest);
    if (checkResult != kOSReturnSuccess) {
        goto finish;
    }
    
    if (!sKernelRequests->setObject(prelinkRequest)) {
        goto finish;
    }
    
    OSKext::pingKextd();
    
finish:
    IORecursiveLockUnlock(sKextLock);
    OSSafeReleaseNULL(prelinkRequest);
    OSSafeReleaseNULL(kextIterator);
    
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

       /* If a nonprelinked library somehow got into the mix for a
        * prelinked kext, at any point in the chain, we must fail
        * because the prelinked relocs for the library will be all wrong.
        */
        if (this->isPrelinked() &&
            libraryKext->declaresExecutable() &&
            !libraryKext->isPrelinked()) {

            OSKextLog(this,
                kOSKextLogErrorLevel |
                kOSKextLogDependenciesFlag,
                "Kext %s (prelinked) - library kext %s (v%s) not prelinked.",
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
    
    if (hasRawKernelDependency) {
        OSKextLog(this,
            kOSKextLogErrorLevel |
            kOSKextLogValidationFlag | kOSKextLogDependenciesFlag,
            "Error - kext %s declares a dependency on %s, which is not permitted.",
            getIdentifierCString(), KERNEL_LIB);
        goto finish;
    }
#if __LP64__
    if (hasKernelDependency) {
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

    if (hasKernelDependency && hasKPIDependency) {
        OSKextLog(this,
            kOSKextLogWarningLevel |
            kOSKextLogDependenciesFlag,
            "Warning - kext %s has immediate dependencies on both "
            "%s* and %s* components; use only one style.",
            getIdentifierCString(), KERNEL_LIB, KPI_LIB_PREFIX);
    }

    if (!hasKernelDependency && !hasKPIDependency) {
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
    if (!hasKPIDependency) {
        unsigned int i;

        flags.hasBleedthrough = true;

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

    OSSafeReleaseNULL(localLoopStack);
    OSSafeReleaseNULL(libraryIterator);

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

    notifyAddClassObservers(this, aClass, flags);

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
    
    notifyRemoveClassObservers(this, aClass, flags);

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
    
    OSSafeReleaseNULL(classIterator);
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
    OSSafeReleaseNULL(theKext);
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
    OSSafeReleaseNULL(classIterator);
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

    OSObject     * parsedXML          = NULL;  // must release
    OSDictionary * requestDict        = NULL;  // do not release
    OSString     * errorString        = NULL;  // must release

    OSObject     * responseObject     = NULL;  // must release
    
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
        /* must be root to use these kext requests */
        if (predicate->isEqualTo(kKextRequestPredicateUnload) ||
            predicate->isEqualTo(kKextRequestPredicateStart) ||
            predicate->isEqualTo(kKextRequestPredicateStop) ||
            predicate->isEqualTo(kKextRequestPredicateGetKernelRequests) ||
            predicate->isEqualTo(kKextRequestPredicateSendResource) ) {
            OSKextLog(/* kext */ NULL,
                      kOSKextLogErrorLevel |
                      kOSKextLogIPCFlag,
                      "Access Failure - must be root user.");
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

    } else if (predicate->isEqualTo(kKextRequestPredicateGetUUIDByAddress)) {

         OSNumber     *lookupNum   = NULL;
         lookupNum = OSDynamicCast(OSNumber,
              _OSKextGetRequestArgument(requestDict,
                  kKextRequestArgumentLookupAddressKey));

         responseObject = OSKext::copyKextUUIDForAddress(lookupNum);
         if (responseObject) {
             result = kOSReturnSuccess;
         } else {
             goto finish;
         }

    } else if (predicate->isEqualTo(kKextRequestPredicateGetLoaded) ||
               predicate->isEqualTo(kKextRequestPredicateGetLoadedByUUID)) {
        OSBoolean    * delayAutounloadBool = NULL;
        OSObject     * infoKeysRaw         = NULL;
        OSArray      * infoKeys            = NULL;
        uint32_t       infoKeysCount       = 0;
        
        delayAutounloadBool = OSDynamicCast(OSBoolean,
            _OSKextGetRequestArgument(requestDict,
                kKextRequestArgumentDelayAutounloadKey));

       /* If asked to delay autounload, reset the timer if it's currently set.
        * (That is, don't schedule an unload if one isn't already pending.
        */
        if (delayAutounloadBool == kOSBooleanTrue) {
            OSKext::considerUnloads(/* rescheduleOnly? */ true);
        }

        infoKeysRaw = _OSKextGetRequestArgument(requestDict,
                kKextRequestArgumentInfoKeysKey);
        infoKeys = OSDynamicCast(OSArray, infoKeysRaw);
        if (infoKeysRaw && !infoKeys) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Invalid arguments to kext info request.");
            goto finish;
        }
        
        if (infoKeys) {
            infoKeysCount = infoKeys->getCount();
            for (uint32_t i = 0; i < infoKeysCount; i++) {
                if (!OSDynamicCast(OSString, infoKeys->getObject(i))) {
                    OSKextLog(/* kext */ NULL,
                        kOSKextLogErrorLevel |
                        kOSKextLogIPCFlag,
                        "Invalid arguments to kext info request.");
                    goto finish;
                }
            }
        }

        if (predicate->isEqualTo(kKextRequestPredicateGetLoaded)) {
             responseObject = OSKext::copyLoadedKextInfo(kextIdentifiers, infoKeys);
        }
        else if (predicate->isEqualTo(kKextRequestPredicateGetLoadedByUUID)) {
             responseObject = OSKext::copyLoadedKextInfoByUUID(kextIdentifiers, infoKeys);
        }
        if (!responseObject) {
            result = kOSKextReturnInternalError;
        } else {
            OSKextLog(/* kext */ NULL,
                kOSKextLogDebugLevel |
                kOSKextLogIPCFlag,
                "Returning loaded kext info.");
            result = kOSReturnSuccess;
        }
    } else if (predicate->isEqualTo(kKextRequestPredicateGetKernelRequests)) {

       /* Hand the current sKernelRequests array to the caller
        * (who must release it), and make a new one.
        */
        responseObject = sKernelRequests;
        sKernelRequests = OSArray::withCapacity(0);
        sPostedKextLoadIdentifiers->flushCollection();
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogIPCFlag,
            "Returning kernel requests.");
        result = kOSReturnSuccess;

    } else if (predicate->isEqualTo(kKextRequestPredicateGetAllLoadRequests)) {
        
        /* Return the set of all requested bundle identifiers */
        responseObject = sAllKextLoadIdentifiers;
        responseObject->retain();
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogIPCFlag,
            "Returning load requests.");
        result = kOSReturnSuccess;
    }
    else {
        OSKextLog(/* kext */ NULL,
                  kOSKextLogDebugLevel |
                  kOSKextLogIPCFlag,
                  "Received '%s' invalid request from user space.",
                  predicate->getCStringNoCopy());
        goto finish;
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

    if (responseOut && responseObject) {
        serializer = OSSerialize::withCapacity(0);
        if (!serializer) {
            result = kOSKextReturnNoMemory;
            goto finish;
        }

        if (!responseObject->serialize(serializer)) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
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
            round_page(responseLength), VM_KERN_MEMORY_OSKEXT);
        if (kmem_result != KERN_SUCCESS) {
            OSKextLog(/* kext */ NULL,
                kOSKextLogErrorLevel |
                kOSKextLogIPCFlag,
                "Failed to copy response to request from user space.");
            result = kmem_result;
            goto finish;
        } else {
            /* 11981737 - clear uninitialized data in last page */
            bzero((void *)(buffer + responseLength),
                  (round_page(responseLength) - responseLength));
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

    OSSafeReleaseNULL(parsedXML);
    OSSafeReleaseNULL(errorString);
    OSSafeReleaseNULL(responseObject);
    OSSafeReleaseNULL(serializer);
    OSSafeReleaseNULL(logInfoArray);

    return result;
}


// #include <InstrProfiling.h>
extern "C" {

    uint64_t __llvm_profile_get_size_for_buffer_internal(const char *DataBegin,
                                                         const char *DataEnd,
                                                         const char *CountersBegin,
                                                         const char *CountersEnd ,
                                                         const char *NamesBegin,
                                                         const char *NamesEnd);
    int __llvm_profile_write_buffer_internal(char *Buffer,
                                             const char *DataBegin,
                                             const char *DataEnd,
                                             const char *CountersBegin,
                                             const char *CountersEnd ,
                                             const char *NamesBegin,
                                             const char *NamesEnd);
}


static
void OSKextPgoMetadataPut(char *pBuffer,
                          size_t *position,
                          size_t bufferSize,
                          uint32_t *num_pairs,
                          const char *key,
                          const char *value)
{
    size_t strlen_key = strlen(key);
    size_t strlen_value = strlen(value);
    size_t len = strlen(key) + 1 + strlen(value) + 1;
    char *pos = pBuffer + *position;
    *position += len;
    if (pBuffer && bufferSize && *position <= bufferSize) {
        memcpy(pos, key, strlen_key); pos += strlen_key;
        *(pos++) = '=';
        memcpy(pos, value, strlen_value); pos += strlen_value;
        *(pos++) = 0;
        if (num_pairs) {
            (*num_pairs)++;
        }
    }
}


static
void OSKextPgoMetadataPutMax(size_t *position, const char *key, size_t value_max)
{
    *position += strlen(key) + 1 + value_max + 1;
}


static
void OSKextPgoMetadataPutAll(OSKext *kext,
                             uuid_t instance_uuid,
                             char *pBuffer,
                             size_t *position,
                             size_t bufferSize,
                             uint32_t *num_pairs)
{
    _static_assert_1_arg(sizeof(clock_sec_t) % 2 == 0);
    //log_10 2^16 ≈ 4.82
    const size_t max_secs_string_size = 5 * sizeof(clock_sec_t)/2;
    const size_t max_timestamp_string_size = max_secs_string_size + 1 + 6;

    if (!pBuffer) {
        OSKextPgoMetadataPutMax(position, "INSTANCE", 36);
        OSKextPgoMetadataPutMax(position, "UUID", 36);
        OSKextPgoMetadataPutMax(position, "TIMESTAMP", max_timestamp_string_size);
    } else {
        uuid_string_t instance_uuid_string;
        uuid_unparse(instance_uuid, instance_uuid_string);
        OSKextPgoMetadataPut(pBuffer, position, bufferSize, num_pairs,
                             "INSTANCE", instance_uuid_string);

        OSData *uuid_data;
        uuid_t uuid;
        uuid_string_t uuid_string;
        uuid_data = kext->copyUUID();
        if (uuid_data) {
            memcpy(uuid, uuid_data->getBytesNoCopy(), sizeof(uuid));
            OSSafeReleaseNULL(uuid_data);
            uuid_unparse(uuid, uuid_string);
            OSKextPgoMetadataPut(pBuffer, position, bufferSize, num_pairs,
                                 "UUID", uuid_string);
        }

        clock_sec_t secs;
        clock_usec_t usecs;
        clock_get_calendar_microtime(&secs, &usecs);
        assert(usecs < 1000000);
        char timestamp[max_timestamp_string_size + 1];
        _static_assert_1_arg(sizeof(long) >= sizeof(clock_sec_t));
        snprintf(timestamp, sizeof(timestamp), "%lu.%06d", (unsigned long)secs, (int)usecs);
        OSKextPgoMetadataPut(pBuffer, position, bufferSize, num_pairs,
                             "TIMESTAMP", timestamp);
    }

    OSKextPgoMetadataPut(pBuffer, position, bufferSize, num_pairs,
                         "NAME", kext->getIdentifierCString());

    char versionCString[kOSKextVersionMaxLength];
    OSKextVersionGetString(kext->getVersion(), versionCString, kOSKextVersionMaxLength);
    OSKextPgoMetadataPut(pBuffer, position, bufferSize, num_pairs,
                         "VERSION", versionCString);

}

static
size_t OSKextPgoMetadataSize(OSKext *kext)
{
    size_t position = 0;
    uuid_t fakeuuid = {};
    OSKextPgoMetadataPutAll(kext, fakeuuid, NULL, &position, 0, NULL);
    return position;
}

int OSKextGrabPgoDataLocked(OSKext *kext,
                            bool metadata,
                            uuid_t instance_uuid,
                            uint64_t *pSize,
                            char *pBuffer,
                            uint64_t bufferSize)
{
    int err = 0;

    kernel_section_t *sect_prf_data = NULL;
    kernel_section_t *sect_prf_name = NULL;
    kernel_section_t *sect_prf_cnts = NULL;
    uint64_t size;
    size_t metadata_size = 0;

    sect_prf_data = kext->lookupSection("__DATA", "__llvm_prf_data");
    sect_prf_name = kext->lookupSection("__DATA", "__llvm_prf_name");
    sect_prf_cnts = kext->lookupSection("__DATA", "__llvm_prf_cnts");

    if (!sect_prf_data || !sect_prf_name || !sect_prf_cnts) {
        err = ENOTSUP;
        goto out;
    }

    size = __llvm_profile_get_size_for_buffer_internal(
                         (const char*) sect_prf_data->addr, (const char*) sect_prf_data->addr + sect_prf_data->size,
                         (const char*) sect_prf_cnts->addr, (const char*) sect_prf_cnts->addr + sect_prf_cnts->size,
                         (const char*) sect_prf_name->addr, (const char*) sect_prf_name->addr + sect_prf_name->size);

    if (metadata) {
        metadata_size = OSKextPgoMetadataSize(kext);
        size += metadata_size;
        size += sizeof(pgo_metadata_footer);
    }


    if (pSize) {
        *pSize = size;
    }

    if (pBuffer && bufferSize) {
        if (bufferSize < size) {
            err = ERANGE;
            goto out;
        }

        err = __llvm_profile_write_buffer_internal(
                    pBuffer,
                    (const char*) sect_prf_data->addr, (const char*) sect_prf_data->addr + sect_prf_data->size,
                    (const char*) sect_prf_cnts->addr, (const char*) sect_prf_cnts->addr + sect_prf_cnts->size,
                    (const char*) sect_prf_name->addr, (const char*) sect_prf_name->addr + sect_prf_name->size);

        if (err) {
            err = EIO;
            goto out;
        }

        if (metadata) {
            char *end_of_buffer = pBuffer + size;
            struct pgo_metadata_footer *footerp = (struct pgo_metadata_footer *) (end_of_buffer - sizeof(struct pgo_metadata_footer));
            char *metadata_buffer = end_of_buffer - (sizeof(struct pgo_metadata_footer) + metadata_size);

            size_t metadata_position = 0;
            uint32_t num_pairs = 0;
            OSKextPgoMetadataPutAll(kext, instance_uuid, metadata_buffer, &metadata_position, metadata_size, &num_pairs);
            while (metadata_position < metadata_size) {
                metadata_buffer[metadata_position++] = 0;
            }

            struct pgo_metadata_footer footer;
            footer.magic = htonl(0x6d657461);
            footer.number_of_pairs = htonl( num_pairs );
            footer.offset_to_pairs = htonl( sizeof(struct pgo_metadata_footer) + metadata_size );
            memcpy(footerp, &footer, sizeof(footer));
        }

    }

out:
    return err;
}


int
OSKextGrabPgoData(uuid_t uuid,
                  uint64_t *pSize,
                  char *pBuffer,
                  uint64_t bufferSize,
                  int wait_for_unload,
                  int metadata)
{
    int err = 0;
    OSKext *kext = NULL;


    IORecursiveLockLock(sKextLock);

    kext = OSKext::lookupKextWithUUID(uuid);
    if (!kext)  {
        err = ENOENT;
        goto out;
    }

    if (wait_for_unload) {
        OSKextGrabPgoStruct s;

        s.metadata = metadata;
        s.pSize = pSize;
        s.pBuffer = pBuffer;
        s.bufferSize = bufferSize;
        s.err = EINTR;

        struct list_head *prev = &kext->pendingPgoHead;
        struct list_head *next = kext->pendingPgoHead.next;

        s.list_head.prev = prev;
        s.list_head.next = next;

        prev->next = &s.list_head;
        next->prev = &s.list_head;

        kext->release();
        kext = NULL;

        IORecursiveLockSleep(sKextLock, &s, THREAD_ABORTSAFE);

        prev = s.list_head.prev;
        next = s.list_head.next;

        prev->next = next;
        next->prev = prev;

        err = s.err;

    } else {
        err = OSKextGrabPgoDataLocked(kext, metadata, kext->instance_uuid, pSize, pBuffer, bufferSize);
    }

 out:
    if (kext) {
        kext->release();
    }

    IORecursiveLockUnlock(sKextLock);

    return err;
}

void
OSKextResetPgoCountersLock()
{
    IORecursiveLockLock(sKextLock);
}

void
OSKextResetPgoCountersUnlock()
{
    IORecursiveLockUnlock(sKextLock);
}


extern unsigned int not_in_kdp;

void
OSKextResetPgoCounters()
{
    assert(!not_in_kdp);
    uint32_t count = sLoadedKexts->getCount();
    for (uint32_t i = 0; i < count; i++) {
        OSKext *kext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        kernel_section_t *sect_prf_cnts = kext->lookupSection("__DATA", "__llvm_prf_cnts");
        if (!sect_prf_cnts) {
            continue;
        }
        memset((void*)sect_prf_cnts->addr, 0, sect_prf_cnts->size);
    }
}

OSDictionary *
OSKext::copyLoadedKextInfoByUUID(
    OSArray * kextIdentifiers,
    OSArray * infoKeys)
{
    OSDictionary * result = NULL;
    OSDictionary * kextInfo = NULL;  // must release
    uint32_t       count, i;
    uint32_t       idCount = 0;
    uint32_t       idIndex = 0;

    IORecursiveLockLock(sKextLock);

#if CONFIG_MACF
    /* Is the calling process allowed to query kext info? */
    if (current_task() != kernel_task) {
        int                 macCheckResult      = 0;
        kauth_cred_t        cred                = NULL;

        cred = kauth_cred_get_with_ref();
        macCheckResult = mac_kext_check_query(cred);
        kauth_cred_unref(&cred);

        if (macCheckResult != 0) {
            OSKextLog(/* kext */ NULL,
                      kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                      "Failed to query kext info (MAC policy error 0x%x).",
                      macCheckResult);
            goto finish;
        }
   }
#endif

   /* Empty list of UUIDs is equivalent to no list (get all).
    */
    if (kextIdentifiers && !kextIdentifiers->getCount()) {
        kextIdentifiers = NULL;
    } else if (kextIdentifiers) {
        idCount = kextIdentifiers->getCount();
    }

   /* Same for keys.
    */
    if (infoKeys && !infoKeys->getCount()) {
        infoKeys = NULL;
    }

    count = sLoadedKexts->getCount();
    result = OSDictionary::withCapacity(count);
    if (!result) {
        goto finish;
    }

    for (i = 0; i < count; i++) {
        OSKext       *thisKext     = NULL;  // do not release
        Boolean       includeThis  = true;
        uuid_t        thisKextUUID;
        OSData       *uuid_data;
        uuid_string_t uuid_key;

        if (kextInfo) {
            kextInfo->release();
            kextInfo = NULL;
        }

        thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (!thisKext) {
            continue;
        }

        uuid_data = thisKext->copyUUID();
        if (!uuid_data) {
            continue;
        }

       memcpy(&thisKextUUID, uuid_data->getBytesNoCopy(), sizeof(thisKextUUID));
       OSSafeReleaseNULL(uuid_data);

       uuid_unparse(thisKextUUID, uuid_key);

       /* Skip current kext if we have a list of UUIDs and
        * it isn't in the list.
        */
        if (kextIdentifiers) {
            includeThis = false;

            for (idIndex = 0; idIndex < idCount; idIndex++) {
                const OSString* wantedUUID = OSDynamicCast(OSString,
                    kextIdentifiers->getObject(idIndex));

                uuid_t uuid;
                uuid_parse(wantedUUID->getCStringNoCopy(), uuid);

                if (0 == uuid_compare(uuid, thisKextUUID)) {
                    includeThis = true;
                    break;
                }

            }
        }

        if (!includeThis) {
            continue;
        }

        kextInfo = thisKext->copyInfo(infoKeys);
        if (kextInfo) {
            result->setObject(uuid_key, kextInfo);
        }
    }

finish:
    IORecursiveLockUnlock(sKextLock);

    if (kextInfo) kextInfo->release();

    return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSDictionary *
OSKext::copyLoadedKextInfo(
    OSArray * kextIdentifiers,
    OSArray * infoKeys) 
{
    OSDictionary * result = NULL;
    OSDictionary * kextInfo = NULL;  // must release
    uint32_t       count, i;
    uint32_t       idCount = 0;
    uint32_t       idIndex = 0;

    IORecursiveLockLock(sKextLock);

#if CONFIG_MACF
    /* Is the calling process allowed to query kext info? */
    if (current_task() != kernel_task) {
        int                 macCheckResult      = 0;
        kauth_cred_t        cred                = NULL;

        cred = kauth_cred_get_with_ref();
        macCheckResult = mac_kext_check_query(cred);
        kauth_cred_unref(&cred);

        if (macCheckResult != 0) {
            OSKextLog(/* kext */ NULL,
                      kOSKextLogErrorLevel | kOSKextLogLoadFlag,
                      "Failed to query kext info (MAC policy error 0x%x).",
                      macCheckResult);
            goto finish;
        }
   }
#endif

   /* Empty list of bundle ids is equivalent to no list (get all).
    */
    if (kextIdentifiers && !kextIdentifiers->getCount()) {
        kextIdentifiers = NULL;
    } else if (kextIdentifiers) {
        idCount = kextIdentifiers->getCount();
    }

   /* Same for keys.
    */
    if (infoKeys && !infoKeys->getCount()) {
        infoKeys = NULL;
    }

    count = sLoadedKexts->getCount();
    result = OSDictionary::withCapacity(count);
    if (!result) {
        goto finish;
    }

#if 0
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_kernel_slide 0x%lx \n",
              vm_kernel_slide);
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_kernel_stext 0x%lx vm_kernel_etext 0x%lx \n",
              vm_kernel_stext, vm_kernel_etext);
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_kernel_base 0x%lx vm_kernel_top 0x%lx \n",
              vm_kernel_base, vm_kernel_top);
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_kext_base 0x%lx vm_kext_top 0x%lx \n",
              vm_kext_base, vm_kext_top);
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_prelink_stext 0x%lx vm_prelink_etext 0x%lx \n",
              vm_prelink_stext, vm_prelink_etext);
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_prelink_sinfo 0x%lx vm_prelink_einfo 0x%lx \n",
              vm_prelink_sinfo, vm_prelink_einfo);
    OSKextLog(/* kext */ NULL,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "kaslr: vm_slinkedit 0x%lx vm_elinkedit 0x%lx \n",
              vm_slinkedit, vm_elinkedit);
#endif

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

        kextInfo = thisKext->copyInfo(infoKeys);
        if (kextInfo) {
            result->setObject(thisKext->getIdentifier(), kextInfo);
        }
    }
    
finish:
    IORecursiveLockUnlock(sKextLock);

    if (kextInfo) kextInfo->release();

    return result;
}

/*********************************************************************
* Any info that needs to do allocations must goto finish on alloc
* failure. Info that is just a lookup should just not set the object
* if the info does not exist.
*********************************************************************/
#define _OSKextLoadInfoDictCapacity   (12)

OSDictionary *
OSKext::copyInfo(OSArray * infoKeys)
{
    OSDictionary         * result                      = NULL;
    bool                   success                     = false;
    OSData               * headerData                  = NULL;  // must release
    OSData               * logData                     = NULL;  // must release
    OSNumber             * cpuTypeNumber               = NULL;  // must release
    OSNumber             * cpuSubtypeNumber            = NULL;  // must release
    OSString             * versionString               = NULL;  // do not release
    uint32_t               executablePathCStringSize   = 0;
    char                 * executablePathCString       = NULL;  // must release
    OSString             * executablePathString        = NULL;  // must release
    OSData               * uuid                        = NULL;  // must release
    OSNumber             * scratchNumber               = NULL;  // must release
    OSArray              * dependencyLoadTags          = NULL;  // must release
    OSCollectionIterator * metaClassIterator           = NULL;  // must release
    OSArray              * metaClassInfo               = NULL;  // must release
    OSDictionary         * metaClassDict               = NULL;  // must release
    OSMetaClass          * thisMetaClass               = NULL;  // do not release
    OSString             * metaClassName               = NULL;  // must release
    OSString             * superclassName              = NULL;  // must release
    uint32_t               count, i;

    result = OSDictionary::withCapacity(_OSKextLoadInfoDictCapacity);
    if (!result) {
        goto finish;
    }

    
   /* Empty keys means no keys, but NULL is quicker to check.
    */
    if (infoKeys && !infoKeys->getCount()) {
        infoKeys = NULL;
    }

   /* Headers, CPU type, and CPU subtype.
    */
    if (!infoKeys ||
        _OSArrayContainsCString(infoKeys, kOSBundleMachOHeadersKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleLogStringsKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleCPUTypeKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleCPUSubtypeKey))
    {

        if (linkedExecutable && !isInterface()) {

            kernel_mach_header_t *kext_mach_hdr = (kernel_mach_header_t *)
                linkedExecutable->getBytesNoCopy();

#if !SECURE_KERNEL
            // do not return macho header info on shipping iOS - 19095897
            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleMachOHeadersKey)) {
                kernel_mach_header_t *  temp_kext_mach_hdr;
                struct load_command *   lcp;

                headerData = OSData::withBytes(kext_mach_hdr,
                    (u_int) (sizeof(*kext_mach_hdr) + kext_mach_hdr->sizeofcmds));
                if (!headerData) {
                    goto finish;
                }

                // unslide any vmaddrs we return to userspace - 10726716
               temp_kext_mach_hdr = (kernel_mach_header_t *)
                    headerData->getBytesNoCopy();
                if (temp_kext_mach_hdr == NULL) {
                    goto finish;
                }

                lcp = (struct load_command *) (temp_kext_mach_hdr + 1);
                for (i = 0; i < temp_kext_mach_hdr->ncmds; i++) {
                    if (lcp->cmd == LC_SEGMENT_KERNEL) {
                        kernel_segment_command_t *  segp;
                        kernel_section_t *          secp;
                        
                        segp = (kernel_segment_command_t *) lcp;
                        // 10543468 - if we jettisoned __LINKEDIT clear size info
                        if (flags.jettisonLinkeditSeg) {
                            if (strncmp(segp->segname, SEG_LINKEDIT, sizeof(segp->segname)) == 0) {
                                segp->vmsize = 0;
                                segp->fileoff = 0;
                                segp->filesize = 0;
                            }
                        }

#if 0
                        OSKextLog(/* kext */ NULL,
                                  kOSKextLogErrorLevel |
                                  kOSKextLogGeneralFlag,
                                  "%s: LC_SEGMENT_KERNEL segname '%s' vmaddr 0x%llX 0x%lX vmsize %llu nsects %u",
                                  __FUNCTION__, segp->segname, segp->vmaddr,
                                  VM_KERNEL_UNSLIDE(segp->vmaddr),
                                  segp->vmsize, segp->nsects);
                        if ( (VM_KERNEL_IS_SLID(segp->vmaddr) == false) &&
                            (VM_KERNEL_IS_KEXT(segp->vmaddr) == false) &&
                            (VM_KERNEL_IS_PRELINKTEXT(segp->vmaddr) == false) &&
                            (VM_KERNEL_IS_PRELINKINFO(segp->vmaddr) == false) &&
                            (VM_KERNEL_IS_KEXT_LINKEDIT(segp->vmaddr) == false) ) {
                            OSKextLog(/* kext */ NULL,
                                      kOSKextLogErrorLevel |
                                      kOSKextLogGeneralFlag,
                                      "%s: not in kext range - vmaddr 0x%llX vm_kext_base 0x%lX vm_kext_top 0x%lX",
                                      __FUNCTION__, segp->vmaddr, vm_kext_base, vm_kext_top);
                        }
#endif
                        segp->vmaddr = VM_KERNEL_UNSLIDE(segp->vmaddr);

                        for (secp = firstsect(segp); secp != NULL; secp = nextsect(segp, secp)) {
                            secp->addr = VM_KERNEL_UNSLIDE(secp->addr);
                        }
                    }
                    lcp = (struct load_command *)((caddr_t)lcp + lcp->cmdsize);
                }
                result->setObject(kOSBundleMachOHeadersKey, headerData);
            }
#endif // SECURE_KERNEL

            if (_OSArrayContainsCString(infoKeys, kOSBundleLogStringsKey)) {
                 osLogDataHeaderRef *header;
                 char headerBytes[offsetof(osLogDataHeaderRef, sections) + NUM_OS_LOG_SECTIONS * sizeof(header->sections[0])];

                 void *os_log_data          = NULL;
                 void *cstring_data         = NULL;
                 unsigned long os_log_size  = 0;
                 unsigned long cstring_size = 0;
                 uint32_t os_log_offset     = 0;
                 uint32_t cstring_offset    = 0;
                 bool res;

                 os_log_data       = getsectdatafromheader(kext_mach_hdr, "__TEXT", "__os_log", &os_log_size);
                 os_log_offset     = getsectoffsetfromheader(kext_mach_hdr, "__TEXT", "__os_log");
                 cstring_data      = getsectdatafromheader(kext_mach_hdr, "__TEXT", "__cstring", &cstring_size);
                 cstring_offset    = getsectoffsetfromheader(kext_mach_hdr, "__TEXT", "__cstring");

                 header             = (osLogDataHeaderRef *) headerBytes;
                 header->version    = OS_LOG_HDR_VERSION;
                 header->sect_count = NUM_OS_LOG_SECTIONS;
                 header->sections[OS_LOG_SECT_IDX].sect_offset  = os_log_offset;
                 header->sections[OS_LOG_SECT_IDX].sect_size    = (uint32_t) os_log_size;
                 header->sections[CSTRING_SECT_IDX].sect_offset = cstring_offset;
                 header->sections[CSTRING_SECT_IDX].sect_size   = (uint32_t) cstring_size;


                 logData = OSData::withBytes(header, (u_int) (sizeof(osLogDataHeaderRef)));
                 if (!logData) {
                      goto finish;
                 }
                 res = logData->appendBytes(&(header->sections[0]), (u_int)(header->sect_count * sizeof(header->sections[0])));
                 if (!res) {
                      goto finish;
                 }
                 if (os_log_data) {
                      res = logData->appendBytes(os_log_data, (u_int)header->sections[OS_LOG_SECT_IDX].sect_size);
                      if (!res) {
                           goto finish;
                      }
                 }
                 if (cstring_data) {
                      res = logData->appendBytes(cstring_data, (u_int)header->sections[CSTRING_SECT_IDX].sect_size);
                      if (!res) {
                           goto finish;
                      }
                 }
                 result->setObject(kOSBundleLogStringsKey, logData);
            }

            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleCPUTypeKey)) {
                cpuTypeNumber = OSNumber::withNumber(
                    (uint64_t) kext_mach_hdr->cputype,
                    8 * sizeof(kext_mach_hdr->cputype));
                if (!cpuTypeNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleCPUTypeKey, cpuTypeNumber);
            }

            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleCPUSubtypeKey)) {
                cpuSubtypeNumber = OSNumber::withNumber(
                    (uint64_t) kext_mach_hdr->cpusubtype,
                    8 * sizeof(kext_mach_hdr->cpusubtype));
                if (!cpuSubtypeNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleCPUSubtypeKey, cpuSubtypeNumber);
            }
        }
    }
    
   /* CFBundleIdentifier. We set this regardless because it's just stupid not to.
    */
    result->setObject(kCFBundleIdentifierKey, bundleID);

   /* CFBundleVersion.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kCFBundleVersionKey)) {
        versionString = OSDynamicCast(OSString,
            getPropertyForHostArch(kCFBundleVersionKey));
        if (versionString) {
            result->setObject(kCFBundleVersionKey, versionString);
        }
    }

   /* OSBundleCompatibleVersion.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleCompatibleVersionKey)) {
        versionString = OSDynamicCast(OSString,
            getPropertyForHostArch(kOSBundleCompatibleVersionKey));
        if (versionString) {
            result->setObject(kOSBundleCompatibleVersionKey, versionString);
        }
    }

   /* Path.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundlePathKey)) {
        if (path) {
            result->setObject(kOSBundlePathKey, path);
        }
    }


   /* OSBundleExecutablePath.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleExecutablePathKey)) {
         if (path && executableRelPath) {

            uint32_t pathLength = path->getLength();  // gets incremented below

            // +1 for slash, +1 for \0
            executablePathCStringSize = pathLength + executableRelPath->getLength() + 2;

            executablePathCString = (char *)kalloc_tag((executablePathCStringSize) *
                sizeof(char), VM_KERN_MEMORY_OSKEXT); // +1 for \0
            if (!executablePathCString) {
                goto finish;
            }
            strlcpy(executablePathCString, path->getCStringNoCopy(),
                executablePathCStringSize);
            executablePathCString[pathLength++] = '/';
            executablePathCString[pathLength++] = '\0';
            strlcat(executablePathCString, executableRelPath->getCStringNoCopy(),
                executablePathCStringSize);

            executablePathString = OSString::withCString(executablePathCString);

            if (!executablePathString) {
                goto finish;
            }

            result->setObject(kOSBundleExecutablePathKey, executablePathString);
        }
    }

   /* UUID, if the kext has one.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleUUIDKey)) {
        uuid = copyUUID();
        if (uuid) {
            result->setObject(kOSBundleUUIDKey, uuid);
        }
    }
    
   /*****
    * OSKernelResource, OSBundleIsInterface, OSBundlePrelinked, OSBundleStarted.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSKernelResourceKey)) {
        result->setObject(kOSKernelResourceKey,
            isKernelComponent() ? kOSBooleanTrue : kOSBooleanFalse);
    }
    
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleIsInterfaceKey)) {
        result->setObject(kOSBundleIsInterfaceKey,
            isInterface() ? kOSBooleanTrue : kOSBooleanFalse);
    }
    
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundlePrelinkedKey)) {
        result->setObject(kOSBundlePrelinkedKey,
            isPrelinked() ? kOSBooleanTrue : kOSBooleanFalse);
    }
    
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleStartedKey)) {
        result->setObject(kOSBundleStartedKey,
            isStarted() ? kOSBooleanTrue : kOSBooleanFalse);
    }

   /* LoadTag (Index).
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleLoadTagKey)) {
        scratchNumber = OSNumber::withNumber((unsigned long long)loadTag,
            /* numBits */ 8 * sizeof(loadTag));
        if (!scratchNumber) {
            goto finish;
        }
        result->setObject(kOSBundleLoadTagKey, scratchNumber);
        OSSafeReleaseNULL(scratchNumber);
    }
    
   /* LoadAddress, LoadSize.
    */
    if (!infoKeys ||
        _OSArrayContainsCString(infoKeys, kOSBundleLoadAddressKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleLoadSizeKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleExecLoadAddressKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleExecLoadSizeKey) ||
        _OSArrayContainsCString(infoKeys, kOSBundleWiredSizeKey))
    {
        if (isInterface() || linkedExecutable) {
           /* These go to userspace via serialization, so we don't want any doubts
            * about their size.
            */
            uint64_t    loadAddress     = 0;
            uint32_t    loadSize        = 0;
            uint32_t    wiredSize       = 0;
            uint64_t    execLoadAddress = 0;
            uint32_t    execLoadSize    = 0;

           /* Interfaces always report 0 load address & size.
            * Just the way they roll.
            *
            * xxx - leaving in # when we have a linkedExecutable...a kernelcomp
            * xxx - shouldn't have one!
            */
            if (linkedExecutable /* && !isInterface() */) {
                kernel_mach_header_t     *mh  = NULL;
                kernel_segment_command_t *seg = NULL;

                loadAddress = (uint64_t)linkedExecutable->getBytesNoCopy();
                mh = (kernel_mach_header_t *)loadAddress;
                loadAddress = VM_KERNEL_UNSLIDE(loadAddress);
                loadSize = linkedExecutable->getLength();

               /* Walk through the kext, looking for the first executable
                * segment in case we were asked for its size/address.
                */
                for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
                    if (seg->initprot & VM_PROT_EXECUTE) {
                        execLoadAddress = VM_KERNEL_UNSLIDE(seg->vmaddr);
                        execLoadSize = seg->vmsize;
                        break;
                    }
                }

               /* If we have a kmod_info struct, calculated the wired size
                * from that. Otherwise it's the full load size.
                */
                if (kmod_info) {
                    wiredSize = loadSize - kmod_info->hdr_size;
                } else {
                    wiredSize = loadSize;
                }
            }

            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleLoadAddressKey)) {
                scratchNumber = OSNumber::withNumber(
                    (unsigned long long)(loadAddress),
                    /* numBits */ 8 * sizeof(loadAddress));
                if (!scratchNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleLoadAddressKey, scratchNumber);
                OSSafeReleaseNULL(scratchNumber);
            }
            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleExecLoadAddressKey)) {
                scratchNumber = OSNumber::withNumber(
                    (unsigned long long)(execLoadAddress),
                    /* numBits */ 8 * sizeof(execLoadAddress));
                if (!scratchNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleExecLoadAddressKey, scratchNumber);
                OSSafeReleaseNULL(scratchNumber);
            }
            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleLoadSizeKey)) {
                scratchNumber = OSNumber::withNumber(
                    (unsigned long long)(loadSize),
                    /* numBits */ 8 * sizeof(loadSize));
                if (!scratchNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleLoadSizeKey, scratchNumber);
                OSSafeReleaseNULL(scratchNumber);
            }
            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleExecLoadSizeKey)) {
                scratchNumber = OSNumber::withNumber(
                    (unsigned long long)(execLoadSize),
                    /* numBits */ 8 * sizeof(execLoadSize));
                if (!scratchNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleExecLoadSizeKey, scratchNumber);
                OSSafeReleaseNULL(scratchNumber);
            }
            if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleWiredSizeKey)) {
                scratchNumber = OSNumber::withNumber(
                    (unsigned long long)(wiredSize),
                    /* numBits */ 8 * sizeof(wiredSize));
                if (!scratchNumber) {
                    goto finish;
                }
                result->setObject(kOSBundleWiredSizeKey, scratchNumber);
                OSSafeReleaseNULL(scratchNumber);
            }
        }
    }

   /* OSBundleDependencies. In descending order for
    * easy compatibility with kextstat(8).
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleDependenciesKey)) {
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
                if (!scratchNumber) {
                    goto finish;
                }
                dependencyLoadTags->setObject(scratchNumber);
            } while (i--);
        }
    }

    OSSafeReleaseNULL(scratchNumber);

   /* OSBundleMetaClasses.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleClassesKey)) {
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
                OSSafeReleaseNULL(scratchNumber);
                OSSafeReleaseNULL(metaClassName);
                OSSafeReleaseNULL(superclassName);

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
                    
               /* Bail if any of the essentials is missing. The root class lacks a superclass,
                * of course.
                */
                if (!metaClassDict || !metaClassName || !scratchNumber) {
                    goto finish;
                }

                metaClassInfo->setObject(metaClassDict);
                metaClassDict->setObject(kOSMetaClassNameKey, metaClassName);
                if (superclassName) {
                    metaClassDict->setObject(kOSMetaClassSuperclassNameKey, superclassName);
                }
                metaClassDict->setObject(kOSMetaClassTrackingCountKey, scratchNumber);
            }
        }
    }
    
   /* OSBundleRetainCount.
    */
    if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleRetainCountKey)) {
        OSSafeReleaseNULL(scratchNumber);
        {
            int kextRetainCount = getRetainCount() - 1;
            if (isLoaded()) {
                kextRetainCount--;
            }
            scratchNumber = OSNumber::withNumber(
                (int)kextRetainCount,
                /* numBits*/ 8 * sizeof(int));
            if (scratchNumber) {
                result->setObject(kOSBundleRetainCountKey, scratchNumber);
            }
        }
    }

    success = true;

finish:
    OSSafeReleaseNULL(headerData);
    OSSafeReleaseNULL(logData);
    OSSafeReleaseNULL(cpuTypeNumber);
    OSSafeReleaseNULL(cpuSubtypeNumber);
    OSSafeReleaseNULL(executablePathString);
    if (executablePathCString) kfree(executablePathCString, executablePathCStringSize);
    OSSafeReleaseNULL(uuid);
    OSSafeReleaseNULL(scratchNumber);
    OSSafeReleaseNULL(dependencyLoadTags);
    OSSafeReleaseNULL(metaClassIterator);
    OSSafeReleaseNULL(metaClassInfo);
    OSSafeReleaseNULL(metaClassDict);
    OSSafeReleaseNULL(metaClassName);
    OSSafeReleaseNULL(superclassName);
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

    /* If requests to user space are disabled, don't go any further */
    if (!sKernelRequestsEnabled) {
        OSKextLog(/* kext */ NULL, 
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "Can't request resource %s for %s - requests to user space are disabled.",
            resourceNameCString,
            kextIdentifierCString);
        result = kOSKextReturnDisabled;
        goto finish;
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

    OSKext::pingKextd();

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
* Assumes sKextLock is held.
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
    OSSafeReleaseNULL(requestTagNum);

    return result;
}

/*********************************************************************
* Assumes sKextLock is held.
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
    return result;
}


/*********************************************************************
* Busy timeout triage
*********************************************************************/
/* static */
bool
OSKext::isWaitingKextd(void)
{
    return sRequestCallbackRecords && sRequestCallbackRecords->getCount();
}

/*********************************************************************
* Assumes sKextLock is held.
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
            "Can't invoke callback for resource request; ");
        goto finish;
    }
    if (!callbackKext->flags.starting && !callbackKext->flags.started) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel | kOSKextLogIPCFlag,
            "Can't invoke kext resource callback; ");
        goto finish;
    }

    (void)callback(requestTag->unsigned32BitValue(),
        (OSReturn)requestResult->unsigned32BitValue(),
        dataPtr, dataLength, context);
        
    result = kOSReturnSuccess;

finish:
    if (callbackKext)   callbackKext->release();
    if (callbackRecord) callbackRecord->release();

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
* Assumes sKextLock is held.
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

    IORecursiveLockLock(sKextLock);
    result = OSKext::dequeueCallbackForRequestTag(requestTag,
        &callbackRecord);
    IORecursiveLockUnlock(sKextLock);

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
* Assumes sKextLock is held.
*********************************************************************/
void
OSKext::invokeOrCancelRequestCallbacks(
    OSReturn callbackResult,
    bool     invokeFlag)
{
    unsigned int count, i;
    
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
    return;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
uint32_t
OSKext::countRequestCallbacks(void)
{
    uint32_t     result = 0;
    unsigned int count, i;
    
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

/*********************************************************************
*********************************************************************/
static bool _OSArrayContainsCString(
    OSArray    * array,
    const char * cString)
{
    bool             result = false;
    const OSSymbol * symbol = NULL;
    uint32_t         count, i;
    
    if (!array || !cString) {
        goto finish;
    }

    symbol = OSSymbol::withCStringNoCopy(cString);
    if (!symbol) {
        goto finish;
    }

    count = array->getCount();
    for (i = 0; i < count; i++) {
        OSObject * thisObject = array->getObject(i);
        if (symbol->isEqualTo(thisObject)) {
            result = true;
            goto finish;
        }
    }

finish:
    if (symbol) symbol->release();
    return result;
}

/*********************************************************************
 * We really only care about boot / system start up related kexts. 
 * We return true if we're less than REBUILD_MAX_TIME since start up,
 * otherwise return false.
 *********************************************************************/
bool _OSKextInPrelinkRebuildWindow(void)
{
    static bool     outside_the_window = false;
    AbsoluteTime    my_abstime;
    UInt64          my_ns;
    SInt32          my_secs;
    
    if (outside_the_window) {
        return(false);
    }
    clock_get_uptime(&my_abstime);
    absolutetime_to_nanoseconds(my_abstime, &my_ns);
    my_secs = (SInt32)(my_ns / NSEC_PER_SEC);
    if (my_secs > REBUILD_MAX_TIME) {
        outside_the_window = true;
        return(false);
    }
    return(true);
}

/*********************************************************************
 *********************************************************************/
bool _OSKextInUnloadedPrelinkedKexts( const OSSymbol * theBundleID )
{
    int unLoadedCount, i;
    bool result = false;
    
    IORecursiveLockLock(sKextLock);
    
    if (sUnloadedPrelinkedKexts == NULL) {
        goto finish;
    }
    unLoadedCount = sUnloadedPrelinkedKexts->getCount();
    if (unLoadedCount == 0) {
        goto finish;
    }
    
    for (i = 0; i < unLoadedCount; i++) {
        const OSSymbol *    myBundleID;     // do not release
        
        myBundleID = OSDynamicCast(OSSymbol, sUnloadedPrelinkedKexts->getObject(i));
        if (!myBundleID) continue;
        if (theBundleID->isEqualTo(myBundleID->getCStringNoCopy())) {
            result = true;
            break;
        }
    }
finish:
    IORecursiveLockUnlock(sKextLock);
    return(result);
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
    OSKextLogSpec   newUserLogFilter,
    bool            captureFlag)
{
    OSKextLogSpec result;
    bool          allocError = false;

   /* Do not call any function that takes sKextLoggingLock during
    * this critical block. That means do logging after.
    */
    IOLockLock(sKextLoggingLock);

    result = sUserSpaceKextLogFilter;
    sUserSpaceKextLogFilter = newUserLogFilter;

    if (newUserLogFilter && captureFlag &&
        !sUserSpaceLogSpecArray && !sUserSpaceLogMessageArray) {

        // xxx - do some measurements for a good initial capacity?
        sUserSpaceLogSpecArray = OSArray::withCapacity(0);
        sUserSpaceLogMessageArray = OSArray::withCapacity(0);
        
        if (!sUserSpaceLogSpecArray || !sUserSpaceLogMessageArray) {
            OSSafeReleaseNULL(sUserSpaceLogSpecArray);
            OSSafeReleaseNULL(sUserSpaceLogMessageArray);
            allocError = true;
        }
    }

    IOLockUnlock(sKextLoggingLock);

   /* If the config flag itself is changing, log the state change
    * going both ways, before setting up the user-space log arrays,
    * so that this is only logged in the kernel.
    */
    if (result != newUserLogFilter) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogGeneralFlag,
            "User-space log flags changed from 0x%x to 0x%x.",
            result, newUserLogFilter);
    }
    if (allocError) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogErrorLevel |
            kOSKextLogGeneralFlag,
            "Failed to allocate user-space log message arrays.");
    }

    return result;
}

/*********************************************************************
* Do not call any function that takes sKextLock here!
*********************************************************************/
/* static */
OSArray *
OSKext::clearUserSpaceLogFilter(void)
{
    OSArray       * result       = NULL;
    OSKextLogSpec   oldLogFilter;
    OSKextLogSpec   newLogFilter = kOSKextLogSilentFilter;

   /* Do not call any function that takes sKextLoggingLock during
    * this critical block. That means do logging after.
    */
    IOLockLock(sKextLoggingLock);

    result = OSArray::withCapacity(2);
    if (result) {
        result->setObject(sUserSpaceLogSpecArray);
        result->setObject(sUserSpaceLogMessageArray);
    }
    OSSafeReleaseNULL(sUserSpaceLogSpecArray);
    OSSafeReleaseNULL(sUserSpaceLogMessageArray);

    oldLogFilter = sUserSpaceKextLogFilter;
    sUserSpaceKextLogFilter = newLogFilter;

    IOLockUnlock(sKextLoggingLock);

   /* If the config flag itself is changing, log the state change
    * going both ways, after tearing down the user-space log
    * arrays, so this is only logged within the kernel.
    */
    if (oldLogFilter != newLogFilter) {
        OSKextLog(/* kext */ NULL,
            kOSKextLogDebugLevel |
            kOSKextLogGeneralFlag,
            "User-space log flags changed from 0x%x to 0x%x.",
            oldLogFilter, newLogFilter);
    }

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

    IOLockLock(sKextLoggingLock);
    result = sUserSpaceKextLogFilter;
    IOLockUnlock(sKextLoggingLock);

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
    case kOSKextLogWarningLevel:
        return VTRED;
    case kOSKextLogBasicLevel:
        return VTYELLOW VTUNDER;
    case kOSKextLogProgressLevel:
        return VTYELLOW;
    case kOSKextLogStepLevel:
        return VTGREEN;
    case kOSKextLogDetailLevel:
        return VTCYAN;
    case kOSKextLogDebugLevel:
        return VTMAGENTA;
    default:
        return "";  // white
    }
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
    va_list          srcArgList)
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

    IOLockLock(sKextLoggingLock);

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
        allocBuffer = (char *)kalloc_tag((length + 1) * sizeof(char), VM_KERN_MEMORY_OSKEXT);
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
    IOLockUnlock(sKextLoggingLock);

    if (allocBuffer) {
        kfree(allocBuffer, (length + 1) * sizeof(char));
    }
    OSSafeReleaseNULL(logString);
    OSSafeReleaseNULL(logSpecNum);
    return;
}

#if KASLR_IOREG_DEBUG
    
#define IOLOG_INDENT( the_indention ) \
{ \
    int     i; \
    for ( i = 0; i < (the_indention); i++ ) { \
        IOLog(" "); \
    } \
}
    
extern vm_offset_t	 vm_kernel_stext;
extern vm_offset_t	 vm_kernel_etext;
extern mach_vm_offset_t kext_alloc_base; 
extern mach_vm_offset_t kext_alloc_max;
    
bool ScanForAddrInObject(OSObject * theObject, 
                         int indent );

bool ScanForAddrInObject(OSObject * theObject, 
                         int indent)
{
    const OSMetaClass *     myTypeID;
    OSCollectionIterator *  myIter;
    OSSymbol *              myKey;
    OSObject *              myValue;
    bool                    myResult = false;
    
    if ( theObject == NULL ) {
        IOLog("%s: theObject is NULL \n", 
              __FUNCTION__);
        return myResult;
    }
    
    myTypeID = OSTypeIDInst(theObject);
    
    if ( myTypeID == OSTypeID(OSDictionary) ) {
        OSDictionary *      myDictionary;
        
        myDictionary = OSDynamicCast(OSDictionary, theObject);
        myIter = OSCollectionIterator::withCollection( myDictionary );
        if ( myIter == NULL ) 
            return myResult;
        myIter->reset();
        
        while ( (myKey = OSDynamicCast(OSSymbol, myIter->getNextObject())) ) {
            bool    myTempResult;
            
            myValue = myDictionary->getObject(myKey);
            myTempResult = ScanForAddrInObject(myValue, (indent + 4));
            if (myTempResult) {
                // if we ever get a true result return true
                myResult = true;
                IOLOG_INDENT(indent);
                IOLog("OSDictionary key \"%s\" \n", myKey->getCStringNoCopy());
            }
        }
        myIter->release();
    }
    else if ( myTypeID == OSTypeID(OSArray) ) {
        OSArray *   myArray;
        
        myArray = OSDynamicCast(OSArray, theObject);
        myIter = OSCollectionIterator::withCollection(myArray);
        if ( myIter == NULL ) 
            return myResult;
        myIter->reset();
        
        while ( (myValue = myIter->getNextObject()) ) {
            bool        myTempResult;
            myTempResult = ScanForAddrInObject(myValue, (indent + 4));
            if (myTempResult) {
                // if we ever get a true result return true
                myResult = true;
                IOLOG_INDENT(indent);
                IOLog("OSArray: \n");
            }
        }
        myIter->release();
    }
    else if ( myTypeID == OSTypeID(OSString) || myTypeID == OSTypeID(OSSymbol) ) {
        
        // should we look for addresses in strings?
    }
    else if ( myTypeID == OSTypeID(OSData) ) {
        
        void * *        myPtrPtr;
        unsigned int    myLen;
        OSData *        myDataObj;
        
        myDataObj =    OSDynamicCast(OSData, theObject);
        myPtrPtr = (void * *) myDataObj->getBytesNoCopy();
        myLen = myDataObj->getLength();
        
        if (myPtrPtr && myLen && myLen > 7) {
            int     i;
            int     myPtrCount = (myLen / sizeof(void *));
            
            for (i = 0; i < myPtrCount; i++) {
                UInt64 numberValue = (UInt64) *(myPtrPtr);
                
                if ( kext_alloc_max != 0 &&
                    numberValue >= kext_alloc_base && 
                    numberValue < kext_alloc_max ) {
                    
                    OSKext * myKext    = NULL;  // must release (looked up)
                                                // IOLog("found OSData %p in kext map %p to %p  \n",
                                                //       *(myPtrPtr),
                                                //       (void *) kext_alloc_base,
                                                //       (void *) kext_alloc_max);
                    
                    myKext = OSKext::lookupKextWithAddress( (vm_address_t) *(myPtrPtr) );
                    if (myKext) {
                        IOLog("found addr %p from an OSData obj within kext \"%s\"  \n",
                              *(myPtrPtr),
                              myKext->getIdentifierCString());
                        myKext->release();
                    }
                    myResult = true;
                }
                if ( vm_kernel_etext != 0 &&
                    numberValue >= vm_kernel_stext && 
                    numberValue < vm_kernel_etext ) {
                    IOLog("found addr %p from an OSData obj within kernel text segment %p to %p  \n",
                          *(myPtrPtr),
                          (void *) vm_kernel_stext,
                          (void *) vm_kernel_etext);
                    myResult = true;
                }
                myPtrPtr++;
            }
        }
    }
    else if ( myTypeID == OSTypeID(OSBoolean) ) {
        
        // do nothing here...
    }
    else if ( myTypeID == OSTypeID(OSNumber) ) {
        
        OSNumber * number = OSDynamicCast(OSNumber, theObject);
        
        UInt64 numberValue = number->unsigned64BitValue();
        
        if ( kext_alloc_max != 0 &&
            numberValue >= kext_alloc_base && 
            numberValue < kext_alloc_max ) {
            
            OSKext * myKext    = NULL;  // must release (looked up)
            IOLog("found OSNumber in kext map %p to %p  \n",
                  (void *) kext_alloc_base,
                  (void *) kext_alloc_max);
            IOLog("OSNumber 0x%08llx (%llu) \n", numberValue, numberValue);
            
            myKext = OSKext::lookupKextWithAddress( (vm_address_t) numberValue );
            if (myKext) {
                IOLog("found in kext \"%s\"  \n",
                      myKext->getIdentifierCString());
                myKext->release();
            }
            
            myResult = true;
        }
        if ( vm_kernel_etext != 0 &&
            numberValue >= vm_kernel_stext && 
            numberValue < vm_kernel_etext ) {
            IOLog("found OSNumber in kernel text segment %p to %p  \n",
                  (void *) vm_kernel_stext,
                  (void *) vm_kernel_etext);
            IOLog("OSNumber 0x%08llx (%llu) \n", numberValue, numberValue);
            myResult = true;
        }
    }
#if 0
    else {
        const OSMetaClass* myMetaClass = NULL;
        
        myMetaClass = theObject->getMetaClass();
        if ( myMetaClass ) {
            IOLog("class %s \n", myMetaClass->getClassName() );
        }
        else {
            IOLog("Unknown object \n" );
        }
    }
#endif
    
    return myResult;
}
#endif // KASLR_KEXT_DEBUG 

}; /* extern "C" */

#if PRAGMA_MARK
#pragma mark Backtrace Dump & kmod_get_info() support
#endif
/*********************************************************************
* This function must be safe to call in panic context.
*********************************************************************/
/* static */
void
OSKext::printKextsInBacktrace(
    vm_offset_t  * addr,
    unsigned int   cnt,
    int         (* printf_func)(const char *fmt, ...),
    uint32_t       flags)
{
    addr64_t    summary_page = 0;
    addr64_t    last_summary_page = 0;
    bool        found_kmod = false;
    u_int       i = 0;

    if (kPrintKextsLock & flags) {
        if (!sKextSummariesLock) return;
        IOLockLock(sKextSummariesLock);
    }

    if (!gLoadedKextSummaries) {
        (*printf_func)("         can't perform kext scan: no kext summary");
        goto finish;
    }

    summary_page = trunc_page((addr64_t)(uintptr_t)gLoadedKextSummaries);
    last_summary_page = round_page(summary_page + sLoadedKextSummariesAllocSize);
    for (; summary_page < last_summary_page; summary_page += PAGE_SIZE) {
        if (pmap_find_phys(kernel_pmap, summary_page) == 0) {
            (*printf_func)("         can't perform kext scan: "
                "missing kext summary page %p", summary_page);
            goto finish;
        }
    }

    for (i = 0; i < gLoadedKextSummaries->numSummaries; ++i) {
        OSKextLoadedKextSummary * summary;
        
        summary = gLoadedKextSummaries->summaries + i;
        if (!summary->address) {
            continue;
        }
        
        if (!summaryIsInBacktrace(summary, addr, cnt)) {
            continue;
        }
        
        if (!found_kmod) {
            if (!(kPrintKextsTerse & flags)) {
                (*printf_func)("      Kernel Extensions in backtrace:\n");
            }
            found_kmod = true;
        }

        printSummary(summary, printf_func, flags);
    }

finish:
    if (kPrintKextsLock & flags) {
        IOLockUnlock(sKextSummariesLock);
    }

    return;
}

/*********************************************************************
* This function must be safe to call in panic context.
*********************************************************************/
/* static */
boolean_t
OSKext::summaryIsInBacktrace(
    OSKextLoadedKextSummary   * summary,
    vm_offset_t               * addr,
    unsigned int                cnt)
{
    u_int i = 0;

    for (i = 0; i < cnt; i++) {
        vm_offset_t kscan_addr = addr[i];
        if ((kscan_addr >= summary->address) &&
            (kscan_addr < (summary->address + summary->size))) 
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Get the kext summary object for the kext where 'addr' lies. Must be called with
 * sKextSummariesLock held.
 */
OSKextLoadedKextSummary *
OSKext::summaryForAddress(const uintptr_t addr)
{
	for (unsigned i = 0; i < gLoadedKextSummaries->numSummaries; ++i) {

		OSKextLoadedKextSummary *summary = &gLoadedKextSummaries->summaries[i];
		if (!summary->address) {
			continue;
		}

#if VM_MAPPED_KEXTS
		/* On our platforms that use VM_MAPPED_KEXTS, we currently do not
		 * support split kexts, but we also may unmap the kexts, which can
		 * race with the above codepath (see OSKext::unload).  As such,
		 * use a simple range lookup if we are using VM_MAPPED_KEXTS.
		 */
		if ((addr >= summary->address) && (addr < (summary->address + summary->size))) {
			return summary;
		}
#else
		kernel_mach_header_t *mh = (kernel_mach_header_t *)summary->address;
		kernel_segment_command_t *seg;

		for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
			if ((addr >= seg->vmaddr) && (addr < (seg->vmaddr + seg->vmsize))) {
				return summary;
			}
		}
#endif
	}

	/* addr did not map to any kext */
	return NULL;
}

/* static */
void *
OSKext::kextForAddress(const void *addr)
{
	void *image = NULL;

	if (((vm_offset_t)(uintptr_t)addr >= vm_kernel_stext) &&
			((vm_offset_t)(uintptr_t)addr < vm_kernel_etext)) {
		return (void *)&_mh_execute_header;
	}

	if (!sKextSummariesLock) {
		return NULL;
	}
	IOLockLock(sKextSummariesLock);
	OSKextLoadedKextSummary *summary = OSKext::summaryForAddress((uintptr_t)addr);
	if (summary) {
		image = (void *)summary->address;
	}
	IOLockUnlock(sKextSummariesLock);

	return image;
}

/*********************************************************************
 * scan list of loaded kext summaries looking for a load address match and if
 * found return the UUID C string.  If not found then set empty string.
 *********************************************************************/
static void findSummaryUUID(
                            uint32_t        tag_ID,
                            uuid_string_t   uuid);

static void findSummaryUUID(
                            uint32_t        tag_ID, 
                            uuid_string_t   uuid)
{
    u_int     i;
    
    uuid[0] = 0x00; // default to no UUID
    
    for (i = 0; i < gLoadedKextSummaries->numSummaries; ++i) {
        OSKextLoadedKextSummary * summary;
        
        summary = gLoadedKextSummaries->summaries + i;
        
        if (summary->loadTag == tag_ID) {
            (void) uuid_unparse(summary->uuid, uuid);
            break;
        }
    }
    return;
}

/*********************************************************************
* This function must be safe to call in panic context.
*********************************************************************/
void OSKext::printSummary(
    OSKextLoadedKextSummary * summary,
    int                    (* printf_func)(const char *fmt, ...),
    uint32_t                  flags)
{
    kmod_reference_t * kmod_ref = NULL;
    uuid_string_t uuid;
    char version[kOSKextVersionMaxLength];
    uint64_t tmpAddr;

    if (!OSKextVersionGetString(summary->version, version, sizeof(version))) {
        strlcpy(version, "unknown version", sizeof(version));
    }
    (void) uuid_unparse(summary->uuid, uuid);
    
    if (kPrintKextsUnslide & flags) {
        tmpAddr = VM_KERNEL_UNSLIDE(summary->address);
    }
    else {
        tmpAddr = summary->address;
    }
    (*printf_func)("%s%s(%s)[%s]@0x%llx->0x%llx\n",
		(kPrintKextsTerse & flags) ? "" : "         ",
        summary->name, version, uuid,
        tmpAddr, tmpAddr + summary->size - 1);

    if (kPrintKextsTerse & flags) return;
    
    /* print dependency info */
    for (kmod_ref = (kmod_reference_t *) summary->reference_list; 
         kmod_ref; 
         kmod_ref = kmod_ref->next) {
        kmod_info_t * rinfo;
        
        if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)kmod_ref)) == 0) {
            (*printf_func)("            kmod dependency scan stopped "
                           "due to missing dependency page: %p\n",
			   (kPrintKextsUnslide & flags) ? (void *)VM_KERNEL_UNSLIDE(kmod_ref) : kmod_ref);
            break;
        }
        rinfo = kmod_ref->info;
        
        if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)rinfo)) == 0) {
            (*printf_func)("            kmod dependency scan stopped "
                           "due to missing kmod page: %p\n",
			   (kPrintKextsUnslide & flags) ? (void *)VM_KERNEL_UNSLIDE(rinfo) : rinfo);
            break;
        }
        
        if (!rinfo->address) {
            continue; // skip fake entries for built-ins
        }
        
        /* locate UUID in gLoadedKextSummaries */
        findSummaryUUID(rinfo->id, uuid);
        
        if (kPrintKextsUnslide & flags) {
            tmpAddr = VM_KERNEL_UNSLIDE(rinfo->address);
        }
        else {
            tmpAddr = rinfo->address;
        }
        (*printf_func)("            dependency: %s(%s)[%s]@%p\n",
                       rinfo->name, rinfo->version, uuid, tmpAddr);
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
                                           char        * identPlusVers,
                                           int           bufSize);

static int
assemble_identifier_and_version(
                                kmod_info_t * kmod_info, 
                                char        * identPlusVers,
                                int           bufSize)
{
    int result = 0;

    compactIdentifier(kmod_info->name, identPlusVers, NULL);
    result = strnlen(identPlusVers, KMOD_MAX_NAME - 1);
    identPlusVers[result++] = '\t';  // increment for real char
    identPlusVers[result] = '\0';    // don't increment for nul char
    result = strlcat(identPlusVers, kmod_info->version, bufSize);
    if (result >= bufSize) {
        identPlusVers[bufSize - 1] = '\0';
        result = bufSize - 1;
    }
    
    return result;
}

/*******************************************************************************
* Assumes sKextLock is held.
*******************************************************************************/
/* static */
int
OSKext::saveLoadedKextPanicListTyped(
    const char * prefix,
    int          invertFlag,
    int          libsFlag,
    char       * paniclist,
    uint32_t     list_size)
{
    int             result = -1;
    unsigned int    count, i;

    count = sLoadedKexts->getCount();
    if (!count) {
        goto finish;
    }

    i = count - 1;
    do {
        OSObject    * rawKext = sLoadedKexts->getObject(i);
        OSKext      * theKext = OSDynamicCast(OSKext, rawKext);
        int           match;
        uint32_t      identPlusVersLength;
        uint32_t      tempLen;
        char          identPlusVers[2*KMOD_MAX_NAME];
        
        if (!rawKext) {
            printf("OSKext::saveLoadedKextPanicListTyped - "
                "NULL kext in loaded kext list; continuing\n");
            continue;
        }

        if (!theKext) {
            printf("OSKext::saveLoadedKextPanicListTyped - "
                "Kext type cast failed in loaded kext list; continuing\n");
            continue;
        }

       /* Skip all built-in kexts.
        */
        if (theKext->isKernelComponent()) {
            continue;
        }

        kmod_info_t * kmod_info = theKext->kmod_info;

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
            goto finish;
        }

        identPlusVersLength = assemble_identifier_and_version(kmod_info,
                                                              identPlusVers,
                                                              sizeof(identPlusVers));
        if (!identPlusVersLength) {
            printf("error saving loaded kext info\n");
            goto finish;
        }

        /* make sure everything fits and we null terminate.
         */
        tempLen = strlcat(paniclist, identPlusVers, list_size);
        if (tempLen >= list_size) {
            // panic list is full, keep it and null terminate
            paniclist[list_size - 1] = 0x00;
            result = 0;
            goto finish;
        }
        tempLen = strlcat(paniclist, "\n", list_size);
        if (tempLen >= list_size) {
            // panic list is full, keep it and null terminate
            paniclist[list_size - 1] = 0x00;
            result = 0;
            goto finish;
        }
    } while (i--);
    
    result = 0;
finish:
    
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
    
    newlist_size = KEXT_PANICLIST_SIZE;
    newlist = (char *)kalloc_tag(newlist_size, VM_KERN_MEMORY_OSKEXT);
    
    if (!newlist) {
        OSKextLog(/* kext */ NULL,
                  kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
                  "Couldn't allocate kext panic log buffer.");
        goto finish;
    }
    
    newlist[0] = '\0';
    
    // non-"com.apple." kexts
    if (OSKext::saveLoadedKextPanicListTyped("com.apple.", /* invert? */ 1,
                                             /* libs? */ -1, newlist, newlist_size) != 0) {
        
        goto finish;
    }
    // "com.apple." nonlibrary kexts
    if (OSKext::saveLoadedKextPanicListTyped("com.apple.", /* invert? */ 0,
                                             /* libs? */ 0, newlist, newlist_size) != 0) {
        
        goto finish;
    }
    // "com.apple." library kexts
    if (OSKext::saveLoadedKextPanicListTyped("com.apple.", /* invert? */ 0,
                                             /* libs? */ 1, newlist, newlist_size) != 0) {
        
        goto finish;
    }
    
    if (loaded_kext_paniclist) {
        kfree(loaded_kext_paniclist, loaded_kext_paniclist_size);
    }
    loaded_kext_paniclist = newlist;
    newlist = NULL;
    loaded_kext_paniclist_size = newlist_size;
    
finish:
    if (newlist) {
        kfree(newlist, newlist_size);
    }
    return;
}
    
/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
void
OSKext::savePanicString(bool isLoading)
{
    u_long len;

    if (!kmod_info) {
        return;  // do not goto finish here b/c of lock
    }

    len = assemble_identifier_and_version( kmod_info,
        (isLoading) ? last_loaded_str_buf : last_unloaded_str_buf,
        (isLoading) ? sizeof(last_loaded_str_buf) : sizeof(last_unloaded_str_buf) );
    if (!len) {
        printf("error saving unloaded kext info\n");
        goto finish;
    }

    if (isLoading) {
        last_loaded_strlen = len;
        last_loaded_address = (void *)kmod_info->address;
        last_loaded_size = kmod_info->size;
        clock_get_uptime(&last_loaded_timestamp);
    } else {
        last_unloaded_strlen = len;
        last_unloaded_address = (void *)kmod_info->address;
        last_unloaded_size = kmod_info->size;
        clock_get_uptime(&last_unloaded_timestamp);
    }

finish:
    return;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::printKextPanicLists(int (*printf_func)(const char *fmt, ...))
{
    if (last_loaded_strlen) {
        printf_func("last loaded kext at %llu: %.*s (addr %p, size %lu)\n",
            AbsoluteTime_to_scalar(&last_loaded_timestamp),
            last_loaded_strlen, last_loaded_str_buf,
            last_loaded_address, last_loaded_size);
    }

    if (last_unloaded_strlen) {
        printf_func("last unloaded kext at %llu: %.*s (addr %p, size %lu)\n",
            AbsoluteTime_to_scalar(&last_unloaded_timestamp),
            last_unloaded_strlen, last_unloaded_str_buf,
            last_unloaded_address, last_unloaded_size);
    }

    printf_func("loaded kexts:\n");
    if (loaded_kext_paniclist &&
        pmap_find_phys(kernel_pmap, (addr64_t) (uintptr_t) loaded_kext_paniclist) &&
        loaded_kext_paniclist[0]) {

        printf_func("%.*s",
                    strnlen(loaded_kext_paniclist, loaded_kext_paniclist_size),
                    loaded_kext_paniclist);
    } else {
        printf_func("(none)\n");
    }
    return;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
void
OSKext::updateLoadedKextSummaries(void)
{
    kern_return_t result = KERN_FAILURE;
    OSKextLoadedKextSummaryHeader *summaryHeader = NULL;
    OSKextLoadedKextSummaryHeader *summaryHeaderAlloc = NULL;
    OSKext *aKext;
    vm_map_offset_t start, end;
    size_t summarySize = 0;
    size_t size;
    u_int count;
    u_int maxKexts;
    u_int i, j;
    OSKextActiveAccount * accountingList;
    OSKextActiveAccount * prevAccountingList;
    uint32_t idx, accountingListAlloc, accountingListCount, prevAccountingListCount;
    
    prevAccountingList = NULL;
    prevAccountingListCount = 0;

#if DEVELOPMENT || DEBUG
    if (IORecursiveLockHaveLock(sKextLock) == false) {
        panic("sKextLock must be held");
    }
#endif
    
    IOLockLock(sKextSummariesLock);
    
    count = sLoadedKexts->getCount();
    for (i = 0, maxKexts = 0; i < count; ++i) {
        aKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        maxKexts += (aKext && aKext->isExecutable());
    }
    
    if (!maxKexts) goto finish;
    if (maxKexts < kOSKextTypicalLoadCount) maxKexts = kOSKextTypicalLoadCount;
    
    /* Calculate the size needed for the new summary headers.
     */
    
    size = sizeof(*gLoadedKextSummaries);
    size += maxKexts * sizeof(*gLoadedKextSummaries->summaries);
    size = round_page(size);
    
    if (gLoadedKextSummaries == NULL || sLoadedKextSummariesAllocSize < size) {
        if (gLoadedKextSummaries) {
            kmem_free(kernel_map, (vm_offset_t)gLoadedKextSummaries, sLoadedKextSummariesAllocSize);
            gLoadedKextSummaries = NULL;
            gLoadedKextSummariesTimestamp = mach_absolute_time();
            sLoadedKextSummariesAllocSize = 0;
        }
        result = kmem_alloc(kernel_map, (vm_offset_t *)&summaryHeaderAlloc, size, VM_KERN_MEMORY_OSKEXT);
        if (result != KERN_SUCCESS) goto finish;
        summaryHeader = summaryHeaderAlloc;
        summarySize = size;
    }
    else {
        summaryHeader = gLoadedKextSummaries;
        summarySize = sLoadedKextSummariesAllocSize;
        
        start = (vm_map_offset_t) summaryHeader;
        end = start + summarySize;
        result = vm_map_protect(kernel_map,
                                start,
                                end,
                                VM_PROT_DEFAULT,
                                FALSE);
        if (result != KERN_SUCCESS) goto finish;
    }
    
    /* Populate the summary header.
     */
    
    bzero(summaryHeader, summarySize);
    summaryHeader->version = kOSKextLoadedKextSummaryVersion;
    summaryHeader->entry_size = sizeof(OSKextLoadedKextSummary);

    /* Populate each kext summary.
     */
    
    count = sLoadedKexts->getCount();
    accountingListAlloc = 0;
    for (i = 0, j = 0; i < count && j < maxKexts; ++i) {
        aKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (!aKext || !aKext->isExecutable()) {
            continue;
        }
        
        aKext->updateLoadedKextSummary(&summaryHeader->summaries[j++]);
        summaryHeader->numSummaries++;
	accountingListAlloc++;
    }

    accountingList = IONew(typeof(accountingList[0]), accountingListAlloc);
    accountingListCount = 0;
    for (i = 0, j = 0; i < count && j < maxKexts; ++i) {
        aKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
        if (!aKext || !aKext->isExecutable()) {
            continue;
        }

	OSKextActiveAccount activeAccount;
	aKext->updateActiveAccount(&activeAccount);
	// order by address
	for (idx = 0; idx < accountingListCount; idx++)
	{
	    if (activeAccount.address < accountingList[idx].address) break;
	}
	bcopy(&accountingList[idx], &accountingList[idx + 1], (accountingListCount - idx) * sizeof(accountingList[0]));
	accountingList[idx] = activeAccount;
	accountingListCount++;
    }
    assert(accountingListCount == accountingListAlloc);
    /* Write protect the buffer and move it into place.
     */
    
    start = (vm_map_offset_t) summaryHeader;
    end = start + summarySize;

    result = vm_map_protect(kernel_map, start, end, VM_PROT_READ, FALSE);
    if (result != KERN_SUCCESS)
        goto finish;

    gLoadedKextSummaries = summaryHeader;
    gLoadedKextSummariesTimestamp = mach_absolute_time();
    sLoadedKextSummariesAllocSize = summarySize;
    summaryHeaderAlloc = NULL;

   /* Call the magic breakpoint function through a static function pointer so
    * the compiler can't optimize the function away.
    */
    if (sLoadedKextSummariesUpdated) (*sLoadedKextSummariesUpdated)();

    IOSimpleLockLock(sKextAccountsLock);
    prevAccountingList      = sKextAccounts;
    prevAccountingListCount = sKextAccountsCount;
    sKextAccounts           = accountingList;
    sKextAccountsCount      = accountingListCount;
    IOSimpleLockUnlock(sKextAccountsLock);

finish:
    IOLockUnlock(sKextSummariesLock);

   /* If we had to allocate a new buffer but failed to generate the summaries,
    * free that now.
    */
    if (summaryHeaderAlloc) {
        kmem_free(kernel_map, (vm_offset_t)summaryHeaderAlloc, summarySize);
    }
    if (prevAccountingList) {
        IODelete(prevAccountingList, typeof(accountingList[0]), prevAccountingListCount);
    }

    return;
}

/*********************************************************************
*********************************************************************/
void
OSKext::updateLoadedKextSummary(OSKextLoadedKextSummary *summary)
{
    OSData *uuid;

    strlcpy(summary->name, getIdentifierCString(), 
        sizeof(summary->name));

    uuid = copyUUID();
    if (uuid) {
        memcpy(summary->uuid, uuid->getBytesNoCopy(), sizeof(summary->uuid));
        OSSafeReleaseNULL(uuid);
    }

    summary->address = kmod_info->address;
    summary->size = kmod_info->size;
    summary->version = getVersion();
    summary->loadTag = kmod_info->id;
    summary->flags = 0;
    summary->reference_list = (uint64_t) kmod_info->reference_list;

    return;
}

/*********************************************************************
*********************************************************************/

void
OSKext::updateActiveAccount(OSKextActiveAccount *accountp)
{
    kernel_mach_header_t     *hdr = NULL;
    kernel_segment_command_t *seg = NULL;

    hdr = (kernel_mach_header_t *)kmod_info->address;

    if (getcommandfromheader(hdr, LC_SEGMENT_SPLIT_INFO)) {
        /* If this kext supports split segments, use the first
         * executable segment as the range for instructions
         * (and thus for backtracing.
         */
        for (seg = firstsegfromheader(hdr); seg != NULL; seg = nextsegfromheader(hdr, seg)) {
            if (seg->initprot & VM_PROT_EXECUTE) {
                break;
            }
        }
    }

    bzero(accountp, sizeof(*accountp));
    if (seg) {
        accountp->address = seg->vmaddr;
        if (accountp->address) {
            accountp->address_end = seg->vmaddr + seg->vmsize;
        }
    } else {
        /* For non-split kexts and for kexts without executable
         * segments, just use the kmod_info range (as the kext
         * is either all in one range or should not show up in
         * instruction backtraces).
         */
        accountp->address = kmod_info->address;
        if (accountp->address) {
            accountp->address_end = kmod_info->address + kmod_info->size;
        }
    }
    accountp->account = this->account;
}

extern "C" const vm_allocation_site_t * 
OSKextGetAllocationSiteForCaller(uintptr_t address)
{
    OSKextActiveAccount *  active;
    vm_allocation_site_t * site;
    vm_allocation_site_t * releasesite;

    uint32_t baseIdx;
    uint32_t lim;

    IOSimpleLockLock(sKextAccountsLock);
    site = releasesite = NULL;
    
    // bsearch sKextAccounts list
    for (baseIdx = 0, lim = sKextAccountsCount; lim; lim >>= 1)
    {
	active = &sKextAccounts[baseIdx + (lim >> 1)];
	if ((address >= active->address) && (address < active->address_end))
	{
	    site = &active->account->site;
	    if (!site->tag) vm_tag_alloc_locked(site, &releasesite);
	    break;
	}
	else if (address > active->address) 
	{	
	    // move right
	    baseIdx += (lim >> 1) + 1;
	    lim--;
	}
	// else move left
    }
    IOSimpleLockUnlock(sKextAccountsLock);
    if (releasesite) kern_allocation_name_release(releasesite);

    return (site);
}

extern "C" uint32_t 
OSKextGetKmodIDForSite(const vm_allocation_site_t * site, char * name, vm_size_t namelen)
{
    OSKextAccount * account = (typeof(account)) site;
    const char    * kname;

    if (name)
    {
        if (account->kext) kname = account->kext->getIdentifierCString();
        else               kname = "<>";
        strlcpy(name, kname, namelen);
    }

    return (account->loadTag);
}

extern "C" void 
OSKextFreeSite(vm_allocation_site_t * site)
{
    OSKextAccount * freeAccount = (typeof(freeAccount)) site;
    IODelete(freeAccount, OSKextAccount, 1);
}

/*********************************************************************
*********************************************************************/
    
#if CONFIG_KEC_FIPS
    
#if PRAGMA_MARK
#pragma mark Kernel External Components for FIPS compliance
#endif
    
/*********************************************************************
 * Kernel External Components for FIPS compliance (KEC_FIPS)
 *********************************************************************/
static void * 
GetAppleTEXTHashForKext(OSKext * theKext, OSDictionary *theInfoDict)
{
    AppleTEXTHash_t         my_ath = {2, 0, NULL};
    AppleTEXTHash_t *       my_athp = NULL;         // do not release
    OSData *                segmentHash = NULL;     // do not release
    
    if (theKext == NULL || theInfoDict == NULL) {
        return(NULL);
    }
    
    // Get the part of the plist associate with kAppleTextHashesKey and let
    // the crypto library do further parsing (slice/architecture)
    segmentHash = OSDynamicCast(OSData, theInfoDict->getObject(kAppleTextHashesKey));
    // Support for ATH v1 while rolling out ATH v2 without revision locking submissions
    // Remove this when v2 PLIST are supported
    if (segmentHash == NULL) {
        // If this fails, we may be dealing with a v1 PLIST
        OSDictionary *          textHashDict = NULL;    // do not release
        textHashDict = OSDynamicCast(OSDictionary, theInfoDict->getObject(kAppleTextHashesKey));
        if (textHashDict == NULL) {
            return(NULL);
        }
        my_ath.ath_version=1;
        segmentHash = OSDynamicCast(OSData,textHashDict->getObject(ARCHNAME));
    } // end of v2 rollout

    if (segmentHash == NULL) {
        return(NULL);
    }
    
    // KEC_FIPS type kexts never unload so we don't have to clean up our 
    // AppleTEXTHash_t
    if (kmem_alloc(kernel_map, (vm_offset_t *) &my_athp, 
                   sizeof(AppleTEXTHash_t), VM_KERN_MEMORY_OSKEXT) != KERN_SUCCESS) {
        return(NULL);
    }
    
    memcpy(my_athp, &my_ath, sizeof(my_ath));
    my_athp->ath_length = segmentHash->getLength();
    if (my_athp->ath_length > 0) {
        my_athp->ath_hash = (void *)segmentHash->getBytesNoCopy();
    }
        
#if 0
    OSKextLog(theKext,
              kOSKextLogErrorLevel |
              kOSKextLogGeneralFlag,
              "Kext %s ath_version %d ath_length %d ath_hash %p",
              theKext->getIdentifierCString(), 
              my_athp->ath_version,
              my_athp->ath_length,
              my_athp->ath_hash); 
#endif
        
    return( (void *) my_athp );
}
    
#endif // CONFIG_KEC_FIPS

#if CONFIG_IMAGEBOOT
int OSKextGetUUIDForName(const char *name, uuid_t uuid)
{
	OSKext *kext = OSKext::lookupKextWithIdentifier(name);
	if (!kext) {
		return 1;
	}

	OSData *uuid_data = kext->copyUUID();
	if (uuid_data) {
		memcpy(uuid, uuid_data->getBytesNoCopy(), sizeof(uuid_t));
		OSSafeReleaseNULL(uuid_data);
		return 0;
	}

	return 1;
}
#endif

