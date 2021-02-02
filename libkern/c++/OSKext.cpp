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

#define IOKIT_ENABLE_SHARED_PTR

extern "C" {
#include <string.h>
#include <kern/clock.h>
#include <kern/host.h>
#include <kern/kext_alloc.h>
#include <firehose/tracepoint_private.h>
#include <firehose/chunk_private.h>
#include <os/firehose_buffer_private.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
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
#include <sys/random.h>
#include <pexpert/pexpert.h>

#include <sys/pgo.h>

#if CONFIG_MACF
#include <sys/kauth.h>
#include <security/mac_framework.h>
#endif

#if CONFIG_CSR
#include <sys/csr.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#endif /* CONFIG_CSR */
};

#include <os/cpp_util.h>

#include <libkern/OSKextLibPrivate.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSLib.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserServer.h>

#include <IOKit/IOStatisticsPrivate.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOPlatformExpert.h>

#include <san/kasan.h>

#if PRAGMA_MARK
#pragma mark External & Internal Function Protos
#endif
/*********************************************************************
*********************************************************************/
extern "C" {
extern int  IODTGetLoaderInfo(const char * key, void ** infoAddr, int * infoSize);
extern void IODTFreeLoaderInfo(const char * key, void * infoAddr, int infoSize);

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va); /* osfmk/machine/pmap.h */
extern int dtrace_keep_kernel_symbols(void);

#if defined(__x86_64__) || defined(__i386__)
extern kern_return_t i386_slide_individual_kext(kernel_mach_header_t *mh, uintptr_t slide);
extern kern_return_t i386_slide_kext_collection_mh_addrs(kernel_mach_header_t *mh, uintptr_t slide, bool adjust_mach_headers);
extern void *ubc_getobject_from_filename(const char *filename, struct vnode **, off_t *file_size);
static void *allocate_kcfileset_map_entry_list(void);
static void add_kcfileset_map_entry(void *map_entry_list, vm_map_offset_t start, vm_map_offset_t size);
static void deallocate_kcfileset_map_entry_list_and_unmap_entries(void *map_entry_list, boolean_t unmap_entries, bool pageable);
int vnode_put(struct vnode *vp);
kern_return_t vm_map_kcfileset_segment(vm_map_offset_t *start, vm_map_offset_t size,
    void *control, vm_object_offset_t fileoffset, vm_prot_t max_prot);
kern_return_t vm_unmap_kcfileset_segment(vm_map_offset_t *start, vm_map_offset_t size);
void * ubc_getobject(struct vnode *vp, __unused int flags);
#endif //(__x86_64__) || defined(__i386__)
}

extern unsigned long gVirtBase;
extern unsigned long gPhysBase;
extern vm_map_t g_kext_map;

bool pageableKCloaded = false;
bool auxKCloaded = false;
bool resetAuxKCSegmentOnUnload = false;

extern boolean_t pageablekc_uuid_valid;
extern uuid_t pageablekc_uuid;
extern uuid_string_t pageablekc_uuid_string;

extern boolean_t auxkc_uuid_valid;
extern uuid_t auxkc_uuid;
extern uuid_string_t auxkc_uuid_string;

static OSReturn _OSKextCreateRequest(
	const char    * predicate,
	OSSharedPtr<OSDictionary> & requestP);
static OSString * _OSKextGetRequestPredicate(OSDictionary * requestDict);
static OSObject * _OSKextGetRequestArgument(
	OSDictionary * requestDict,
	const char   * argName);
static bool _OSKextSetRequestArgument(
	OSDictionary * requestDict,
	const char   * argName,
	OSObject     * value);
static void * _OSKextExtractPointer(OSData * wrapper);
static OSKextRequestResourceCallback _OSKextExtractCallbackPointer(OSData * wrapper);
static OSReturn _OSDictionarySetCStringValue(
	OSDictionary * dict,
	const char   * key,
	const char   * value);
static bool _OSKextInUnloadedPrelinkedKexts(const OSSymbol * theBundleID);
#if CONFIG_KXLD
static bool _OSKextInPrelinkRebuildWindow(void);
#endif

// We really should add containsObject() & containsCString to OSCollection & subclasses.
// So few pad slots, though....
static bool _OSArrayContainsCString(OSArray * array, const char * cString);
static void OSKextLogKextInfo(OSKext *aKext, uint64_t address, uint64_t size, firehose_tracepoint_code_t code);

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
	mkext_basic_header * mkext; // beginning of whole mkext file
	void               * fileinfo;// mkext2_file_entry or equiv; see mkext.h
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
static  bool                sPanicOnKCMismatch         = false;
static  bool                sOSKextWasResetAfterUserspaceReboot = false;

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

static OSSharedPtr<OSDictionary>   sKextsByID;
static OSSharedPtr<OSDictionary>   sExcludeListByID;
static OSKextVersion               sExcludeListVersion        = 0;
static OSSharedPtr<OSArray>        sLoadedKexts;
static OSSharedPtr<OSDictionary>   sNonLoadableKextsByID;
static OSSharedPtr<OSArray>        sUnloadedPrelinkedKexts;
static OSSharedPtr<OSArray>        sLoadedDriverKitKexts;

// Requests to the IOKit daemon waiting to be picked up.
static OSSharedPtr<OSArray>        sKernelRequests;
// Identifier of kext load requests in sKernelRequests
static OSSharedPtr<OSSet>          sPostedKextLoadIdentifiers;
static OSSharedPtr<OSArray>        sRequestCallbackRecords;

// Identifiers of all kexts ever requested in kernel; used for prelinked kernel
static OSSharedPtr<OSSet>          sAllKextLoadIdentifiers;
#if CONFIG_KXLD
static KXLDContext        * sKxldContext               = NULL;
#endif
static uint32_t             sNextLoadTag               = 0;
static uint32_t             sNextRequestTag            = 0;

static bool                 sUserLoadsActive           = false;
static bool                 sIOKitDaemonActive         = false;
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
	.next =            NULL,
	.info_version =    KMOD_INFO_VERSION,
	.id =              0,             // loadTag: kernel is always 0
	.name =            kOSKextKernelIdentifier,// bundle identifier
	.version =         "0",           // filled in in OSKext::initialize()
	.reference_count = -1,            // never adjusted; kernel never unloads
	.reference_list =  NULL,
	.address =         0,
	.size =            0,             // filled in in OSKext::initialize()
	.hdr_size =        0,
	.start =           NULL,
	.stop =            NULL
};

/* Set up a fake kmod_info struct for statically linked kexts that don't have one. */

kmod_info_t invalid_kmod_info = {
	.next =            NULL,
	.info_version =    KMOD_INFO_VERSION,
	.id =              UINT32_MAX,
	.name =            "invalid",
	.version =         "0",
	.reference_count = -1,
	.reference_list =  NULL,
	.address =         0,
	.size =            0,
	.hdr_size =        0,
	.start =           NULL,
	.stop =            NULL
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
static char       last_loaded_str_buf[2 * KMOD_MAX_NAME];
static u_long     last_loaded_strlen            = 0;
static void     * last_loaded_address           = NULL;
static u_long     last_loaded_size              = 0;

AbsoluteTime      last_unloaded_timestamp;
static char       last_unloaded_str_buf[2 * KMOD_MAX_NAME];
static u_long     last_unloaded_strlen          = 0;
static void     * last_unloaded_address         = NULL;
static u_long     last_unloaded_size            = 0;

// Statically linked kmods described by several mach-o sections:
//
// kPrelinkInfoSegment:kBuiltinInfoSection
// Array of pointers to kmod_info_t structs.
//
// kPrelinkInfoSegment:kBuiltinInfoSection
// Array of pointers to an embedded mach-o header.
//
// __DATA:kBuiltinInitSection, kBuiltinTermSection
// Structors for all kmods. Has to be filtered by proc address.
//

static uint32_t gBuiltinKmodsCount;
static kernel_section_t * gBuiltinKmodsSectionInfo;
static kernel_section_t * gBuiltinKmodsSectionStart;

const OSSymbol              * gIOSurfaceIdentifier;
vm_tag_t                      gIOSurfaceTag;

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
static thread_call_t        sUnloadCallout             = NULL;
#if CONFIG_KXLD
static thread_call_t        sDestroyLinkContextThread  = NULL;   // one-shot, one-at-a-time thread
#endif // CONFIG_KXLD
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

void(*const sLoadedKextSummariesUpdated)(void) = OSKextLoadedKextSummariesUpdated;
OSKextLoadedKextSummaryHeader * gLoadedKextSummaries __attribute__((used)) = NULL;
uint64_t gLoadedKextSummariesTimestamp __attribute__((used)) = 0;
static size_t sLoadedKextSummariesAllocSize = 0;

static OSKextActiveAccount    * sKextAccounts;
static uint32_t                 sKextAccountsCount;
};

/*********************************************************************
 * sKextLoggingLock protects the logging variables declared immediately below.
 **********/
static IOLock                 * sKextLoggingLock           = NULL;

static  const OSKextLogSpec     kDefaultKernelLogFilter    = kOSKextLogBasicLevel |
    kOSKextLogVerboseFlagsMask;
static  OSKextLogSpec           sKernelLogFilter           = kDefaultKernelLogFilter;
static  bool                    sBootArgLogFilterFound     = false;
SYSCTL_UINT(_debug, OID_AUTO, kextlog, CTLFLAG_RW | CTLFLAG_LOCKED, &sKernelLogFilter,
    0, "kernel kext logging");

static  OSKextLogSpec           sUserSpaceKextLogFilter    = kOSKextLogSilentFilter;
static  OSSharedPtr<OSArray>    sUserSpaceLogSpecArray;
static  OSSharedPtr<OSArray>    sUserSpaceLogMessageArray;

/*********
 * End scope for sKextInnerLock-protected variables.
 *********************************************************************/


/*********************************************************************
 *  helper function used for collecting PGO data upon unload of a kext
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
void
osdata_kmem_free(void * ptr, unsigned int length)
{
	kmem_free(kernel_map, (vm_address_t)ptr, length);
	return;
}

void
osdata_phys_free(void * ptr, unsigned int length)
{
	ml_static_mfree((vm_offset_t)ptr, length);
	return;
}

void
osdata_vm_deallocate(void * ptr, unsigned int length)
{
	(void)vm_deallocate(kernel_map, (vm_offset_t)ptr, length);
	return;
}

void
osdata_kext_free(void * ptr, unsigned int length)
{
	(void)kext_free((vm_offset_t)ptr, length);
}
};

#if PRAGMA_MARK
#pragma mark KXLD Allocation Callback
#endif
#if CONFIG_KXLD
/*********************************************************************
* KXLD Allocation Callback
*********************************************************************/
kxld_addr_t
kern_allocate(
	u_long              size,
	KXLDAllocateFlags * flags,
	void              * user_data)
{
	vm_address_t  result       = 0; // returned
	kern_return_t mach_result  = KERN_FAILURE;
	bool          success      = false;
	OSKext      * theKext      = (OSKext *)user_data;
	unsigned int  roundSize    = 0;
	OSSharedPtr<OSData>      linkBuffer;

	if (round_page(size) > UINT_MAX) {
		OSKextLog(theKext,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag,
		    "%s: Requested memory size is greater than UINT_MAX.",
		    theKext->getIdentifierCString());
		goto finish;
	}

	roundSize = (unsigned int)round_page(size);

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

	theKext->setLinkedExecutable(linkBuffer.get());

	*flags = kKxldAllocateWritable;
	success = true;

finish:
	if (!success && result) {
		kext_free(result, roundSize);
		result = 0;
	}

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
#endif // CONFIG_KXLD

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

OSDefineMetaClassAndStructors(OSKextSavedMutableSegment, OSObject);

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::initialize(void)
{
	OSSharedPtr<OSData>     kernelExecutable   = NULL;// do not release
	u_char          * kernelStart        = NULL;// do not free
	size_t            kernelLength       = 0;
	IORegistryEntry * registryRoot       = NULL;// do not release
	OSSharedPtr<OSNumber> kernelCPUType;
	OSSharedPtr<OSNumber> kernelCPUSubtype;
	OSKextLogSpec     bootLogFilter      = kOSKextLogSilentFilter;
	bool              setResult          = false;
	uint64_t        * timestamp          = NULL;
	__unused char     bootArgBuffer[16];// for PE_parse_boot_argn w/strings

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
	sLoadedDriverKitKexts = OSArray::withCapacity(kOSKextTypicalLoadCount);
	sUnloadedPrelinkedKexts = OSArray::withCapacity(kOSKextTypicalLoadCount / 10);
	sKernelRequests = OSArray::withCapacity(0);
	sPostedKextLoadIdentifiers = OSSet::withCapacity(0);
	sAllKextLoadIdentifiers = OSSet::withCapacity(kOSKextTypicalLoadCount);
	sRequestCallbackRecords = OSArray::withCapacity(0);
	assert(sKextsByID && sLoadedKexts && sLoadedDriverKitKexts && sKernelRequests &&
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

#if !defined(__arm__) && !defined(__arm64__)
	/*
	 * On our ARM targets, the kernelcache/boot kernel collection contains
	 * the set of kexts required to boot, as specified by KCB.  Safeboot is
	 * either unsupported, or is supported by the bootloader only loading
	 * the boot kernel collection; as a result OSKext has no role to play
	 * in safeboot policy on ARM.
	 */
	sSafeBoot = PE_parse_boot_argn("-x", bootArgBuffer,
	    sizeof(bootArgBuffer)) ? true : false;
#endif /* defined(__arm__) && defined(__arm64__) */

	if (sSafeBoot) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogWarningLevel |
		    kOSKextLogGeneralFlag,
		    "SAFE BOOT DETECTED - "
		    "only valid OSBundleRequired kexts will be loaded.");
	}

	PE_parse_boot_argn("keepsyms", &sKeepSymbols, sizeof(sKeepSymbols));
#if CONFIG_DTRACE
	if (dtrace_keep_kernel_symbols()) {
		sKeepSymbols = true;
	}
#endif /* CONFIG_DTRACE */
#if KASAN_DYNAMIC_BLACKLIST
	/* needed for function lookup */
	sKeepSymbols = true;
#endif

	/*
	 * Should we panic when the SystemKC is not linked against the
	 * BootKC that was loaded by the booter? By default: yes, if the
	 * "-nokcmismatchpanic" boot-arg is passed, then we _don't_ panic
	 * on mis-match and instead just print an error and continue.
	 */
	sPanicOnKCMismatch = PE_parse_boot_argn("-nokcmismatchpanic", bootArgBuffer,
	    sizeof(bootArgBuffer)) ? false : true;

	/* Set up an OSKext instance to represent the kernel itself.
	 */
	sKernelKext = new OSKext;
	assert(sKernelKext);

	kernelStart = (u_char *)&_mh_execute_header;
	kernelLength = getlastaddr() - (vm_offset_t)kernelStart;
	assert(kernelLength <= UINT_MAX);
	kernelExecutable = OSData::withBytesNoCopy(
		kernelStart, (unsigned int)kernelLength);
	assert(kernelExecutable);

#if KASLR_KEXT_DEBUG
	IOLog("kaslr: kernel start 0x%lx end 0x%lx length %lu vm_kernel_slide %lu (0x%016lx) \n",
	    (unsigned long)kernelStart,
	    (unsigned long)getlastaddr(),
	    kernelLength,
	    (unsigned long)vm_kernel_slide,
	    (unsigned long)vm_kernel_slide);
#endif

	sKernelKext->loadTag = sNextLoadTag++; // the kernel is load tag 0
	sKernelKext->bundleID = OSSymbol::withCString(kOSKextKernelIdentifier);

	sKernelKext->version = OSKextParseVersionString(osrelease);
	sKernelKext->compatibleVersion = sKernelKext->version;
	sKernelKext->linkedExecutable = os::move(kernelExecutable);
	sKernelKext->interfaceUUID = sKernelKext->copyUUID();

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
	    sKernelKext->bundleID.get());
	assert(setResult);
	setResult = sKernelKext->infoDict->setObject(kOSKernelResourceKey,
	    kOSBooleanTrue);
	assert(setResult);

	{
		OSSharedPtr<OSString> scratchString(OSString::withCStringNoCopy(osrelease));
		assert(scratchString);
		setResult = sKernelKext->infoDict->setObject(kCFBundleVersionKey,
		    scratchString.get());
		assert(setResult);
	}

	{
		OSSharedPtr<OSString> scratchString(OSString::withCStringNoCopy("mach_kernel"));
		assert(scratchString);
		setResult = sKernelKext->infoDict->setObject(kCFBundleNameKey,
		    scratchString.get());
		assert(setResult);
	}

	/* Add the kernel kext to the bookkeeping dictionaries. Note that
	 * the kernel kext doesn't have a kmod_info struct. copyInfo()
	 * gathers info from other places anyhow.
	 */
	setResult = sKextsByID->setObject(sKernelKext->bundleID.get(), sKernelKext);
	assert(setResult);
	setResult = sLoadedKexts->setObject(sKernelKext);
	assert(setResult);

	// XXX: better way with OSSharedPtr?
	// sKernelKext remains a valid pointer even after the decref
	sKernelKext->release();

	registryRoot = IORegistryEntry::getRegistryRoot();
	kernelCPUType = OSNumber::withNumber(
		(long long unsigned int)_mh_execute_header.cputype,
		8 * sizeof(_mh_execute_header.cputype));
	kernelCPUSubtype = OSNumber::withNumber(
		(long long unsigned int)_mh_execute_header.cpusubtype,
		8 * sizeof(_mh_execute_header.cpusubtype));
	assert(registryRoot && kernelCPUSubtype && kernelCPUType);

	registryRoot->setProperty(kOSKernelCPUTypeKey, kernelCPUType.get());
	registryRoot->setProperty(kOSKernelCPUSubtypeKey, kernelCPUSubtype.get());

	gBuiltinKmodsSectionInfo = getsectbyname(kPrelinkInfoSegment, kBuiltinInfoSection);
	if (gBuiltinKmodsSectionInfo) {
		uint32_t count;

		assert(gBuiltinKmodsSectionInfo->addr);
		assert(gBuiltinKmodsSectionInfo->size);
		assert(gBuiltinKmodsSectionInfo->size / sizeof(kmod_info_t *) <= UINT_MAX);
		gBuiltinKmodsCount = (unsigned int)(gBuiltinKmodsSectionInfo->size / sizeof(kmod_info_t *));

		gBuiltinKmodsSectionStart = getsectbyname(kPrelinkInfoSegment, kBuiltinStartSection);
		assert(gBuiltinKmodsSectionStart);
		assert(gBuiltinKmodsSectionStart->addr);
		assert(gBuiltinKmodsSectionStart->size);
		assert(gBuiltinKmodsSectionStart->size / sizeof(uintptr_t) <= UINT_MAX);
		count = (unsigned int)(gBuiltinKmodsSectionStart->size / sizeof(uintptr_t));
		// one extra pointer for the end of last kmod
		assert(count == (gBuiltinKmodsCount + 1));

		vm_kernel_builtinkmod_text     = ((uintptr_t *)gBuiltinKmodsSectionStart->addr)[0];
		vm_kernel_builtinkmod_text_end = ((uintptr_t *)gBuiltinKmodsSectionStart->addr)[count - 1];
	}

	// Don't track this object -- it's never released
	gIOSurfaceIdentifier = OSSymbol::withCStringNoCopy("com.apple.iokit.IOSurface").detach();

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
* This is expected to be called exactly once, from exactly one thread
* context, during kernel bootstrap.
*********************************************************************/
/* static */
OSReturn
OSKext::removeKextBootstrap(void)
{
	OSReturn                   result                = kOSReturnError;

	const char               * dt_kernel_header_name = "Kernel-__HEADER";
	const char               * dt_kernel_symtab_name = "Kernel-__SYMTAB";
	kernel_mach_header_t     * dt_mach_header        = NULL;
	int                        dt_mach_header_size   = 0;
	struct symtab_command    * dt_symtab             = NULL;
	int                        dt_symtab_size        = 0;
	int                        dt_result             = 0;

	kernel_segment_command_t * seg_to_remove         = NULL;

	const char __unused      * dt_segment_name       = NULL;
	void       __unused      * segment_paddress      = NULL;
	int        __unused        segment_size          = 0;

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogGeneralFlag,
	    "Jettisoning kext bootstrap segments.");

	/*
	 * keep the linkedit segment around when booted from a new MH_FILESET
	 * KC because all the kexts shared a linkedit segment.
	 */
	kc_format_t kc_format;
	if (!PE_get_primary_kc_format(&kc_format)) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag,
		    "Unable to determine primary KC format");
	}

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
#elif __i386__ || __x86_64__
	/* On x86, use the mapping data from the segment load command to
	 * unload KLD directly.
	 * This may invalidate any assumptions about  "avail_start"
	 * defining the lower bound for valid physical addresses.
	 */
	if (seg_to_remove && seg_to_remove->vmaddr && seg_to_remove->vmsize) {
		bzero((void *)seg_to_remove->vmaddr, seg_to_remove->vmsize);
		ml_static_mfree(seg_to_remove->vmaddr, seg_to_remove->vmsize);
	}
#else
#error arch
#endif

	seg_to_remove = NULL;

	/*****
	 * Prelinked kernel's symtab (if there is one).
	 */
	if (kc_format != KCFormatFileset) {
		kernel_section_t * sect;
		sect = getsectbyname("__PRELINK", "__symtab");
		if (sect && sect->addr && sect->size) {
			ml_static_mfree(sect->addr, sect->size);
		}
	}

	seg_to_remove = (kernel_segment_command_t *)getsegbyname("__LINKEDIT");

	/* kxld always needs the kernel's __LINKEDIT segment, but we can make it
	 * pageable, unless keepsyms is set.  To do that, we have to copy it from
	 * its booter-allocated memory, free the booter memory, reallocate proper
	 * managed memory, then copy the segment back in.
	 *
	 * NOTE: This optimization is not valid for fileset KCs because each
	 * fileset entry (kext or xnu) in an MH_FILESET has a LINKEDIT segment
	 * that points to one fileset-global LINKEDIT segment. This
	 * optimization is also only valid for platforms that support vm
	 * mapped kexts or mapped kext collections (pageable KCs)
	 */
#if VM_MAPPED_KEXTS
	if (!sKeepSymbols && kc_format != KCFormatFileset) {
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
			return result;
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
		    (seg_offset != (vm_map_offset_t) seg_data)) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogGeneralFlag | kOSKextLogArchiveFlag,
			    "Can't create __LINKEDIT VM entry at %p, length 0x%llx (error 0x%x).",
			    seg_data, seg_length, mem_result);
			return result;
		}

		/* And copy it back.
		 */
		memcpy(seg_data, seg_copy, seg_length);

		/* Free the copy.
		 */
		kmem_free(kernel_map, seg_copy_offset, seg_length);
	} else if (!sKeepSymbols && kc_format == KCFormatFileset) {
		/* Remove the linkedit segment of the Boot KC */
		kernel_mach_header_t *mh = (kernel_mach_header_t *)PE_get_kc_header(KCKindPrimary);
		OSKext::jettisonFileSetLinkeditSegment(mh);
	}
#else // !VM_MAPPED_KEXTS
	/*****
	 * Dump the LINKEDIT segment, unless keepsyms is set.
	 */
	if (!sKeepSymbols && kc_format != KCFormatFileset) {
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
#endif // VM_MAPPED_KEXTS

	seg_to_remove = NULL;

	result = kOSReturnSuccess;

	return result;
}

#if CONFIG_KXLD
/*********************************************************************
*********************************************************************/
void
OSKext::flushNonloadedKexts(
	Boolean flushPrelinkedKexts)
{
	OSSharedPtr<OSSet>                keepKexts;

	/* TODO: make this more efficient with MH_FILESET kexts */

	// Do not unload prelinked kexts on arm because the kernelcache is not
	// structured in a way that allows them to be unmapped
#if !defined(__x86_64__)
	flushPrelinkedKexts = false;
#endif /* defined(__x86_64__) */

	IORecursiveLockLock(sKextLock);

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogKextBookkeepingFlag,
	    "Flushing nonloaded kexts and other unused data.");

	OSKext::considerDestroyingLinkContext();

	/* If we aren't flushing unused prelinked kexts, we have to put them
	 * aside while we flush everything else so make a container for them.
	 */
	keepKexts = OSSet::withCapacity(16);
	if (!keepKexts) {
		goto finish;
	}

	/* Set aside prelinked kexts (in-use or not) and break
	 * any lingering inter-kext references for nonloaded kexts
	 * so they have min. retain counts.
	 */
	{
		sKextsByID->iterateObjects(^bool (const OSSymbol * thisID __unused, OSObject * obj) {
			OSKext * thisKext = OSDynamicCast(OSKext, obj);
			if (!thisKext) {
			        return false;
			}
			if (!flushPrelinkedKexts && thisKext->isPrelinked()) {
			        keepKexts->setObject(thisKext);
			} else if (!thisKext->declaresExecutable()) {
			        /*
			         * Don't unload codeless kexts, because they never appear in the loadedKexts array.
			         * Requesting one from the IOKit daemon will load it and then immediately remove it by calling
			         * flushNonloadedKexts().
			         * And adding one to loadedKexts breaks code assuming they have kmod_info etc.
			         */
			        keepKexts->setObject(thisKext);
			} else if (thisKext->isInFileset()) {
			        /* keep all kexts in the new MH_FILESET KC */
			        keepKexts->setObject(thisKext);
			}

			thisKext->flushDependencies(/* forceIfLoaded */ false);
			return false;
		});
	}
	/* Dump all the kexts in the ID dictionary; we'll repopulate it shortly.
	 */
	sKextsByID->flushCollection();

	/* Now put the loaded kexts back into the ID dictionary.
	 */
	sLoadedKexts->iterateObjects(^bool (OSObject * obj) {
		OSKext * thisKext = OSDynamicCast(OSKext, obj);
		if (!thisKext) {
		        return false;
		}
		sKextsByID->setObject(thisKext->getIdentifierCString(), thisKext);
		return false;
	});

	/* Finally, put back the kept kexts if we saved any.
	 */
	keepKexts->iterateObjects(^bool (OSObject * obj) {
		OSKext * thisKext = OSDynamicCast(OSKext, obj);
		if (!thisKext) {
		        return false;
		}
		sKextsByID->setObject(thisKext->getIdentifierCString(), thisKext);
		return false;
	});

finish:
	IORecursiveLockUnlock(sKextLock);
	return;
}
#else /* !CONFIG_KXLD */

void
OSKext::flushNonloadedKexts(
	Boolean flushPrelinkedKexts __unused)
{
	IORecursiveLockLock(sKextLock);

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogKextBookkeepingFlag,
	    "Flushing dependency info for non-loaded kexts.");

	/*
	 * In a world where we don't dynamically link kexts, they all come
	 * from a kext collection that's either in wired memory, or
	 * wire-on-demand. We don't need to mess around with moving kexts in
	 * and out of the sKextsByID array - they can all just stay there.
	 * Here we just flush the dependency list for kexts that are not
	 * loaded.
	 */
	sKextsByID->iterateObjects(^bool (const OSSymbol * thisID __unused, OSObject * obj) {
		OSKext * thisKext = OSDynamicCast(OSKext, obj);
		if (!thisKext) {
		        return false;
		}
		thisKext->flushDependencies(/* forceIfLoaded */ false);
		return false;
	});

	IORecursiveLockUnlock(sKextLock);
	return;
}

#endif /* CONFIG_KXLD */

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::setIOKitDaemonActive(bool active)
{
	IOServiceTrace(IOSERVICE_KEXTD_ALIVE, 0, 0, 0, 0);
	IORecursiveLockLock(sKextLock);
	sIOKitDaemonActive = active;
	if (sKernelRequests->getCount()) {
		OSKext::pingIOKitDaemon();
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
OSKext::pingIOKitDaemon(void)
{
	OSReturn    result     = kOSReturnError;
#if !NO_KEXTD
	mach_port_t kextd_port = IPC_PORT_NULL;

	if (!sIOKitDaemonActive) {
		result = kOSKextReturnDisabled; // basically unavailable
		goto finish;
	}

	result = host_get_kextd_port(host_priv_self(), &kextd_port);
	if (result != KERN_SUCCESS || !IPC_PORT_VALID(kextd_port)) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogIPCFlag,
		    "Can't get " kIOKitDaemonName " port.");
		goto finish;
	}

	result = kextd_ping(kextd_port);
	if (result != KERN_SUCCESS) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogIPCFlag,
		    kIOKitDaemonName " ping failed (0x%x).", (int)result);
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
	OSSharedPtr<OSDictionary> exitRequest;

	IORecursiveLockLock(sKextLock);

	OSKext::setLoadEnabled(false);
	OSKext::setUnloadEnabled(false);
	OSKext::setAutounloadsEnabled(false);
	OSKext::setKernelRequestsEnabled(false);

#if defined(__x86_64__) || defined(__i386__)
	if (IOPMRootDomainGetWillShutdown()) {
		OSKext::freeKCFileSetcontrol();
	}
#endif // (__x86_64__) || defined(__i386__)

#if !NO_KEXTD
	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogGeneralFlag,
	    "System shutdown; requesting immediate " kIOKitDaemonName " exit.");

	checkResult = _OSKextCreateRequest(kKextRequestPredicateRequestDaemonExit,
	    exitRequest);
	if (checkResult != kOSReturnSuccess) {
		goto finish;
	}
	if (!sKernelRequests->setObject(exitRequest.get())) {
		goto finish;
	}

	OSKext::pingIOKitDaemon();

finish:
#endif

	IORecursiveLockUnlock(sKextLock);
	return;
}

void
OSKext::willUserspaceReboot(void)
{
	OSKext::willShutdown();
	IOService::userSpaceWillReboot();
	gIOCatalogue->terminateDriversForUserspaceReboot();
}

void
OSKext::resetAfterUserspaceReboot(void)
{
	OSSharedPtr<OSArray> arr = OSArray::withCapacity(1);
	IOService::updateConsoleUsers(arr.get(), 0, true /* after_userspace_reboot */);

	IORecursiveLockLock(sKextLock);
	gIOCatalogue->resetAfterUserspaceReboot();
	IOService::userSpaceDidReboot();
	OSKext::setLoadEnabled(true);
	OSKext::setUnloadEnabled(true);
	OSKext::setAutounloadsEnabled(true);
	OSKext::setKernelRequestsEnabled(true);
	sOSKextWasResetAfterUserspaceReboot = true;
	IORecursiveLockUnlock(sKextLock);
}

extern "C" void
OSKextResetAfterUserspaceReboot(void)
{
	OSKext::resetAfterUserspaceReboot();
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

static bool
segmentIsMutable(kernel_segment_command_t *seg)
{
	/* Mutable segments have to have VM_PROT_WRITE */
	if ((seg->maxprot & VM_PROT_WRITE) == 0) {
		return false;
	}
	/* Exclude the __DATA_CONST segment */
	if (strncmp(seg->segname, "__DATA_CONST", sizeof(seg->segname)) == 0) {
		return false;
	}
	/* Exclude __LINKEDIT */
	if (strncmp(seg->segname, "__LINKEDIT", sizeof(seg->segname)) == 0) {
		return false;
	}
	return true;
}

#if PRAGMA_MARK
#pragma mark Kext Life Cycle
#endif
/*********************************************************************
*********************************************************************/
OSSharedPtr<OSKext>
OSKext::withPrelinkedInfoDict(
	OSDictionary * anInfoDict,
	bool doCoalescedSlides,
	kc_kind_t type)
{
	OSSharedPtr<OSKext> newKext(OSMakeShared<OSKext>());

	if (newKext && !newKext->initWithPrelinkedInfoDict(anInfoDict, doCoalescedSlides, type)) {
		return NULL;
	}

	return newKext;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::initWithPrelinkedInfoDict(
	OSDictionary * anInfoDict,
	bool doCoalescedSlides,
	kc_kind_t type)
{
	bool            result              = false;
	OSString      * kextPath            = NULL;                // do not release
	OSNumber      * addressNum          = NULL;                // reused; do not release
	OSNumber      * lengthNum           = NULL;                // reused; do not release
	OSBoolean     * scratchBool         = NULL;                // do not release
	void          * data                = NULL;                // do not free
	void          * srcData             = NULL;                // do not free
	OSSharedPtr<OSData>        prelinkedExecutable;
	uint32_t        length              = 0;                // reused
	uintptr_t       kext_slide          = PE_get_kc_slide(type);
	bool            shouldSaveSegments  = false;

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
	IOLog("kaslr: doCoalescedSlides %d kext %s \n", doCoalescedSlides, getIdentifierCString());
#endif

	/* Also get the executable's bundle-relative path if present.
	 * Don't look for an arch-specific path property.
	 */
	executableRelPath.reset(OSDynamicCast(OSString,
	    anInfoDict->getObject(kPrelinkExecutableRelativePathKey)), OSRetain);
	userExecutableRelPath.reset(OSDynamicCast(OSString,
	    anInfoDict->getObject(kCFBundleDriverKitExecutableKey)), OSRetain);

	/* Don't need the paths to be in the info dictionary any more.
	 */
	anInfoDict->removeObject(kPrelinkBundlePathKey);
	anInfoDict->removeObject(kPrelinkExecutableRelativePathKey);

	scratchBool = OSDynamicCast(OSBoolean,
	    getPropertyForHostArch(kOSBundleRequireExplicitLoadKey));
	if (scratchBool == kOSBooleanTrue) {
		flags.requireExplicitLoad = 1;
	}

	/* Create an OSData wrapper around the linked executable.
	 */
	addressNum = OSDynamicCast(OSNumber,
	    anInfoDict->getObject(kPrelinkExecutableLoadKey));
	if (addressNum && addressNum->unsigned64BitValue() != kOSKextCodelessKextLoadAddr) {
		lengthNum = OSDynamicCast(OSNumber,
		    anInfoDict->getObject(kPrelinkExecutableSizeKey));
		if (!lengthNum) {
			OSKextLog(this,
			    kOSKextLogErrorLevel |
			    kOSKextLogArchiveFlag,
			    "Kext %s can't find prelinked kext executable size.",
			    getIdentifierCString());
			return result;
		}

		data = (void *) (((uintptr_t) (addressNum->unsigned64BitValue())) + kext_slide);
		length = (uint32_t) (lengthNum->unsigned32BitValue());

#if KASLR_KEXT_DEBUG
		IOLog("kaslr: unslid 0x%lx slid 0x%lx length %u - prelink executable \n",
		    (unsigned long)ml_static_unslide((vm_offset_t)data),
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
			srcData = (void *) (((uintptr_t) (addressNum->unsigned64BitValue())) + kext_slide);

#if KASLR_KEXT_DEBUG
			IOLog("kaslr: unslid 0x%lx slid 0x%lx - prelink executable source \n",
			    (unsigned long)ml_static_unslide((vm_offset_t)srcData),
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
		setLinkedExecutable(prelinkedExecutable.get());
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
			kmod_info = (kmod_info_t *) (((uintptr_t) (addressNum->unsigned64BitValue())) + kext_slide);
			if (kmod_info->address) {
				kmod_info->address = (((uintptr_t)(kmod_info->address)) + kext_slide);
			} else {
				kmod_info->address = (uintptr_t)data;
				kmod_info->size = length;
			}
#if KASLR_KEXT_DEBUG
			IOLog("kaslr: unslid 0x%lx slid 0x%lx - kmod_info \n",
			    (unsigned long)((vm_offset_t)kmod_info) - kext_slide,
			    (unsigned long)kmod_info);
			IOLog("kaslr: unslid 0x%lx slid 0x%lx - kmod_info->address \n",
			    (unsigned long)((vm_offset_t)kmod_info->address) - kext_slide,
			    (unsigned long)kmod_info->address);
 #endif
		}

		anInfoDict->removeObject(kPrelinkKmodInfoKey);
	}

	if ((addressNum = OSDynamicCast(OSNumber, anInfoDict->getObject("ModuleIndex")))) {
		uintptr_t builtinTextStart;
		uintptr_t builtinTextEnd;

		flags.builtin = true;
		builtinKmodIdx = addressNum->unsigned32BitValue();
		assert(builtinKmodIdx < gBuiltinKmodsCount);

		builtinTextStart = ((uintptr_t *)gBuiltinKmodsSectionStart->addr)[builtinKmodIdx];
		builtinTextEnd   = ((uintptr_t *)gBuiltinKmodsSectionStart->addr)[builtinKmodIdx + 1];

		kmod_info = ((kmod_info_t **)gBuiltinKmodsSectionInfo->addr)[builtinKmodIdx];
		kmod_info->address = builtinTextStart;
		kmod_info->size    = builtinTextEnd - builtinTextStart;
	}

	/* If the plist has a UUID for an interface, save that off.
	 */
	if (isInterface()) {
		interfaceUUID.reset(OSDynamicCast(OSData,
		    anInfoDict->getObject(kPrelinkInterfaceUUIDKey)), OSRetain);
		if (interfaceUUID) {
			anInfoDict->removeObject(kPrelinkInterfaceUUIDKey);
		}
	}

	result = (kOSReturnSuccess == slidePrelinkedExecutable(doCoalescedSlides));
	if (!result) {
		goto finish;
	}

	kc_type = type;
	/* Exclude builtin and codeless kexts */
	if (prelinkedExecutable && kmod_info) {
		switch (kc_type) {
		case KCKindPrimary:
			shouldSaveSegments = (
				getPropertyForHostArch(kOSMutableSegmentCopy) == kOSBooleanTrue ||
				getPropertyForHostArch(kOSBundleAllowUserLoadKey) == kOSBooleanTrue);
			if (shouldSaveSegments) {
				flags.resetSegmentsFromImmutableCopy = 1;
			}
			break;
		case KCKindPageable:
			flags.resetSegmentsFromVnode = 1;
			break;
		case KCKindAuxiliary:
			if (!pageableKCloaded) {
				flags.resetSegmentsFromImmutableCopy = 1;
			} else if (resetAuxKCSegmentOnUnload) {
				flags.resetSegmentsFromVnode = 1;
			}
			break;
		default:
			break;
		}
	}

	if (flags.resetSegmentsFromImmutableCopy) {
		/* Save a pristine copy of the mutable segments */
		kernel_segment_command_t *seg = NULL;
		kernel_mach_header_t *k_mh = (kernel_mach_header_t *)kmod_info->address;

		savedMutableSegments = OSArray::withCapacity(0);

		for (seg = firstsegfromheader(k_mh); seg; seg = nextsegfromheader(k_mh, seg)) {
			if (!segmentIsMutable(seg)) {
				continue;
			}
			uint64_t unslid_vmaddr = seg->vmaddr - kext_slide;
			uint64_t vmsize = seg->vmsize;
			OSKextLog(this, kOSKextLogDebugLevel | kOSKextLogLoadFlag,
			    "Saving kext %s mutable segment %.*s %llx->%llx.", getIdentifierCString(), (int)strnlen(seg->segname, sizeof(seg->segname)), seg->segname, unslid_vmaddr, unslid_vmaddr + vmsize - 1);
			OSSharedPtr<OSKextSavedMutableSegment> savedSegment = OSKextSavedMutableSegment::withSegment(seg);
			if (!savedSegment) {
				OSKextLog(this,
				    kOSKextLogErrorLevel |
				    kOSKextLogGeneralFlag,
				    "Kext %s failed to save mutable segment %llx->%llx.", getIdentifierCString(), unslid_vmaddr, unslid_vmaddr + vmsize - 1);
				result = kOSKextReturnInternalError;
				goto finish;
			}
			savedMutableSegments->setObject(savedSegment);
		}
	}

	if (doCoalescedSlides == false && !flags.resetSegmentsFromVnode) {
		/*
		 * set VM protections now, wire pages for the old style Aux KC now,
		 * wire pages for the rest of the KC types at load time.
		 */
		result = (kOSReturnSuccess == setVMAttributes(true, (type == KCKindAuxiliary) ? true : false));
		if (!result) {
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
	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSSharedPtr<OSKext>
OSKext::withCodelessInfo(OSDictionary * anInfoDict)
{
	OSSharedPtr<OSKext> newKext = OSMakeShared<OSKext>();

	if (newKext && !newKext->initWithCodelessInfo(anInfoDict)) {
		return NULL;
	}

	return newKext;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::initWithCodelessInfo(OSDictionary * anInfoDict)
{
	bool        result      = false;
	OSString  * kextPath    = NULL;        // do not release
	OSBoolean * scratchBool = NULL;        // do not release

	if (anInfoDict == NULL || !super::init()) {
		goto finish;
	}

	/*
	 * Get the path. Don't look for an arch-specific path property.
	 */
	kextPath = OSDynamicCast(OSString,
	    anInfoDict->getObject(kKextRequestArgumentCodelessInfoBundlePathKey));
	if (!kextPath) {
		OSKextLog(NULL,
		    kOSKextLogErrorLevel | kOSKextLogLoadFlag,
		    "Requested codeless kext dictionary does not contain the '%s' key",
		    kKextRequestArgumentCodelessInfoBundlePathKey);
		goto finish;
	}

	uniquePersonalityProperties(anInfoDict);

	if (!setInfoDictionaryAndPath(anInfoDict, kextPath)) {
		goto finish;
	}

	/*
	 * This path is meant to initialize codeless kexts only. Refuse
	 * anything that looks like it has an executable and/or declares
	 * itself as a kernel component.
	 */
	if (declaresExecutable() || isKernelComponent()) {
		OSKextLog(NULL,
		    kOSKextLogErrorLevel | kOSKextLogLoadFlag,
		    "Refusing to register codeless kext that declares an executable/kernel component: %s",
		    getIdentifierCString());
		goto finish;
	}

	if (strcmp(getIdentifierCString(), kIOExcludeListBundleID) == 0) {
		boolean_t updated = updateExcludeList(infoDict.get());
		if (updated) {
			OSKextLog(this,
			    kOSKextLogDebugLevel | kOSKextLogLoadFlag,
			    "KextExcludeList was updated to version: %lld", sExcludeListVersion);
		}
	}

	kc_type = KCKindNone;

	scratchBool = OSDynamicCast(OSBoolean,
	    getPropertyForHostArch(kOSBundleRequireExplicitLoadKey));
	if (scratchBool == kOSBooleanTrue) {
		flags.requireExplicitLoad = 1;
	}

	/* Also get the executable's bundle-relative path if present.
	 * Don't look for an arch-specific path property.
	 */
	userExecutableRelPath.reset(OSDynamicCast(OSString,
	    anInfoDict->getObject(kCFBundleDriverKitExecutableKey)), OSRetain);

	/* remove unnecessary paths from the info dict */
	anInfoDict->removeObject(kKextRequestArgumentCodelessInfoBundlePathKey);

	result = registerIdentifier();

finish:
	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::setAllVMAttributes(void)
{
	OSSharedPtr<OSCollectionIterator> kextIterator;
	const OSSymbol * thisID                 = NULL;        // do not release

	IORecursiveLockLock(sKextLock);

	kextIterator = OSCollectionIterator::withCollection(sKextsByID.get());
	if (!kextIterator) {
		goto finish;
	}

	while ((thisID = OSDynamicCast(OSSymbol, kextIterator->getNextObject()))) {
		OSKext *    thisKext;        // do not release

		thisKext = OSDynamicCast(OSKext, sKextsByID->getObject(thisID));
		if (!thisKext || thisKext->isInterface() || !thisKext->declaresExecutable()) {
			continue;
		}

		if (!thisKext->flags.resetSegmentsFromVnode) {
			/*
			 * set VM protections now, wire pages for the old style Aux KC now,
			 * wire pages for the rest of the KC types at load time.
			 */
			thisKext->setVMAttributes(true, (thisKext->kc_type == KCKindAuxiliary) ? true : false);
		}
	}

finish:
	IORecursiveLockUnlock(sKextLock);

	return;
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSKext>
OSKext::withBooterData(
	OSString * deviceTreeName,
	OSData   * booterData)
{
	OSSharedPtr<OSKext> newKext(OSMakeShared<OSKext>());

	if (newKext && !newKext->initWithBooterData(deviceTreeName, booterData)) {
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
	_BooterKextFileInfo * kextFileInfo   = NULL;        // do not free
	char                * infoDictAddr   = NULL;        // do not free
	void                * executableAddr = NULL;        // do not free
	char                * bundlePathAddr = NULL;        // do not free

	OSDictionary        * theInfoDict    = NULL;        // do not release
	OSSharedPtr<OSObject> parsedXML;
	OSSharedPtr<OSString> kextPath;

	OSSharedPtr<OSString> errorString;
	OSSharedPtr<OSData>   executable;

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

	parsedXML = OSUnserializeXML(infoDictAddr, errorString);
	if (parsedXML) {
		theInfoDict = OSDynamicCast(OSDictionary, parsedXML.get());
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
		bundlePathAddr[kextFileInfo->bundlePathLength - 1] = '\0';         // just in case!

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

	if (!setInfoDictionaryAndPath(theInfoDict, kextPath.get())) {
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
		if (!setExecutable(executable.get(), booterData)) {
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
	return result;
}

/*********************************************************************
*********************************************************************/
bool
OSKext::registerIdentifier(void)
{
	bool            result              = false;
	OSKext        * existingKext        = NULL;        // do not release
	bool            existingIsLoaded    = false;
	bool            existingIsPrelinked = false;
	bool            existingIsCodeless  = false;
	bool            existingIsDext      = false;
	OSKextVersion   newVersion          = -1;
	OSKextVersion   existingVersion     = -1;
	char            newVersionCString[kOSKextVersionMaxLength];
	char            existingVersionCString[kOSKextVersionMaxLength];
	OSSharedPtr<OSData> newUUID;
	OSSharedPtr<OSData> existingUUID;

	IORecursiveLockLock(sKextLock);

	/* Get the new kext's version for checks & log messages.
	 */
	newVersion = getVersion();
	OSKextVersionGetString(newVersion, newVersionCString,
	    kOSKextVersionMaxLength);

	/* If we don't have an existing kext with this identifier,
	 * just record the new kext and we're done!
	 */
	existingKext = OSDynamicCast(OSKext, sKextsByID->getObject(bundleID.get()));
	if (!existingKext) {
		sKextsByID->setObject(bundleID.get(), this);
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
	existingIsDext = existingKext->isDriverKit();
	existingIsCodeless = !existingKext->declaresExecutable() && !existingIsDext;

	/* If we have a non-codeless kext with this identifier that's already
	 * loaded/prelinked, we can't use the new one, but let's be really
	 * thorough and check how the two are related for a precise diagnostic
	 * log message.
	 *
	 * This check is valid for kexts that declare an executable and for
	 * dexts, but not for codeless kexts - we can just replace those.
	 */
	if ((!existingIsCodeless || existingIsDext) &&
	    (existingIsLoaded || existingIsPrelinked)) {
		bool sameVersion = (newVersion == existingVersion);
		bool sameExecutable = true;         // assume true unless we have UUIDs

		/* Only get the UUID if the existing kext is loaded. Doing so
		 * might have to uncompress an mkext executable and we shouldn't
		 * take that hit when neither kext is loaded.
		 *
		 * Note: there is no decompression that happens when all kexts
		 * are loaded from kext collecitons.
		 */
		newUUID = copyUUID();
		existingUUID = existingKext->copyUUID();

		if (existingIsDext && !isDriverKit()) {
			OSKextLog(this,
			    kOSKextLogWarningLevel |
			    kOSKextLogKextBookkeepingFlag,
			    "Notice - new kext %s, v%s matches a %s dext"
			    "with the same bundle ID, v%s.",
			    getIdentifierCString(), newVersionCString,
			    (existingIsLoaded ? "loaded" : "prelinked"),
			    existingVersionCString);
			goto finish;
		}

		/* I'm entirely too paranoid about checking equivalence of executables,
		 * but I remember nasty problems with it in the past.
		 *
		 * - If we have UUIDs for both kexts, compare them.
		 * - If only one kext has a UUID, they're definitely different.
		 */
		if (newUUID && existingUUID) {
			sameExecutable = newUUID->isEqualTo(existingUUID.get());
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
	} /* if ((!existingIsCodeless || existingIsDext) && (existingIsLoaded || existingIsPrelinked)) */

	/* Refuse to allow an existing loaded codeless kext be replaced by a
	 * normal kext with the same bundle ID.
	 */
	if (existingIsCodeless && declaresExecutable()) {
		OSKextLog(this,
		    kOSKextLogWarningLevel | kOSKextLogKextBookkeepingFlag,
		    "Refusing new kext %s, v%s: a codeless copy is already %s",
		    getIdentifierCString(), newVersionCString,
		    (existingIsLoaded ? "loaded" : "prelinked"));
		goto finish;
	}

	/* Dexts packaged in the BootKC will be protected against replacement
	 * by non-dexts by the logic above which checks if they are prelinked.
	 * Dexts which are prelinked into the System KC will be registered
	 * before any other kexts in the AuxKC are registered, and we never
	 * put dexts in the AuxKC. Therefore, there is no need to check if an
	 * existing object is a dext and is being replaced by a non-dext.
	 * The scenario cannot happen by construction.
	 *
	 * See: OSKext::loadFileSetKexts()
	 */

	/* We have two nonloaded/nonprelinked kexts, so our decision depends on whether
	 * user loads are happening or if we're still in early boot. User agents are
	 * supposed to resolve dependencies topside and include only the exact
	 * kexts needed; so we always accept the new kext (in fact we should never
	 * see an older unloaded copy hanging around).
	 */
	if (sUserLoadsActive) {
		sKextsByID->setObject(bundleID.get(), this);
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
		sKextsByID->setObject(bundleID.get(), this);
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
	OSString     * bundleIDString           = NULL;        // do not release
	OSString     * versionString            = NULL;        // do not release
	OSString     * compatibleVersionString  = NULL;        // do not release
	const char   * versionCString           = NULL;        // do not free
	const char   * compatibleVersionCString = NULL;        // do not free
	OSBoolean    * scratchBool              = NULL;        // do not release
	OSDictionary * scratchDict              = NULL;        // do not release

	if (infoDict) {
		panic("Attempt to set info dictionary on a kext "
		    "that already has one (%s).",
		    getIdentifierCString());
	}

	if (!aDictionary || !OSDynamicCast(OSDictionary, aDictionary)) {
		goto finish;
	}

	infoDict.reset(aDictionary, OSRetain);

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
		path.reset(aPath, OSRetain);
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

	compatibleVersion = -1;         // set to illegal value for kexts that don't have

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
			    kCFBundleVersionKey, versionCString);
			goto finish;
		}
	}

	/* Check to see if this kext is in exclude list */
	if (isInExcludeList()) {
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
		flags.interface = 1;         // xxx - hm. the kernel itself isn't an interface...
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
	const char * executableKey = NULL;         // do not free

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
	OSObject       * value       = NULL;        // do not release
	OSString       * stringValue = NULL;        // do not release
	OSSharedPtr<const OSSymbol> symbolValue;

	value = dict->getObject(key);
	if (!value) {
		goto finish;
	}
	if (OSDynamicCast(OSSymbol, value)) {
		/* this is already an OSSymbol: we're good */
		goto finish;
	}

	stringValue = OSDynamicCast(OSString, value);
	if (!stringValue) {
		goto finish;
	}

	symbolValue = OSSymbol::withString(stringValue);
	if (!symbolValue) {
		goto finish;
	}

	dict->setObject(key, symbolValue.get());

finish:
	return;
}

/*********************************************************************
*********************************************************************/
static void
uniqueStringPlistProperty(OSDictionary * dict, const OSString * key)
{
	OSObject       * value       = NULL;        // do not release
	OSString       * stringValue = NULL;        // do not release
	OSSharedPtr<const OSSymbol> symbolValue;

	value = dict->getObject(key);
	if (!value) {
		goto finish;
	}
	if (OSDynamicCast(OSSymbol, value)) {
		/* this is already an OSSymbol: we're good */
		goto finish;
	}

	stringValue = OSDynamicCast(OSString, value);
	if (!stringValue) {
		goto finish;
	}

	symbolValue = OSSymbol::withString(stringValue);
	if (!symbolValue) {
		goto finish;
	}

	dict->setObject(key, symbolValue.get());

finish:
	return;
}

void
OSKext::uniquePersonalityProperties(OSDictionary * personalityDict)
{
	OSKext::uniquePersonalityProperties(personalityDict, true);
}

/*********************************************************************
* Replace common personality property values with uniqued instances
* to save on wired memory.
*********************************************************************/
/* static */
void
OSKext::uniquePersonalityProperties(OSDictionary * personalityDict, bool defaultAddKernelBundleIdentifier)
{
	/* Properties every personality has.
	 */
	uniqueStringPlistProperty(personalityDict, kCFBundleIdentifierKey);
	uniqueStringPlistProperty(personalityDict, kIOProviderClassKey);
	uniqueStringPlistProperty(personalityDict, gIOClassKey.get());
	if (personalityDict->getObject(kCFBundleIdentifierKernelKey)) {
		uniqueStringPlistProperty(personalityDict, kCFBundleIdentifierKernelKey);
	} else if (defaultAddKernelBundleIdentifier) {
		personalityDict->setObject(kCFBundleIdentifierKernelKey, personalityDict->getObject(kCFBundleIdentifierKey));
	}

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

	infoDict.reset();
	bundleID.reset();
	path.reset();
	executableRelPath.reset();
	userExecutableRelPath.reset();
	dependencies.reset();
	linkedExecutable.reset();
	metaClasses.reset();
	interfaceUUID.reset();
	driverKitUUID.reset();

	if (isInterface() && kmod_info) {
		kfree(kmod_info, sizeof(kmod_info_t));
	}

	super::free();
	return;
}

#if PRAGMA_MARK
#pragma mark Mkext files
#endif

#if CONFIG_KXLD
/*
 * mkext archives are really only relevant on kxld-enabled kernels.
 * Without a dynamic kernel linker, we don't need to support any mkexts.
 */

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::readMkextArchive(OSData * mkextData,
    uint32_t * checksumPtr)
{
	OSReturn       result       = kOSKextReturnBadData;
	uint32_t       mkextLength  = 0;
	mkext_header * mkextHeader  = NULL;        // do not free
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
	mkext2_header * mkextHeader                = NULL;        // do not free
	void          * mkextEnd                   = NULL;        // do not free
	uint32_t        mkextVersion;
	uint8_t       * crc_address                = NULL;
	size_t          crc_buffer_size            = 0;
	uint32_t        checksum;
	uint32_t        mkextPlistOffset;
	uint32_t        mkextPlistCompressedSize;
	char          * mkextPlistEnd              = NULL;        // do not free
	uint32_t        mkextPlistFullSize;
	OSSharedPtr<OSString>     errorString;
	OSSharedPtr<OSData>       mkextPlistUncompressedData;
	const char    * mkextPlistDataBuffer       = NULL;        // do not free
	OSSharedPtr<OSObject>      parsedXML;
	OSDictionary  * mkextPlist                 = NULL;        // do not release
	OSArray       * mkextInfoDictArray         = NULL;        // do not release
	uint32_t        count, i;
	kc_format_t kc_format;

	if (!PE_get_primary_kc_format(&kc_format)) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogGeneralFlag,
		    "Unable to determine primary KC format");
		goto finish;
	}

	mkextLength = mkextData->getLength();
	mkextHeader = (mkext2_header *)mkextData->getBytesNoCopy();
	mkextEnd = (char *)mkextHeader + mkextLength;
	mkextVersion = MKEXT_GET_VERSION(mkextHeader);

	crc_address = (u_int8_t *)&mkextHeader->version;
	crc_buffer_size = (uintptr_t)mkextHeader +
	    MKEXT_GET_LENGTH(mkextHeader) - (uintptr_t)crc_address;
	if (crc_buffer_size > INT32_MAX) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogArchiveFlag,
		    "Mkext archive size is too large (%lu > INT32_MAX).",
		    crc_buffer_size);
		result = kOSKextReturnBadData;
		goto finish;
	}
	checksum = mkext_adler32(crc_address, (int32_t)crc_buffer_size);

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
	parsedXML = OSUnserializeXML(mkextPlistDataBuffer, errorString);
	if (parsedXML) {
		mkextPlist = OSDynamicCast(OSDictionary, parsedXML.get());
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
			OSSharedPtr<OSKext> newKext = OSKext::withMkext2Info(infoDict, mkextData);

			/* Fail dynamic loading of a kext when booted from MH_FILESET */
			if (kc_format == KCFormatFileset &&
			    newKext &&
			    !(newKext->isPrelinked()) &&
			    newKext->declaresExecutable()) {
				result = kOSReturnError;
				printf("Kext LOG: Dynamic loading of kext denied for kext %s\n",
				    newKext->getIdentifier() ? newKext->getIdentifierCString() : "unknown kext");

				OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
				    "Dynamic loading of kext denied for kext %s\n",
				    newKext->getIdentifier() ? newKext->getIdentifierCString() : "unknown kext");
				goto finish;
			}
		}
	}

	/* If the caller needs the plist, hand them back our copy
	 */
	if (mkextPlistOut) {
		*mkextPlistOut = mkextPlist;
		parsedXML.detach();
	}

	/* Even if we didn't keep any kexts from the mkext, we may have a load
	 * request to process, so we are successful (no errors occurred).
	 */
	result = kOSReturnSuccess;

finish:
	return result;
}

/* static */
OSReturn
OSKext::readMkext2Archive(
	OSData        * mkextData,
	OSSharedPtr<OSDictionary> &mkextPlistOut,
	uint32_t      * checksumPtr)
{
	OSDictionary * mkextPlist = NULL;
	OSReturn ret;

	if (kOSReturnSuccess == (ret = readMkext2Archive(mkextData,
	    &mkextPlist,
	    checksumPtr))) {
		mkextPlistOut.reset(mkextPlist, OSNoRetain);
	}
	return ret;
}

/*********************************************************************
*********************************************************************/
/* static */
OSSharedPtr<OSKext>
OSKext::withMkext2Info(
	OSDictionary * anInfoDict,
	OSData       * mkextData)
{
	OSSharedPtr<OSKext> newKext = OSMakeShared<OSKext>();

	if (newKext && !newKext->initWithMkext2Info(anInfoDict, mkextData)) {
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
	OSString             * kextPath            = NULL;        // do not release
	OSNumber             * executableOffsetNum = NULL;        // do not release
	OSSharedPtr<OSData>               executable;

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
	executableRelPath.reset(OSDynamicCast(OSString,
	    anInfoDict->getObject(kMKEXTExecutableRelativePathKey)), OSRetain);

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
		if (!setExecutable(executable.get(), mkextData, true)) {
			goto finish;
		}
	}

	result = registerIdentifier();

finish:
	return result;
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSData>
OSKext::createMkext2FileEntry(
	OSData     * mkextData,
	OSNumber   * offsetNum,
	const char * name)
{
	OSSharedPtr<OSData> result;
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
		result.reset();
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
	if (total > UINT32_MAX) {
		panic("z_alloc(%p, %x, %x): overflow caused by %x * %x\n",
		    notused, num_items, size, num_items, size);
	}

	uint64_t   allocSize64 =  total + ((uint64_t)sizeof(zmem));
	//Check for overflow due to addition
	if (allocSize64 > UINT32_MAX) {
		panic("z_alloc(%p, %x, %x): overflow caused by %x + %lx\n",
		    notused, num_items, size, (uint32_t)total, sizeof(zmem));
	}
	uint32_t allocSize = (uint32_t)allocSize64;

	zmem = (z_mem *)kheap_alloc_tag(KHEAP_DATA_BUFFERS, allocSize,
	    Z_WAITOK, VM_KERN_MEMORY_OSKEXT);
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
	kheap_free(KHEAP_DATA_BUFFERS, zmem, zmem->alloc_size);
	return;
}
};

OSSharedPtr<OSData>
OSKext::extractMkext2FileData(
	UInt8      * data,
	const char * name,
	uint32_t     compressedSize,
	uint32_t     fullSize)
{
	OSSharedPtr<OSData>      result;
	OSSharedPtr<OSData>      uncompressedData;        // release on error

	uint8_t     * uncompressedDataBuffer = NULL;        // do not free
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

	result = os::move(uncompressedData);

finish:
	/* Don't bother checking return, nothing we can do on fail.
	 */
	if (zstream_inited) {
		inflateEnd(&zstream);
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

	OSSharedPtr<OSData>        mkextData;
	OSSharedPtr<OSDictionary>  mkextPlist;

	OSSharedPtr<OSArray>       logInfoArray;
	OSSharedPtr<OSSerialize>   serializer;

	OSString       * predicate                   = NULL;        // do not release
	OSDictionary   * requestArgs                 = NULL;        // do not release

	OSString       * kextIdentifier              = NULL;        // do not release
	OSNumber       * startKextExcludeNum         = NULL;        // do not release
	OSNumber       * startMatchingExcludeNum     = NULL;        // do not release
	OSBoolean      * delayAutounloadBool         = NULL;        // do not release
	OSArray        * personalityNames            = NULL;        // do not release

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

	result = readMkext2Archive(mkextData.get(), mkextPlist, NULL);
	if (result != kOSReturnSuccess) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
		    "Failed to read kext load request.");
		goto finish;
	}

	predicate = _OSKextGetRequestPredicate(mkextPlist.get());
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
		/* kextRef */ NULL,
		/* allowDefer */ false,
		delayAutounload,
		startKextExcludeLevel,
		startMatchingExcludeLevel,
		personalityNames);
	if (result != kOSReturnSuccess) {
		goto finish;
	}
	/* If the load came down from the IOKit daemon, it will shortly inform IOCatalogue
	 * for matching via a separate IOKit calldown.
	 */

finish:

	/* Gather up the collected log messages for user space. Any
	 * error messages past this call will not make it up as log messages
	 * but will be in the system log.
	 */
	logInfoArray = OSKext::clearUserSpaceLogFilter();

	if (logInfoArray && logInfoOut && logInfoLengthOut) {
		tempResult = OSKext::serializeLogInfo(logInfoArray.get(),
		    logInfoOut, logInfoLengthOut);
		if (tempResult != kOSReturnSuccess) {
			result = tempResult;
		}
	}

	OSKext::flushNonloadedKexts(/* flushPrelinkedKexts */ false);

	IORecursiveLockUnlock(sKextLock);

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

	return result;
}

#endif // CONFIG_KXLD

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
	OSSharedPtr<OSSerialize>  serializer;
	char         * logInfo            = NULL;        // returned by reference
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

	if (!logInfoArray->serialize(serializer.get())) {
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
	return result;
}

#if PRAGMA_MARK
#pragma mark Instance Management Methods
#endif
/*********************************************************************
*********************************************************************/
OSSharedPtr<OSKext>
OSKext::lookupKextWithIdentifier(const char * kextIdentifier)
{
	OSSharedPtr<OSKext> foundKext;

	IORecursiveLockLock(sKextLock);
	foundKext.reset(OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier)), OSRetain);
	IORecursiveLockUnlock(sKextLock);

	return foundKext;
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSKext>
OSKext::lookupKextWithIdentifier(OSString * kextIdentifier)
{
	return OSKext::lookupKextWithIdentifier(kextIdentifier->getCStringNoCopy());
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSKext>
OSKext::lookupKextWithLoadTag(uint32_t aTag)
{
	OSSharedPtr<OSKext> foundKext;             // returned
	uint32_t i, j;
	OSArray *list[2] = {sLoadedKexts.get(), sLoadedDriverKitKexts.get()};
	uint32_t count[2] = {sLoadedKexts->getCount(), sLoadedDriverKitKexts->getCount()};

	IORecursiveLockLock(sKextLock);

	for (j = 0; j < (sizeof(list) / sizeof(list[0])); j++) {
		for (i = 0; i < count[j]; i++) {
			OSKext * thisKext = OSDynamicCast(OSKext, list[j]->getObject(i));
			if (thisKext->getLoadTag() == aTag) {
				foundKext.reset(thisKext, OSRetain);
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
OSSharedPtr<OSKext>
OSKext::lookupKextWithAddress(vm_address_t address)
{
	OSSharedPtr<OSKext> foundKext;             // returned
	uint32_t count, i;
	kmod_info_t *kmod_info;
	vm_address_t originalAddress;
#if defined(__arm64__)
	uint64_t   textExecBase;
	size_t     textExecSize;
#endif /* defined(__arm64__) */

	originalAddress = address;
#if  __has_feature(ptrauth_calls)
	address = (vm_address_t)VM_KERNEL_STRIP_PTR(address);
#endif /*  __has_feature(ptrauth_calls) */

	IORecursiveLockLock(sKextLock);

	count = sLoadedKexts->getCount();
	for (i = 0; i < count; i++) {
		OSKext * thisKext = OSDynamicCast(OSKext, sLoadedKexts->getObject(i));
		if (thisKext == sKernelKext) {
			continue;
		}
		if (thisKext->kmod_info && thisKext->kmod_info->address) {
			kmod_info = thisKext->kmod_info;
			vm_address_t kext_start = kmod_info->address;
			vm_address_t kext_end = kext_start + kmod_info->size;
			if ((kext_start <= address) && (address < kext_end)) {
				foundKext.reset(thisKext, OSRetain);
				goto finish;
			}
#if defined(__arm64__)
			textExecBase = (uintptr_t) getsegdatafromheader((kernel_mach_header_t *)kmod_info->address, "__TEXT_EXEC", &textExecSize);
			if ((textExecBase <= address) && (address < textExecBase + textExecSize)) {
				foundKext.reset(thisKext, OSRetain);
				goto finish;
			}
#endif /* defined (__arm64__) */
		}
	}
	if ((address >= vm_kernel_stext) && (address < vm_kernel_etext)) {
		foundKext.reset(sKernelKext, OSRetain);
		goto finish;
	}
	/*
	 * DriverKit userspace executables do not have a kernel linkedExecutable,
	 * so we "fake" their address range with the LoadTag. We cannot use the ptrauth-stripped address
	 * here, so use the original address passed to this method.
	 *
	 * This is supposed to be used for logging reasons only. When logd
	 * calls this function it ors the address with FIREHOSE_TRACEPOINT_PC_KERNEL_MASK, so we
	 * remove it here before checking it against the LoadTag.
	 * Also we need to remove FIREHOSE_TRACEPOINT_PC_DYNAMIC_BIT set when emitting the log line.
	 */

	address = originalAddress & ~(FIREHOSE_TRACEPOINT_PC_KERNEL_MASK | FIREHOSE_TRACEPOINT_PC_DYNAMIC_BIT);
	count = sLoadedDriverKitKexts->getCount();
	for (i = 0; i < count; i++) {
		OSKext * thisKext = OSDynamicCast(OSKext, sLoadedDriverKitKexts->getObject(i));
		if (thisKext->getLoadTag() == address) {
			foundKext.reset(thisKext, OSRetain);
		}
	}

finish:
	IORecursiveLockUnlock(sKextLock);

	return foundKext;
}

OSSharedPtr<OSData>
OSKext::copyKextUUIDForAddress(OSNumber *address)
{
	OSSharedPtr<OSData>   uuid;
	OSSharedPtr<OSKext>   kext;

	if (!address) {
		return NULL;
	}

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

	uintptr_t slidAddress = ml_static_slide((uintptr_t)address->unsigned64BitValue());
	if (slidAddress != 0) {
		kext = lookupKextWithAddress(slidAddress);
		if (kext) {
			uuid = kext->copyTextUUID();
		}
	}

	if (!uuid) {
		/*
		 * If we still don't have a UUID, then we failed to match the slid + stripped address with
		 * a kext. This might have happened because the log message came from a dext.
		 *
		 * Try again with the original address.
		 */
		kext = lookupKextWithAddress((vm_address_t)address->unsigned64BitValue());
		if (kext && kext->isDriverKit()) {
			uuid = kext->copyTextUUID();
		}
	}

	return uuid;
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSKext>
OSKext::lookupKextWithUUID(uuid_t wanted)
{
	OSSharedPtr<OSKext> foundKext;             // returned
	uint32_t j, i;
	OSArray *list[2] = {sLoadedKexts.get(), sLoadedDriverKitKexts.get()};
	uint32_t count[2] = {sLoadedKexts->getCount(), sLoadedDriverKitKexts->getCount()};


	IORecursiveLockLock(sKextLock);

	for (j = 0; j < (sizeof(list) / sizeof(list[0])); j++) {
		for (i = 0; i < count[j]; i++) {
			OSKext   * thisKext     = NULL;

			thisKext = OSDynamicCast(OSKext, list[j]->getObject(i));
			if (!thisKext) {
				continue;
			}

			OSSharedPtr<OSData> uuid_data = thisKext->copyUUID();
			if (!uuid_data) {
				continue;
			}

			uuid_t uuid;
			memcpy(&uuid, uuid_data->getBytesNoCopy(), sizeof(uuid));

			if (0 == uuid_compare(wanted, uuid)) {
				foundKext.reset(thisKext, OSRetain);
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
bool
OSKext::isKextWithIdentifierLoaded(const char * kextIdentifier)
{
	bool result = false;
	OSKext * foundKext = NULL;             // returned

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
	OSKext * checkKext = NULL;         // do not release
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

	if (aKext->isInFileset()) {
		OSKextLog(aKext,
		    kOSKextLogProgressLevel |
		    kOSKextLogKextBookkeepingFlag,
		    "Fileset kext %s unloaded.",
		    aKext->getIdentifierCString());
	} else {
		OSKextLog(aKext,
		    kOSKextLogProgressLevel |
		    kOSKextLogKextBookkeepingFlag,
		    "Removing kext %s.",
		    aKext->getIdentifierCString());

		sKextsByID->removeObject(aKext->getIdentifier());
	}
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
	uint32_t i, j;
	OSArray *list[2] = {sLoadedKexts.get(), sLoadedDriverKitKexts.get()};
	uint32_t count[2] = {sLoadedKexts->getCount(), sLoadedDriverKitKexts->getCount()};


	IORecursiveLockLock(sKextLock);

	for (j = 0; j < (sizeof(list) / sizeof(list[0])); j++) {
		for (i = 0; i < count[j]; i++) {
			OSKext * thisKext = OSDynamicCast(OSKext, list[j]->getObject(i));
			if (thisKext->loadTag == loadTag) {
				foundKext = thisKext;
				break;
			}
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
OSSharedPtr<OSDictionary>
OSKext::copyKexts(void)
{
	OSSharedPtr<OSDictionary> result;

	IORecursiveLockLock(sKextLock);
	result = OSDynamicPtrCast<OSDictionary>(sKextsByID->copyCollection());
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
	OSString                  * deviceTreeName      = NULL;        // do not release
	const _DeviceTreeBuffer   * deviceTreeBuffer    = NULL;        // do not release
	char                      * booterDataPtr       = NULL;        // do not release
	_BooterKextFileInfo       * kextFileInfo        = NULL;        // do not release
	char                      * infoDictAddr        = NULL;        // do not release
	OSSharedPtr<OSObject>       parsedXML;
	OSDictionary              * theInfoDict         = NULL;        // do not release

	theIterator->reset();

	/* look for AppleKextExcludeList.kext */
	while ((deviceTreeName =
	    OSDynamicCast(OSString, theIterator->getNextObject()))) {
		const char *    devTreeNameCString;
		OSData *        deviceTreeEntry;        // do not release
		OSString *      myBundleID;        // do not release

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
		    !kextFileInfo->infoDictLength) {
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

		theInfoDict = OSDynamicCast(OSDictionary, parsedXML.get());
		if (!theInfoDict) {
			continue;
		}

		myBundleID =
		    OSDynamicCast(OSString,
		    theInfoDict->getObject(kCFBundleIdentifierKey));
		if (myBundleID &&
		    strcmp( myBundleID->getCStringNoCopy(), kIOExcludeListBundleID ) == 0) {
			boolean_t updated = updateExcludeList(theInfoDict);
			if (!updated) {
				/* 25322874 */
				panic("Missing OSKextExcludeList dictionary\n");
			}
			break;
		}
	}         // while ( (deviceTreeName = ...) )

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
	OSDictionary *  myInfoDict = NULL;        // do not release
	OSString *      myBundleID;        // do not release
	u_int           i;

	/* Find the Apple Kext Exclude List. */
	for (i = 0; i < theInfoArray->getCount(); i++) {
		myInfoDict = OSDynamicCast(OSDictionary, theInfoArray->getObject(i));
		if (!myInfoDict) {
			continue;
		}
		myBundleID =
		    OSDynamicCast(OSString,
		    myInfoDict->getObject(kCFBundleIdentifierKey));
		if (myBundleID &&
		    strcmp( myBundleID->getCStringNoCopy(), kIOExcludeListBundleID ) == 0) {
			boolean_t updated = updateExcludeList(myInfoDict);
			if (!updated) {
				/* 25322874 */
				panic("Missing OSKextExcludeList dictionary\n");
			}
			break;
		}
	}         // for (i = 0; i < theInfoArray->getCount()...

	return;
}

/* static */
boolean_t
OSKext::updateExcludeList(OSDictionary *infoDict)
{
	OSDictionary *myTempDict = NULL;         // do not free
	OSString     *myTempString = NULL;        // do not free
	OSKextVersion newVersion = 0;
	boolean_t updated = false;

	if (!infoDict) {
		return false;
	}

	myTempDict = OSDynamicCast(OSDictionary, infoDict->getObject("OSKextExcludeList"));
	if (!myTempDict) {
		return false;
	}

	myTempString = OSDynamicCast(OSString, infoDict->getObject(kCFBundleVersionKey));
	if (!myTempString) {
		return false;
	}

	newVersion = OSKextParseVersionString(myTempString->getCStringNoCopy());
	if (newVersion == 0) {
		return false;
	}

	IORecursiveLockLock(sKextLock);

	if (newVersion > sExcludeListVersion) {
		sExcludeListByID = OSDictionary::withDictionary(myTempDict, 0);
		sExcludeListVersion = newVersion;
		updated = true;
	}

	IORecursiveLockUnlock(sKextLock);
	return updated;
}

#if PRAGMA_MARK
#pragma mark Accessors
#endif
/*********************************************************************
*********************************************************************/
const OSSymbol *
OSKext::getIdentifier(void)
{
	return bundleID.get();
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
	return getCompatibleVersion() > 0;
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
	if (isDriverKit()) {
		return false;
	}
	return getPropertyForHostArch(kCFBundleExecutableKey) != NULL;
}

/*********************************************************************
*********************************************************************/
OSData *
OSKext::getExecutable(void)
{
	OSData * result              = NULL;
	OSSharedPtr<OSData> extractedExecutable;

	if (flags.builtin) {
		return sKernelKext->linkedExecutable.get();
	}

	result = OSDynamicCast(OSData, infoDict->getObject(_kOSKextExecutableKey));
	if (result) {
		return result;
	}

#if CONFIG_KXLD
	OSData * mkextExecutableRef  = NULL;        // do not release
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
			if (!setExecutable(extractedExecutable.get())) {
				goto finish;
			}
			result = extractedExecutable.get();
		} else {
			goto finish;
		}
	}

finish:
#endif // CONFIG_KXLD
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
	return this == sKernelKext;
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
	return !isKernel() && !isInterface() && declaresExecutable();
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
	OSString * required = NULL;         // do not release

	if (isKernel()) {
		result = true;
		goto finish;
	}

	if (isDriverKit()) {
		result = true;
		goto finish;
	}

	required = OSDynamicCast(OSString,
	    getPropertyForHostArch(kOSBundleRequiredKey));
	if (!required) {
		goto finish;
	}
	if (required->isEqualTo(kOSBundleRequiredRoot) ||
	    required->isEqualTo(kOSBundleRequiredLocalRoot) ||
	    required->isEqualTo(kOSBundleRequiredNetworkRoot) ||
	    required->isEqualTo(kOSBundleRequiredSafeBoot) ||
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
bool
OSKext::isLoaded(void)
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
void
OSKext::getSizeInfo(uint32_t *loadSize, uint32_t *wiredSize)
{
	if (linkedExecutable) {
		*loadSize = linkedExecutable->getLength();

		/* If we have a kmod_info struct, calculated the wired size
		 * from that. Otherwise it's the full load size.
		 */
		if (kmod_info) {
			*wiredSize = *loadSize - (uint32_t)kmod_info->hdr_size;
		} else {
			*wiredSize = *loadSize;
		}
	} else {
		*wiredSize = 0;
		*loadSize = 0;
	}
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSData>
OSKext::copyUUID(void)
{
	OSSharedPtr<OSData>          result;
	OSData                     * theExecutable = NULL;        // do not release
	const kernel_mach_header_t * header;

	/* An interface kext doesn't have a linked executable with an LC_UUID,
	 * we create one when it's linked.
	 */
	if (interfaceUUID) {
		result = interfaceUUID;
		goto finish;
	}

	if (flags.builtin || isInterface()) {
		return sKernelKext->copyUUID();
	}

	if (isDriverKit() && infoDict) {
		return driverKitUUID;
	}

	/* For real kexts, try to get the UUID from the linked executable,
	 * or if is hasn't been linked yet, the unrelocated executable.
	 */
	theExecutable = linkedExecutable.get();
	if (!theExecutable) {
		theExecutable = getExecutable();
	}

	if (!theExecutable) {
		goto finish;
	}

	header = (const kernel_mach_header_t *)theExecutable->getBytesNoCopy();
	result = copyMachoUUID(header);

finish:
	return result;
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSData>
OSKext::copyTextUUID(void)
{
	if (flags.builtin) {
		return copyMachoUUID((const kernel_mach_header_t *)kmod_info->address);
	}
	return copyUUID();
}

/*********************************************************************
*********************************************************************/
OSSharedPtr<OSData>
OSKext::copyMachoUUID(const kernel_mach_header_t * header)
{
	OSSharedPtr<OSData>                     result;
	const struct load_command  * load_cmd      = NULL;
	const struct uuid_command  * uuid_cmd      = NULL;
	uint32_t                     i;

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

void
OSKext::setDriverKitUUID(OSData *uuid)
{
	if (!OSCompareAndSwapPtr(nullptr, uuid, &driverKitUUID)) {
		OSSafeReleaseNULL(uuid);
	}
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

static char *
makeHostArchKey(const char * key, size_t * keySizeOut)
{
	char     * result = NULL;
	size_t     keyLength = strlen(key);
	size_t     keySize;

	/* Add 1 for the ARCH_SEPARATOR_CHAR, and 1 for the '\0'.
	 */
	keySize = 1 + 1 + keyLength + strlen(ARCHNAME);
	result = (char *)kheap_alloc_tag(KHEAP_TEMP, keySize,
	    Z_WAITOK, VM_KERN_MEMORY_OSKEXT);

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
	OSObject * result           = NULL;// do not release
	size_t     hostArchKeySize  = 0;
	char     * hostArchKey      = NULL;// must kfree

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
	if (hostArchKey) {
		kheap_free(KHEAP_TEMP, hostArchKey, hostArchKeySize);
	}
	return result;
}

#if PRAGMA_MARK
#pragma mark Load/Start/Stop/Unload
#endif

#define isWhiteSpace(c) ((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == ',' || (c) == '\n')

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
	OSString *      versionString           = NULL;        // do not release
	char *          versionCString          = NULL;        // do not free
	size_t          i;
	boolean_t       wantLessThan = false;
	boolean_t       wantLessThanEqualTo = false;
	boolean_t       isInExcludeList = true;
	char            myBuffer[32];

	IORecursiveLockLock(sKextLock);

	if (!sExcludeListByID) {
		isInExcludeList = false;
	} else {
		/* look up by bundleID in our exclude list and if found get version
		 * string (or strings) that we will not allow to load
		 */
		versionString = OSDynamicCast(OSString, sExcludeListByID->getObject(bundleID.get()));
		if (versionString == NULL || versionString->getLength() > (sizeof(myBuffer) - 1)) {
			isInExcludeList = false;
		}
	}

	IORecursiveLockUnlock(sKextLock);

	if (!isInExcludeList) {
		return false;
	}

	/* parse version strings */
	versionCString = (char *) versionString->getCStringNoCopy();

	/* look for "LT" or "LE" form of version string, must be in first two
	 * positions.
	 */
	if (*versionCString == 'L' && *(versionCString + 1) == 'T') {
		wantLessThan = true;
		versionCString += 2;
	} else if (*versionCString == 'L' && *(versionCString + 1) == 'E') {
		wantLessThanEqualTo = true;
		versionCString += 2;
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
					return true;
				}
			} else if (wantLessThan) {
				if (version < excludeVers) {
					return true;
				}
			} else if (version == excludeVers) {
				return true;
			}

			/* reset for the next (if any) version string */
			i = 0;
			wantLessThan = false;
			wantLessThanEqualTo = false;
		} else {
			/* save valid version character */
			myBuffer[i++] = *versionCString;

			/* make sure bogus version string doesn't overrun local buffer */
			if (i >= sizeof(myBuffer)) {
				break;
			}
		}
	}

	return false;
}

/*********************************************************************
* sNonLoadableKextsByID is a dictionary with keys / values of:
*  key = bundleID string of kext we will not allow to load
*  value = boolean (true == loadable, false == not loadable)
*
*  Only kexts which are in the AuxKC will be marked as "not loadble,"
*  i.e., the value for the kext's bundleID will be false. All kexts in
*  the primary and system KCs will always be marked as "loadable."
*
*  This list ultimately comes from kexts which have been uninstalled
*  in user space by deleting the kext from disk, but which have not
*  yet been removed from the AuxKC. Because the user could choose to
*  re-install the exact same version of the kext, we need to keep
*  a dictionary of boolean values so that user space only needs to
*  keep a simple list of "uninstalled" or "missing" bundles. When
*  a bundle is re-installed, the iokit daemon can use the
*  AucKCBundleAvailable  predicate to set the individual kext's
*  availability to true.
*********************************************************************/
bool
OSKext::isLoadable(void)
{
	bool isLoadable = true;

	if (kc_type != KCKindAuxiliary) {
		/* this filtering only applies to kexts in the auxkc */
		return true;
	}

	IORecursiveLockLock(sKextLock);

	if (sNonLoadableKextsByID) {
		/* look up by bundleID in our exclude list and if found get version
		 * string (or strings) that we will not allow to load
		 */
		OSBoolean *loadableVal;
		loadableVal = OSDynamicCast(OSBoolean, sNonLoadableKextsByID->getObject(bundleID.get()));
		if (loadableVal && !loadableVal->getValue()) {
			isLoadable = false;
		}
	}
	IORecursiveLockUnlock(sKextLock);

	return isLoadable;
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
	OSSharedPtr<OSString> kextIdentifier;

	kextIdentifier = OSString::withCString(kextIdentifierCString);
	if (!kextIdentifier) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}
	result = OSKext::loadKextWithIdentifier(kextIdentifier.get(),
	    NULL /* kextRef */,
	    allowDeferFlag, delayAutounloadFlag,
	    startOpt, startMatchingOpt, personalityNames);

finish:
	return result;
}

OSReturn
OSKext::loadKextWithIdentifier(
	OSString          * kextIdentifier,
	OSSharedPtr<OSObject>         &kextRef,
	Boolean             allowDeferFlag,
	Boolean             delayAutounloadFlag,
	OSKextExcludeLevel  startOpt,
	OSKextExcludeLevel  startMatchingOpt,
	OSArray           * personalityNames)
{
	OSObject * kextRefRaw = NULL;
	OSReturn result;

	result = loadKextWithIdentifier(kextIdentifier,
	    &kextRefRaw,
	    allowDeferFlag,
	    delayAutounloadFlag,
	    startOpt,
	    startMatchingOpt,
	    personalityNames);
	if ((kOSReturnSuccess == result) && kextRefRaw) {
		kextRef.reset(kextRefRaw, OSNoRetain);
	}
	return result;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSKext::loadKextWithIdentifier(
	OSString          * kextIdentifier,
	OSObject         ** kextRef,
	Boolean             allowDeferFlag,
	Boolean             delayAutounloadFlag,
	OSKextExcludeLevel  startOpt,
	OSKextExcludeLevel  startMatchingOpt,
	OSArray           * personalityNames)
{
	OSReturn          result               = kOSReturnError;
	OSReturn          pingResult           = kOSReturnError;
	OSKext          * theKext              = NULL;        // do not release
	OSSharedPtr<OSDictionary>   loadRequest;
	OSSharedPtr<const OSSymbol> kextIdentifierSymbol;

	if (kextRef) {
		*kextRef = NULL;
	}

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
		if (!sPostedKextLoadIdentifiers->containsObject(kextIdentifierSymbol.get())) {
			result = _OSKextCreateRequest(kKextRequestPredicateRequestLoad,
			    loadRequest);
			if (result != kOSReturnSuccess) {
				goto finish;
			}
			if (!_OSKextSetRequestArgument(loadRequest.get(),
			    kKextRequestArgumentBundleIdentifierKey, kextIdentifier)) {
				result = kOSKextReturnNoMemory;
				goto finish;
			}
			if (!sKernelRequests->setObject(loadRequest.get())) {
				result = kOSKextReturnNoMemory;
				goto finish;
			}

			if (!sPostedKextLoadIdentifiers->setObject(kextIdentifierSymbol.get())) {
				result = kOSKextReturnNoMemory;
				goto finish;
			}

			OSKextLog(theKext,
			    kOSKextLogDebugLevel |
			    kOSKextLogLoadFlag,
			    "Kext %s not found; queued load request to user space.",
			    kextIdentifier->getCStringNoCopy());
		}

		pingResult = OSKext::pingIOKitDaemon();
		if (pingResult == kOSKextReturnDisabled) {
			OSKextLog(/* kext */ NULL,
			    ((sPrelinkBoot) ? kOSKextLogDebugLevel : kOSKextLogErrorLevel) |
			    kOSKextLogLoadFlag,
			    "Kext %s might not load - " kIOKitDaemonName " is currently unavailable.",
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

		if (theKext->kc_type == KCKindUnknown) {
			OSKext::removeKext(theKext,
			    /* terminateService/removePersonalities */ true);
		}
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
	if ((kOSReturnSuccess == result) && kextRef) {
		*kextRef = theKext;
		theKext->matchingRefCount++;
		theKext->retain();
	}

	IORecursiveLockUnlock(sKextLock);

	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::loadKextFromKC(OSKext *theKext, OSDictionary *requestDict)
{
	OSReturn  result = kOSReturnError;

	OSBoolean *delayAutounloadBool     = NULL; // do not release
	OSNumber  *startKextExcludeNum     = NULL; // do not release
	OSNumber  *startMatchingExcludeNum = NULL; // do not release
	OSArray   *personalityNames        = NULL; // do not release

	/*
	 * Default values for these options:
	 *      regular autounload behavior
	 *      start the kext
	 *      send all personalities to the catalog
	 */
	Boolean            delayAutounload           = false;
	OSKextExcludeLevel startKextExcludeLevel     = kOSKextExcludeNone;
	OSKextExcludeLevel startMatchingExcludeLevel = kOSKextExcludeNone;

	IORecursiveLockLock(sKextLock);

	OSKextLog(/* kext */ NULL,
	    kOSKextLogDebugLevel |
	    kOSKextLogIPCFlag,
	    "Received kext KC load request from user space.");

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

	delayAutounloadBool = OSDynamicCast(OSBoolean,
	    _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentDelayAutounloadKey));
	startKextExcludeNum = OSDynamicCast(OSNumber,
	    _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentStartExcludeKey));
	startMatchingExcludeNum = OSDynamicCast(OSNumber,
	    _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentStartMatchingExcludeKey));
	personalityNames = OSDynamicCast(OSArray,
	    _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentPersonalityNamesKey));

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
	    "Received request from user space to load KC kext %s.",
	    theKext->getIdentifierCString());

	/* this could be in the Auxiliary KC, so record the load request */
	OSKext::recordIdentifierRequest(OSDynamicCast(OSString, theKext->getIdentifier()));

	/*
	 * Load the kext
	 */
	result = theKext->load(startKextExcludeLevel,
	    startMatchingExcludeLevel, personalityNames);

	if (result != kOSReturnSuccess) {
		OSKextLog(theKext,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
		    "Failed to load kext %s (error 0x%x).",
		    theKext->getIdentifierCString(), (int)result);

		OSKext::removeKext(theKext,
		    /* terminateService/removePersonalities */ true);
		goto finish;
	} else {
		OSKextLog(theKext,
		    kOSKextLogProgressLevel |
		    kOSKextLogLoadFlag,
		    "Kext %s Loaded successfully from %s KC",
		    theKext->getIdentifierCString(), theKext->getKCTypeString());
	}

	if (delayAutounload) {
		OSKextLog(theKext,
		    kOSKextLogProgressLevel |
		    kOSKextLogLoadFlag | kOSKextLogKextBookkeepingFlag,
		    "Setting delayed autounload for %s.",
		    theKext->getIdentifierCString());
		theKext->flags.delayAutounload = 1;
	}

finish:
	IORecursiveLockUnlock(sKextLock);

	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSReturn
OSKext::loadCodelessKext(OSString *kextIdentifier, OSDictionary *requestDict)
{
	OSReturn  result = kOSReturnError;
	OSDictionary *anInfoDict = NULL; // do not release

	anInfoDict = OSDynamicCast(OSDictionary,
	    _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentCodelessInfoKey));
	if (anInfoDict == NULL) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag | kOSKextLogLoadFlag,
		    "Missing 'Codeless Kext Info' dictionary in codeless kext load request of %s.",
		    kextIdentifier->getCStringNoCopy());
		return kOSKextReturnInvalidArgument;
	}

	IORecursiveLockLock(sKextLock);

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogIPCFlag,
	    "Received request from user space to load codeless kext %s.",
	    kextIdentifier->getCStringNoCopy());

	{
		// instantiate a new kext, and don't hold a reference
		// (the kext subsystem will hold one implicitly)
		OSSharedPtr<OSKext> newKext = OSKext::withCodelessInfo(anInfoDict);
		if (!newKext) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogGeneralFlag | kOSKextLogLoadFlag,
			    "Could not instantiate codeless kext.");
			result = kOSKextReturnNotLoadable;
			goto finish;
		}
		if (!kextIdentifier->isEqualTo(newKext->getIdentifierCString())) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogGeneralFlag | kOSKextLogLoadFlag,
			    "Codeless kext identifiers don't match '%s' != '%s'",
			    kextIdentifier->getCStringNoCopy(), newKext->getIdentifierCString());

			OSKext::removeKext(newKext.get(), false);
			result = kOSKextReturnInvalidArgument;
			goto finish;
		}

		/* Record the request for the codeless kext */
		OSKext::recordIdentifierRequest(OSDynamicCast(OSString, newKext->getIdentifier()));

		result = kOSReturnSuccess;
		/* Send the kext's personalities to the IOCatalog. This is an explicit load. */
		result = newKext->sendPersonalitiesToCatalog(true, NULL);
	}

finish:
	IORecursiveLockUnlock(sKextLock);

	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::dropMatchingReferences(
	OSSet * kexts)
{
	IORecursiveLockLock(sKextLock);
	kexts->iterateObjects(^bool (OSObject * obj) {
		OSKext * thisKext = OSDynamicCast(OSKext, obj);
		if (!thisKext) {
		        return false;
		}
		thisKext->matchingRefCount--;
		return false;
	});
	IORecursiveLockUnlock(sKextLock);
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSKext::recordIdentifierRequest(
	OSString * kextIdentifier)
{
	OSSharedPtr<const OSSymbol> kextIdentifierSymbol;
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
	if (!sAllKextLoadIdentifiers->containsObject(kextIdentifierSymbol.get())) {
		if (!sAllKextLoadIdentifiers->setObject(kextIdentifierSymbol.get())) {
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
	OSKextExcludeLevel   dependenciesStartOpt         = startOpt;
	OSKextExcludeLevel   dependenciesStartMatchingOpt = startMatchingOpt;
	unsigned int         i, count;
	Boolean              alreadyLoaded                = false;
	OSKext             * lastLoadedKext               = NULL;        // do not release

	if (isInExcludeList()) {
		OSKextLog(this,
		    kOSKextLogErrorLevel | kOSKextLogGeneralFlag |
		    kOSKextLogLoadFlag,
		    "Kext %s is in exclude list, not loadable",
		    getIdentifierCString());

		result = kOSKextReturnNotLoadable;
		goto finish;
	}
	if (!isLoadable()) {
		OSKextLog(this,
		    kOSKextLogErrorLevel | kOSKextLogGeneralFlag |
		    kOSKextLogLoadFlag,
		    "Kext %s is not loadable",
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

#if CONFIG_MACF && XNU_TARGET_OS_OSX
#if CONFIG_KXLD
	if (current_task() != kernel_task) {
#else
	/*
	 * On non-kxld systems, only check the mac-hook for kexts in the
	 * Pageable and Aux KCs. This means on Apple silicon devices that
	 * the mac hook will only be useful to block 3rd party kexts.
	 *
	 * Note that this should _not_ be called on kexts loaded from the
	 * kernel bootstrap thread as the kernel proc's cred struct is not
	 * yet initialized! This won't happen on macOS because all the kexts
	 * in the BootKC are self-contained and their kc_type = KCKindPrimary.
	 */
	if (kc_type != KCKindPrimary && kc_type != KCKindUnknown) {
#endif /* CONFIG_KXLD */
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
		/* There is a special case where a non-executable kext can be loaded: the
		 * AppleKextExcludeList.  Detect that special kext by bundle identifier and
		 * load its metadata into the global data structures, if appropriate
		 */
		if (strcmp(getIdentifierCString(), kIOExcludeListBundleID) == 0) {
			boolean_t updated = updateExcludeList(infoDict.get());
			if (updated) {
				OSKextLog(this,
				    kOSKextLogDebugLevel | kOSKextLogLoadFlag,
				    "KextExcludeList was updated to version: %lld", sExcludeListVersion);
			}
		}

		if (isDriverKit()) {
			if (loadTag == 0) {
				sLoadedDriverKitKexts->setObject(this);
				loadTag = sNextLoadTag++;
			}
		}
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

#if !VM_MAPPED_KEXTS
	if (isPrelinked() == false) {
		OSKextLog(this,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
		    "Can't load kext %s - not in a kext collection.",
		    getIdentifierCString());
		result = kOSKextReturnDisabled;
		goto finish;
	}
#endif /* defined(__x86_64__) */

#if CONFIG_KXLD
	if (!sKxldContext) {
		kern_return_t kxldResult;
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
#endif // CONFIG_KXLD

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

	// The kernel PRNG is not initialized when the first kext is
	// loaded, so use early random
	uuid_generate_early_random(instance_uuid);
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
	if (gIOSurfaceIdentifier == bundleID) {
		vm_tag_alloc(&account->site);
		gIOSurfaceTag = account->site.tag;
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
		    OSDynamicCast(OSString, bundleID.get()));
	}
	return result;
}

#if CONFIG_KXLD
/*********************************************************************
*
*********************************************************************/
static char *
strdup(const char * string)
{
	char * result = NULL;
	size_t size;

	if (!string) {
		goto finish;
	}

	size = 1 + strlen(string);
	result = (char *)kheap_alloc_tag(KHEAP_DATA_BUFFERS, size,
	    Z_WAITOK, VM_KERN_MEMORY_OSKEXT);
	if (!result) {
		goto finish;
	}

	memcpy(result, string, size);

finish:
	return result;
}
#endif // CONFIG_KXLD

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

	if (!linkedExecutable) {
		return NULL;
	}

	mh = (kernel_mach_header_t *)linkedExecutable->getBytesNoCopy();

	for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
		if (0 != strncmp(seg->segname, segname, sizeof(seg->segname))) {
			continue;
		}

		for (sec = firstsect(seg); sec != NULL; sec = nextsect(seg, sec)) {
			if (0 == strncmp(sec->sectname, secname, sizeof(sec->sectname))) {
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
OSKext::slidePrelinkedExecutable(bool doCoalescedSlides)
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

	if (linkedExecutable == NULL || flags.builtin) {
		result = kOSReturnSuccess;
		goto finish;
	}

	mh = (kernel_mach_header_t *)linkedExecutable->getBytesNoCopy();
	if (kernel_mach_header_is_in_fileset(mh)) {
		// kexts in filesets are slid as part of collection sliding
		result = kOSReturnSuccess;
		goto finish;
	}

	segmentSplitInfo = (struct linkedit_data_command *) getcommandfromheader(mh, LC_SEGMENT_SPLIT_INFO);

	for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
		if (!seg->vmaddr) {
			continue;
		}

		seg->vmaddr = ml_static_slide(seg->vmaddr);

#if KASLR_KEXT_DEBUG
		IOLog("kaslr: segname %s unslid 0x%lx slid 0x%lx \n",
		    seg->segname,
		    (unsigned long)ml_static_unslide(seg->vmaddr),
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
			sec->addr = ml_static_slide(sec->addr);

#if KASLR_KEXT_DEBUG
			IOLog("kaslr: sectname %s unslid 0x%lx slid 0x%lx \n",
			    sec->sectname,
			    (unsigned long)ml_static_unslide(sec->addr),
			    (unsigned long)sec->addr);
#endif
		}
	}

	dysymtab = (struct dysymtab_command *) getcommandfromheader(mh, LC_DYSYMTAB);

	symtab = (struct symtab_command *) getcommandfromheader(mh, LC_SYMTAB);

	if (symtab != NULL && doCoalescedSlides == false) {
		/* Some pseudo-kexts have symbol tables without segments.
		 * Ignore them. */
		if (symtab->nsyms > 0 && haveLinkeditBase) {
			sym = (kernel_nlist_t *) (linkeditBase + symtab->symoff);
			for (i = 0; i < symtab->nsyms; i++) {
				if (sym[i].n_type & N_STAB) {
					continue;
				}
				sym[i].n_value = ml_static_slide(sym[i].n_value);

#if KASLR_KEXT_DEBUG
#define MAX_SYMS_TO_LOG 5
				if (i < MAX_SYMS_TO_LOG) {
					IOLog("kaslr: LC_SYMTAB unslid 0x%lx slid 0x%lx \n",
					    (unsigned long)ml_static_unslide(sym[i].n_value),
					    (unsigned long)sym[i].n_value);
				}
#endif
			}
		}
	}

	if (dysymtab != NULL && doCoalescedSlides == false) {
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
				if (reloc[i].r_extern != 0
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
				uintptr_t *relocAddr = (uintptr_t*)(relocBase + reloc[i].r_address);
				*relocAddr = ml_static_slide(*relocAddr);

#if KASLR_KEXT_DEBUG
#define MAX_DYSYMS_TO_LOG 5
				if (i < MAX_DYSYMS_TO_LOG) {
					IOLog("kaslr: LC_DYSYMTAB unslid 0x%lx slid 0x%lx \n",
					    (unsigned long)ml_static_unslide(*((uintptr_t *)(relocAddr))),
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
			if (new_kextsize > UINT_MAX) {
				OSKextLog(this,
				    kOSKextLogErrorLevel | kOSKextLogLoadFlag |
				    kOSKextLogLinkFlag,
				    "Kext %s: new kext size is too large.",
				    getIdentifierCString());
				goto finish;
			}
			if (((kmod_info->size - new_kextsize) > PAGE_SIZE) && (!segmentSplitInfo)) {
				vm_offset_t     endofkext = kmod_info->address + kmod_info->size;
				vm_offset_t     new_endofkext = kmod_info->address + new_kextsize;
				vm_offset_t     endofrelocInfo = (vm_offset_t) (((uint8_t *)reloc) + reloc_size);
				size_t          bytes_remaining = endofkext - endofrelocInfo;
				OSSharedPtr<OSData>        new_osdata;

				/* fix up symbol offsets if they are after the dsymtab local relocs */
				if (symtab) {
					if (dysymtab->locreloff < symtab->symoff) {
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

				new_osdata = OSData::withBytesNoCopy((void *)kmod_info->address, (unsigned int)new_kextsize);
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
					linkedExecutable = os::move(new_osdata);

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
	OSSharedPtr<OSArray>  linkDependencies;
	uint32_t              num_kmod_refs      = 0;
	OSData              * theExecutable      = NULL;        // do not release
	OSString            * versString         = NULL;        // do not release
	const char          * versCString        = NULL;        // do not free
	const char          * string             = NULL;        // do not free

#if CONFIG_KXLD
	unsigned int          i;
	uint32_t              numDirectDependencies   = 0;
	kern_return_t         kxldResult;
	KXLDDependency     *  kxlddeps           = NULL;        // must kfree
	uint32_t              num_kxlddeps       = 0;
	struct mach_header ** kxldHeaderPtr      = NULL;        // do not free
	struct mach_header  * kxld_header        = NULL;        // xxx - need to free here?
#endif // CONFIG_KXLD

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

#if defined(__x86_64__) || defined(__i386__)
	if (flags.resetSegmentsFromVnode) {
		/* Fixup the chains and slide the mach headers */
		kernel_mach_header_t *mh = (kernel_mach_header_t *)kmod_info->address;

		if (i386_slide_individual_kext(mh, PE_get_kc_slide(kc_type)) != KERN_SUCCESS) {
			result = kOSKextReturnValidation;
			goto finish;
		}
	}
#endif //(__x86_64__) || defined(__i386__)

	if (isPrelinked()) {
		goto register_kmod;
	}

	/* <rdar://problem/21444003> all callers must be entitled */
	if (FALSE == IOTaskHasEntitlement(current_task(), kOSKextCollectionManagementEntitlement)) {
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
		OSSharedPtr<OSData> executableCopy = OSData::withData(theExecutable);
		if (executableCopy) {
			setLinkedExecutable(executableCopy.get());
		}
		goto register_kmod;
	}

#if CONFIG_KXLD
	numDirectDependencies = getNumDependencies();

	if (flags.hasBleedthrough) {
		linkDependencies = dependencies;
	} else {
		linkDependencies = OSArray::withArray(dependencies.get());
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
			dependencyKext->addBleedthroughDependencies(linkDependencies.get());
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

	for (i = 0; i < num_kxlddeps; ++i) {
		OSKext * dependency = OSDynamicCast(OSKext, linkDependencies->getObject(i));

		if (dependency->isInterface()) {
			OSKext *interfaceTargetKext = NULL;        //do not release
			OSData * interfaceTarget = NULL;        //do not release

			if (dependency->isKernelComponent()) {
				interfaceTargetKext = sKernelKext;
				interfaceTarget = sKernelKext->linkedExecutable.get();
			} else {
				interfaceTargetKext = OSDynamicCast(OSKext,
				    dependency->dependencies->getObject(0));

				interfaceTarget = interfaceTargetKext->linkedExecutable.get();
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

			if (dependency->linkedExecutable != NULL) {
				kxlddeps[i].interface = (u_char *) dependency->linkedExecutable->getBytesNoCopy();
				kxlddeps[i].interface_size = dependency->linkedExecutable->getLength();
			} else {
				kxlddeps[i].interface = (u_char *) NULL;
				kxlddeps[i].interface_size = 0;
			}
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

#else // !CONFIG_KXLD
	OSKextLog(this, kOSKextLogErrorLevel | kOSKextLogLoadFlag,
	    "Refusing to link non-prelinked kext: %s (no kxld support)", getIdentifierCString());
	result = kOSKextReturnLinkError;
	goto finish;
#endif // CONFIG_KXLD

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
	kmod_info->reference_count = 0;         // KMOD_DECL... sets it to -1 (invalid).

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

	if (kmod_info->hdr_size > UINT32_MAX) {
		OSKextLog(this,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
#if __LP64__
		    "Kext %s header size is too large (%lu > UINT32_MAX).",
#else
		    "Kext %s header size is too large (%u > UINT32_MAX).",
#endif
		    kmod_info->name,
		    kmod_info->hdr_size);
		result = KERN_FAILURE;
		goto finish;
	}

	if (kmod_info->size > UINT32_MAX) {
		OSKextLog(this,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
#if __LP64__
		    "Kext %s size is too large (%lu > UINT32_MAX).",
#else
		    "Kext %s size is too large (%u > UINT32_MAX).",
#endif
		    kmod_info->name,
		    kmod_info->size);
		result = KERN_FAILURE;
		goto finish;
	}

	if (!isInterface() && linkedExecutable) {
		OSKextLog(this,
		    kOSKextLogProgressLevel |
		    kOSKextLogLoadFlag,
		    "Kext %s executable loaded; %u pages at 0x%lx (load tag %u).",
		    kmod_info->name,
		    (unsigned)kmod_info->size / PAGE_SIZE,
		    (unsigned long)ml_static_unslide(kmod_info->address),
		    (unsigned)kmod_info->id);
	}

	/* VM protections and wiring for the Aux KC are done at collection loading time */
	if (kc_type != KCKindAuxiliary || flags.resetSegmentsFromVnode) {
		/* if prelinked and primary KC, VM protections are already set */
		result = setVMAttributes(!isPrelinked() || flags.resetSegmentsFromVnode, true);
		if (result != KERN_SUCCESS) {
			goto finish;
		}
	}

#if KASAN
	if (linkedExecutable) {
		kasan_load_kext((vm_offset_t)linkedExecutable->getBytesNoCopy(),
		    linkedExecutable->getLength(), getIdentifierCString());
	}
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

#if CONFIG_KXLD
	/* Clear up locally allocated dependency info.
	 */
	for (i = 0; i < num_kxlddeps; ++i) {
		size_t size;

		if (kxlddeps[i].kext_name) {
			size = 1 + strlen(kxlddeps[i].kext_name);
			kheap_free(KHEAP_DATA_BUFFERS, kxlddeps[i].kext_name, size);
		}
		if (kxlddeps[i].interface_name) {
			size = 1 + strlen(kxlddeps[i].interface_name);
			kheap_free(KHEAP_DATA_BUFFERS, kxlddeps[i].interface_name, size);
		}
	}
	if (kxlddeps) {
		kfree(kxlddeps, (num_kxlddeps * sizeof(*kxlddeps)));
	}
#endif // CONFIG_KXLD

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
			kmod_info = NULL;
		}
		if (kc_type == KCKindUnknown) {
			kmod_info = NULL;
			if (linkedExecutable) {
				linkedExecutable.reset();
			}
		}
	}

	return result;
}

#if VM_MAPPED_KEXTS
/* static */
void
OSKext::jettisonFileSetLinkeditSegment(kernel_mach_header_t *mh)
{
	kernel_segment_command_t *linkeditseg = NULL;

	linkeditseg = getsegbynamefromheader(mh, SEG_LINKEDIT);
	assert(linkeditseg != NULL);

	/* BootKC on x86_64 is not vm mapped */
	ml_static_mfree(linkeditseg->vmaddr, linkeditseg->vmsize);

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogGeneralFlag,
	    "Jettisoning fileset Linkedit segments from vmaddr %llx with size %llu",
	    linkeditseg->vmaddr, linkeditseg->vmsize);
}
#endif /* VM_MAPPED_KEXTS */

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
	OSSharedPtr<OSData>        data;

	if (isInFileset()) {
		return;
	}

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
	    round_page(linkedit->vmaddr + linkedit->vmsize)) {
		goto finish;
	}

	/* Create a new OSData for the smaller kext object.
	 */
	linkeditsize = round_page(linkedit->vmsize);
	kextsize = kmod_info->size - linkeditsize;
	start = linkedit->vmaddr;

	if (kextsize > UINT_MAX) {
		goto finish;
	}
	data = OSData::withBytesNoCopy((void *)kmod_info->address, (unsigned int)kextsize);
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
	linkedExecutable = os::move(data);
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

	if (flags.builtin) {
		return;
	}
	mh = (kernel_mach_header_t *)kmod_info->address;

	if (isInFileset()) {
		return;
	}

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
	linkedExecutable.reset(anExecutable, OSRetain);
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
		OSKext   * thisKext     = NULL;        // do not release

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

#if VM_MAPPED_KEXTS
		if (!sKeepSymbols && kc_type == KCKindPrimary) {
			if (forceInit == kOSBooleanTrue) {
				/* Make sure the kext is not from the Boot KC */
				panic("OSBundleForceDTraceInit key specified for the Boot KC kext : %s", getIdentifierCString());
			} else {
				/* Linkedit segment of the Boot KC is gone, make sure fbt_provide_module don't use kernel symbols */
				modflag |= KMOD_DTRACE_NO_KERNEL_SYMS;
			}
		}
#endif /* VM_MAPPED_KEXTS */
		if (forceInit == kOSBooleanTrue) {
			modflag |= KMOD_DTRACE_FORCE_INIT;
		}
		if (flags.builtin) {
			modflag |= KMOD_DTRACE_STATIC_KEXT;
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
	kernel_mach_header_t *kext_mh,
	vm_map_t   map,
	vm_map_offset_t    start,
	vm_map_offset_t    end,
	vm_prot_t  new_prot,
	boolean_t  set_max,
	kc_kind_t  kc_type)
{
#pragma unused(kext_mh,map,kc_type)
	assert(map == kernel_map);         // we can handle KEXTs arising from the PRELINK segment and no others
	assert(start <= end);
	if (start >= end) {
		return KERN_SUCCESS;         // Punt segments of length zero (e.g., headers) or less (i.e., blunders)
	} else if (set_max) {
		return KERN_SUCCESS;         // Punt set_max, as there's no mechanism to record that state
	} else {
		return ml_static_protect(start, end - start, new_prot);
	}
}

static inline kern_return_t
OSKext_wire(
	kernel_mach_header_t *kext_mh,
	vm_map_t   map,
	vm_map_offset_t    start,
	vm_map_offset_t    end,
	vm_prot_t  access_type,
	boolean_t       user_wire,
	kc_kind_t       kc_type)
{
#pragma unused(kext_mh,map,start,end,access_type,user_wire,kc_type)
	return KERN_SUCCESS;         // No-op as PRELINK kexts are cemented into physical memory at boot
}
#else
#error Unrecognized architecture
#endif
#else
static inline kern_return_t
OSKext_protect(
	kernel_mach_header_t *kext_mh,
	vm_map_t   map,
	vm_map_offset_t    start,
	vm_map_offset_t    end,
	vm_prot_t  new_prot,
	boolean_t  set_max,
	kc_kind_t  kc_type)
{
	if (start == end) {         // 10538581
		return KERN_SUCCESS;
	}
	if (kernel_mach_header_is_in_fileset(kext_mh) && kc_type == KCKindPrimary) {
		/*
		 * XXX: This will probably need to be different for AuxKC and
		 * pageableKC!
		 */
		return ml_static_protect(start, end - start, new_prot);
	}
	return vm_map_protect(map, start, end, new_prot, set_max);
}

static inline kern_return_t
OSKext_wire(
	kernel_mach_header_t *kext_mh,
	vm_map_t   map,
	vm_map_offset_t    start,
	vm_map_offset_t    end,
	vm_prot_t  access_type,
	boolean_t       user_wire,
	kc_kind_t       kc_type)
{
	if (kernel_mach_header_is_in_fileset(kext_mh) && kc_type == KCKindPrimary) {
		/* TODO: we may need to hook this for the pageableKC */
		return KERN_SUCCESS;
	}
	return vm_map_wire_kernel(map, start, end, access_type, VM_KERN_MEMORY_KEXT, user_wire);
}
#endif

OSReturn
OSKext::setVMAttributes(bool protect, bool wire)
{
	vm_map_t                    kext_map        = NULL;
	kernel_segment_command_t  * seg             = NULL;
	vm_map_offset_t             start_protect   = 0;
	vm_map_offset_t             start_wire      = 0;
	vm_map_offset_t             end_protect     = 0;
	vm_map_offset_t             end_wire        = 0;
	OSReturn                    result          = kOSReturnError;

	if (isInterface() || !declaresExecutable() || flags.builtin) {
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

	if (isInFileset() && kc_type != KCKindPageable) {
		// kexts in filesets have protections setup as part of collection loading
		result = KERN_SUCCESS;
		goto finish;
	}
#endif

	/* Protect the headers as read-only; they do not need to be wired */
	result = (protect) ? OSKext_protect((kernel_mach_header_t *)kmod_info->address,
	    kext_map, kmod_info->address,
	    kmod_info->address + kmod_info->hdr_size, VM_PROT_READ, TRUE, kc_type)
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

		/*
		 * For the non page aligned segments, the range calculation for protection
		 * and wiring differ as follows:
		 *
		 * Protection: The non page aligned data at the start or at the end of the
		 * segment is excluded from the protection. This exclusion is needed to make
		 * sure OSKext_protect is not called twice on same page, if the page is shared
		 * between two segments.
		 *
		 * Wiring: The non page aligned data at the start or at the end of the
		 * segment is included in the wiring range, this inclusion is needed to make sure
		 * all the data of the segment is wired.
		 */
		start_protect = round_page(seg->vmaddr);
		end_protect = trunc_page(seg->vmaddr + seg->vmsize);

		start_wire = trunc_page(seg->vmaddr);
		end_wire = round_page(seg->vmaddr + seg->vmsize);

		/*
		 * Linkedit and Linkinfo for the Pageable KC and the Aux KC are shared
		 * across kexts and data from kexts is not page aligned
		 */
		if (protect && (end_protect > start_protect) &&
		    ((strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) != 0 &&
		    strncmp(seg->segname, SEG_LINKINFO, sizeof(seg->segname)) != 0) ||
		    (kc_type != KCKindPageable && kc_type != KCKindAuxiliary))) {
			result = OSKext_protect((kernel_mach_header_t *)kmod_info->address,
			    kext_map, start_protect, end_protect, seg->maxprot, TRUE, kc_type);
			if (result != KERN_SUCCESS) {
				OSKextLog(this,
				    kOSKextLogErrorLevel |
				    kOSKextLogLoadFlag,
				    "Kext %s failed to set maximum VM protections "
				    "for segment %s - 0x%x.",
				    getIdentifierCString(), seg->segname, (int)result);
				goto finish;
			}

			result = OSKext_protect((kernel_mach_header_t *)kmod_info->address,
			    kext_map, start_protect, end_protect, seg->initprot, FALSE, kc_type);
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
			result = OSKext_wire((kernel_mach_header_t *)kmod_info->address,
			    kext_map, start_wire, end_wire, seg->initprot, FALSE, kc_type);
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
	return sKeepSymbols || (strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) &&
	       strncmp(seg->segname, SEG_LINKINFO, sizeof(seg->segname)));
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
	uint64_t                              kext_segbase = 0;
	uint64_t                              kext_segsize = 0;
	mach_msg_type_number_t                count;
	vm_region_submap_short_info_data_64_t info;
	uintptr_t                             kext_slide = PE_get_kc_slide(kc_type);

	if (flags.builtin) {
		return kOSReturnSuccess;
	}

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
	if (isInFileset()) {
#if defined(HAS_APPLE_PAC)
		address = (mach_vm_address_t)ptrauth_auth_data((void*)address, ptrauth_key_function_pointer, 0);
#endif /* defined(HAS_APPLE_PAC) */
	}

	/* Verify that the start/stop function lies within the kext's address range.
	 */
	if (getcommandfromheader((kernel_mach_header_t *)kmod_info->address, LC_SEGMENT_SPLIT_INFO) ||
	    isInFileset()) {
		/* This will likely be how we deal with split kexts; walk the segments to
		 * check that the function lies inside one of the segments of this kext.
		 */
		for (seg = firstsegfromheader((kernel_mach_header_t *)kmod_info->address);
		    seg != NULL;
		    seg = nextsegfromheader((kernel_mach_header_t *)kmod_info->address, seg)) {
			if ((address >= seg->vmaddr) && address < (seg->vmaddr + seg->vmsize)) {
				kext_segbase = seg->vmaddr;
				kext_segsize = seg->vmsize;
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
			    (void *)(((uintptr_t)address) - kext_slide),
			    (void *)(((uintptr_t)kmod_info->address) - kext_slide));
			result = kOSKextReturnBadData;
			goto finish;
		}

		seg = NULL;
	} else {
		if (address < kmod_info->address + kmod_info->hdr_size ||
		    kmod_info->address + kmod_info->size <= address) {
			OSKextLog(this,
			    kOSKextLogErrorLevel |
			    kOSKextLogLoadFlag,
			    "Kext %s module %s pointer is outside of kext range "
			    "(%s %p - kext at %p-%p).",
			    getIdentifierCString(),
			    whichOp,
			    whichOp,
			    (void *)(((uintptr_t)address) - kext_slide),
			    (void *)(((uintptr_t)kmod_info->address) - kext_slide),
			    (void *)((((uintptr_t)kmod_info->address) - kext_slide) + kmod_info->size));
			result = kOSKextReturnBadData;
			goto finish;
		}
	}

	/* Only do these checks before calling the start function;
	 * If anything goes wrong with the mapping while the kext is running,
	 * we'll likely have panicked well before any attempt to stop the kext.
	 */
	if (startFlag) {
		if (!isInFileset() || kc_type != KCKindPrimary) {
			/*
			 * Verify that the start/stop function is executable.
			 */
			kern_result = mach_vm_region_recurse(kernel_map, &address, &size, &depth,
			    (vm_region_recurse_info_t)&info, &count);
			if (kern_result != KERN_SUCCESS) {
				OSKextLog(this,
				    kOSKextLogErrorLevel |
				    kOSKextLogLoadFlag,
				    "Kext %s - bad %s pointer %p.",
				    getIdentifierCString(),
				    whichOp, (void *)ml_static_unslide(address));
				result = kOSKextReturnBadData;
				goto finish;
			}
		} else {
			/*
			 * Since kexts loaded from the primary KC are held in memory
			 * allocated by efiboot, we cannot use mach_vm_region_recurse() to
			 * discover that memory's protection flags.  Instead, we need to
			 * get that information from the kernel pmap itself.  Above, we
			 * (potentially) saved the size of the segment in which the address
			 * in question was located.  If we have a non-zero size, verify
			 * that all pages in the (address, address + kext_segsize) range
			 * are marked executable.  If we somehow did not record the size
			 * (or the base) just verify the single page that includes the address.
			 */
			if (kext_segbase == 0 || kext_segsize == 0) {
				kext_segbase = address & ~(uint64_t)PAGE_MASK;
				kext_segsize = PAGE_SIZE;
			}
		}

#if VM_MAPPED_KEXTS
		if (((!isInFileset() || kc_type != KCKindPrimary) && !(info.protection & VM_PROT_EXECUTE)) ||
		    ((isInFileset() && kc_type == KCKindPrimary) &&
		    ml_static_verify_page_protections(kext_segbase, kext_segsize, VM_PROT_EXECUTE) != KERN_SUCCESS)) {
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

	if (seg->vmsize > UINT32_MAX) {
		return false;
	}

	if (!segmentShouldBeWired(seg)) {
		return true;
	}

	for (address = seg->vmaddr;
	    address < round_page(seg->vmaddr + seg->vmsize);
	    address += PAGE_SIZE) {
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
	OSSharedPtr<OSData>                 uuid_data;

	stamp = firehose_tracepoint_time(firehose_activity_flags_default);
	trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_metadata, _firehose_tracepoint_type_metadata_kext, (firehose_tracepoint_flags_t)0, code);

	uuid_data = aKext->copyTextUUID();
	if (uuid_data) {
		memcpy(uuid_info->ftui_uuid, uuid_data->getBytesNoCopy(), sizeof(uuid_info->ftui_uuid));
	}

	uuid_info->ftui_size    = size;
	if (aKext->isDriverKit()) {
		uuid_info->ftui_address = address;
	} else {
		uuid_info->ftui_address = ml_static_unslide(address);
	}
	firehose_trace_metadata(firehose_stream_metadata, trace_id, stamp, uuid_info, uuid_info_len);
	return;
}

void
OSKext::OSKextLogDriverKitInfoLoad(OSKext *kext)
{
	OSKextLogKextInfo(kext, kext->getLoadTag(), 1, firehose_tracepoint_code_load);
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
				result = kOSKextReturnStartStopError;         // xxx - make new return?
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
	result = OSRuntimeInitializeCPP(this);
	if (result == KERN_SUCCESS) {
		result = startfunc(kmod_info, kmodStartData);
	}

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
		    kOSKextLogWarningLevel |
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
bool
OSKext::canUnloadKextWithIdentifier(
	OSString * kextIdentifier,
	bool       checkClassesFlag)
{
	bool     result = false;
	OSKext * aKext  = NULL;        // do not release

	IORecursiveLockLock(sKextLock);

	aKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextIdentifier));

	if (!aKext) {
		goto finish;         // can't unload what's not loaded
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
		if (result == KERN_SUCCESS) {
			result = OSRuntimeFinalizeCPP(this);
		}

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
	bool            in_fileset = false;

	if (!sUnloadEnabled) {
		OSKextLog(this,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
		    "Kext unloading is disabled (%s).",
		    this->getIdentifierCString());

		result = kOSKextReturnDisabled;
		goto finish;
	}

	// cache this result so we don't need to access the kmod_info after
	// it's been potentially free'd
	in_fileset = isInFileset();

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

	if (isDriverKit()) {
		index = sLoadedKexts->getNextIndexOfObject(this, 0);
		if (index != (unsigned int)-1) {
			sLoadedDriverKitKexts->removeObject(index);
			OSKextLogKextInfo(this, loadTag, 1, firehose_tracepoint_code_unload);
			loadTag = 0;
		}
	}

	if (!isLoaded()) {
		result = kOSReturnSuccess;
		goto finish;
	}

	if (isKernelComponent()) {
		result = kOSKextReturnInvalidArgument;
		goto finish;
	}

	if (metaClasses && !OSMetaClass::removeClasses(metaClasses.get())) {
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
	(void) OSRuntimeFinalizeCPP(this);

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
			} else {         /* index == 0 */
				nextKext->kmod_info->next = NULL;
			}
		}

		OSKext * lastKext = OSDynamicCast(OSKext, sLoadedKexts->getLastObject());
		if (lastKext && !lastKext->isKernel()) {
			kmod = lastKext->kmod_info;
		} else {
			kmod = NULL;         // clear the global kmod variable
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
	if (account->site.tag) {
		account->site.flags |= VM_TAG_UNLOAD;
	} else {
		freeAccount = account;
	}
	IOSimpleLockUnlock(sKextAccountsLock);
	if (freeAccount) {
		IODelete(freeAccount, OSKextAccount, 1);
	}

	/* Unwire and free the linked executable.
	 */
	if (linkedExecutable) {
#if KASAN
		kasan_unload_kext((vm_offset_t)linkedExecutable->getBytesNoCopy(), linkedExecutable->getLength());
#endif

#if VM_MAPPED_KEXTS
		if (!isInterface() && (!in_fileset || flags.resetSegmentsFromVnode)) {
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
					vm_map_offset_t start_wire = trunc_page(seg->vmaddr);
					vm_map_offset_t end_wire = round_page(seg->vmaddr + seg->vmsize);

					result = vm_map_unwire(kext_map, start_wire,
					    end_wire, FALSE);
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
#if defined(__x86_64__) || defined(__i386__)
			if (in_fileset && flags.resetSegmentsFromVnode) {
				IORecursiveLockLock(sKextLock);
				resetKCFileSetSegments();
				IORecursiveLockUnlock(sKextLock);
			}
#endif // (__x86_64__) || defined(__i386__)
		}
#endif /* VM_MAPPED_KEXTS */
		if (flags.resetSegmentsFromImmutableCopy) {
			result = resetMutableSegments();
			if (result != kOSReturnSuccess) {
				OSKextLog(this,
				    kOSKextLogErrorLevel |
				    kOSKextLogLoadFlag,
				    "Failed to reset kext %s.",
				    getIdentifierCString());
				result = kOSKextReturnInternalError;
				goto finish;
			}
		}
		if (kc_type == KCKindUnknown) {
			linkedExecutable.reset();
		}
	}

	/* An interface kext has a fake kmod_info that was allocated,
	 * so we have to free it.
	 */
	if (isInterface()) {
		kfree(kmod_info, sizeof(kmod_info_t));
		kmod_info = NULL;
	}

	if (!in_fileset) {
		kmod_info = NULL;
	}

	flags.loaded = false;
	flushDependencies();

	/* save a copy of the bundle ID for us to check when deciding to
	 * rebuild the kernel cache file.  If a kext was already in the kernel
	 * cache and unloaded then later loaded we do not need to rebuild the
	 * kernel cache.  9055303
	 */
	if (isPrelinked()) {
		if (!_OSKextInUnloadedPrelinkedKexts(bundleID.get())) {
			IORecursiveLockLock(sKextLock);
			if (sUnloadedPrelinkedKexts) {
				sUnloadedPrelinkedKexts->setObject(bundleID.get());
			}
			IORecursiveLockUnlock(sKextLock);
		}
	}

	OSKextLog(this,
	    kOSKextLogProgressLevel | kOSKextLogLoadFlag,
	    "Kext %s unloaded.", getIdentifierCString());

	queueKextNotification(kKextRequestPredicateUnloadNotification,
	    OSDynamicCast(OSString, bundleID.get()));

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
	OSSharedPtr<OSDictionary>    loadRequest;

	if (!kextIdentifier) {
		result = kOSKextReturnInvalidArgument;
		goto finish;
	}

	/* Create a new request unless one is already sitting
	 * in sKernelRequests for this bundle identifier
	 */
	result = _OSKextCreateRequest(notificationName, loadRequest);
	if (result != kOSReturnSuccess) {
		goto finish;
	}
	if (!_OSKextSetRequestArgument(loadRequest.get(),
	    kKextRequestArgumentBundleIdentifierKey, kextIdentifier)) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}
	if (!sKernelRequests->setObject(loadRequest.get())) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}

	/* We might want to only queue the notification if the IOKit daemon is active,
	 * but that wouldn't work for embedded. Note that we don't care if
	 * the ping immediately succeeds here so don't do anything with the
	 * result of this call.
	 */
	OSKext::pingIOKitDaemon();

	result = kOSReturnSuccess;

finish:
	return result;
}


#if CONFIG_KXLD
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
		sDestroyLinkContextThread = NULL;
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
		&_OSKextConsiderDestroyingLinkContext, NULL);
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

#else // !CONFIG_KXLD

/* static */
void
OSKext::considerDestroyingLinkContext(void)
{
	return;
}

#endif // CONFIG_KXLD

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

#if NO_KEXTD
	/*
	 * Do not unload prelinked kexts on platforms that do not have an
	 * IOKit daemon as there is no way to reload the kext or restart
	 * matching.
	 */
	if (aKext->isPrelinked()) {
		goto finish;
	}
#endif /* defined(__x86_64__) */

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
void
OSKext::considerUnloads(Boolean rescheduleOnlyFlag)
{
	AbsoluteTime when;

	IORecursiveLockLock(sKextInnerLock);

	if (!sUnloadCallout) {
		sUnloadCallout = thread_call_allocate(&_OSKextConsiderUnloads, NULL);
	}

	/* we only reset delay value for unloading if we already have something
	 * pending.  rescheduleOnlyFlag should not start the count down.
	 */
	if (rescheduleOnlyFlag && !sConsiderUnloadsPending) {
		goto finish;
	}

	thread_call_cancel(sUnloadCallout);
	if (OSKext::getAutounloadEnabled() && !sSystemSleep
#if !NO_KEXTD
	    && sIOKitDaemonActive
#endif
	    ) {
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
IOReturn
OSKextSystemSleepOrWake(UInt32 messageType)
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

#ifdef CONFIG_KXLD
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
	OSSharedPtr<OSDictionary>         prelinkRequest;
	OSSharedPtr<OSCollectionIterator> kextIterator;
	const OSSymbol * thisID                 = NULL;        // do not release
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

	/* We need to wait for the IOKit daemon to get up and running with unloads already done
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
	kextIterator = OSCollectionIterator::withCollection(sKextsByID.get());
	if (!kextIterator) {
		goto finish;
	}

	while ((thisID = OSDynamicCast(OSSymbol, kextIterator->getNextObject()))) {
		OSKext *    thisKext;        // do not release

		thisKext = OSDynamicCast(OSKext, sKextsByID->getObject(thisID));
		if (!thisKext || thisKext->isPrelinked() || thisKext->isKernel()) {
			continue;
		}

		if (_OSKextInUnloadedPrelinkedKexts(thisKext->bundleID.get())) {
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
	    prelinkRequest);
	if (checkResult != kOSReturnSuccess) {
		goto finish;
	}

	if (!sKernelRequests->setObject(prelinkRequest.get())) {
		goto finish;
	}

	OSKext::pingIOKitDaemon();

finish:
	IORecursiveLockUnlock(sKextLock);

	return;
}

#else /* !CONFIG_KXLD */

void
OSKext::considerRebuildOfPrelinkedKernel(void)
{
	/* in a non-dynamic kext loading world, there is never a reason to rebuild */
	return;
}

#endif /* CONFIG_KXLD */

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
	OSSharedPtr<OSArray>   localLoopStack;
	bool                   addedToLoopStack         = false;
	OSDictionary         * libraries                = NULL;        // do not release
	OSSharedPtr<OSCollectionIterator> libraryIterator;
	OSString             * libraryID                = NULL;        // do not release
	OSKext               * libraryKext              = NULL;        // do not release
	bool                   hasRawKernelDependency   = false;
	bool                   hasKernelDependency      = false;
	bool                   hasKPIDependency         = false;
	bool                   hasPrivateKPIDependency  = false;
	unsigned int           count;

#if CONFIG_KXLD
	OSString             * infoString               = NULL;        // do not release
	OSString             * readableString           = NULL;        // do not release
#endif // CONFIG_KXLD

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

		localLoopStack = OSArray::withCapacity(6);         // any small capacity will do
		if (!localLoopStack) {
			OSKextLog(this,
			    kOSKextLogErrorLevel |
			    kOSKextLogDependenciesFlag,
			    "Kext %s can't create bookkeeping stack to resolve dependencies.",
			    getIdentifierCString());
			goto finish;
		}
		loopStack = localLoopStack.get();
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
		    0 == strncmp(library_id, KERNEL_LIB, sizeof(KERNEL_LIB) - 1)) {
			hasRawKernelDependency = true;
		} else if (STRING_HAS_PREFIX(library_id, KERNEL_LIB_PREFIX)) {
			hasKernelDependency = true;
		} else if (STRING_HAS_PREFIX(library_id, KPI_LIB_PREFIX)) {
			hasKPIDependency = true;
			if (!strncmp(library_id, PRIVATE_KPI, sizeof(PRIVATE_KPI) - 1)) {
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
			dependencyKext->addBleedthroughDependencies(dependencies.get());
		}
	}
#endif /* __LP64__ */

#if CONFIG_KXLD
	/*
	 * If we're not dynamically linking kexts, then we don't need to check
	 * copyright strings. The linker in user space has already done this.
	 */
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
#endif // CONFIG_KXLD

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
			dependencies.reset();
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
	return dependencies.get();
}

bool
OSKext::hasDependency(const OSSymbol * depID)
{
	bool result __block;

	if (depID == getIdentifier()) {
		return true;
	}
	if (!dependencies) {
		return false;
	}
	result = false;
	dependencies->iterateObjects(^bool (OSObject * obj) {
		OSKext * kext;
		kext = OSDynamicCast(OSKext, obj);
		if (!kext) {
		        return false;
		}
		result = (depID == kext->getIdentifier());
		return result;
	});
	return result;
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
		const OSMetaClass * metaScan  = NULL;        // do not release

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
	return metaClasses.get();
}

/*********************************************************************
*********************************************************************/
bool
OSKext::hasOSMetaClassInstances(void)
{
	bool                   result        = false;
	OSSharedPtr<OSCollectionIterator> classIterator;
	OSMetaClass          * checkClass    = NULL;        // do not release

	if (!metaClasses) {
		goto finish;
	}

	classIterator = OSCollectionIterator::withCollection(metaClasses.get());
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
	OSSharedPtr<OSKext> theKext;

	theKext = OSKext::lookupKextWithIdentifier(kextIdentifier);
	if (!theKext) {
		goto finish;
	}

	theKext->reportOSMetaClassInstances(msgLogSpec);
finish:
	return;
}

/*********************************************************************
*********************************************************************/
void
OSKext::reportOSMetaClassInstances(OSKextLogSpec msgLogSpec)
{
	OSSharedPtr<OSCollectionIterator> classIterator;
	OSMetaClass          * checkClass    = NULL;        // do not release

	if (!metaClasses) {
		goto finish;
	}

	classIterator = OSCollectionIterator::withCollection(metaClasses.get());
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
	return;
}

#if PRAGMA_MARK
#pragma mark User-Space Requests
#endif

static kern_return_t
patchDextLaunchRequests(task_t calling_task, OSArray *requests)
{
	OSReturn result = kOSReturnSuccess;
	for (uint32_t requestIndex = 0; requestIndex < requests->getCount(); requestIndex++) {
		OSDictionary * request = NULL;         //do not release
		IOUserServerCheckInToken * token = NULL;         //do not release
		OSString * requestPredicate = NULL;         //do not release
		OSSharedPtr<OSNumber> portNameNumber;
		mach_port_name_t portName = 0;
		request = OSDynamicCast(OSDictionary, requests->getObject(requestIndex));
		if (!request) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
			    "Elements of request should be of type OSDictionary");
			result = kOSKextReturnInternalError;
			goto finish;
		}
		requestPredicate = _OSKextGetRequestPredicate(request);
		if (!requestPredicate) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
			    "Failed to get request predicate");
			result = kOSKextReturnInternalError;
			goto finish;
		}
		// is this a dext launch?
		if (requestPredicate->isEqualTo(kKextRequestPredicateRequestDaemonLaunch)) {
			token = OSDynamicCast(IOUserServerCheckInToken, _OSKextGetRequestArgument(request, kKextRequestArgumentCheckInToken));
			if (!token) {
				OSKextLog(/* kext */ NULL,
				    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
				    "Could not find a IOUserServerCheckInToken in daemon launch request.");
				result = kOSKextReturnInternalError;
				goto finish;
			}
			portName = iokit_make_send_right(calling_task, token, IKOT_IOKIT_IDENT);
			if (portName == 0 || portName == MACH_PORT_DEAD) {
				OSKextLog(/* kext */ NULL,
				    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
				    "Could not create send right for object.");
				result = kOSKextReturnInternalError;
				goto finish;
			}
			// Store the mach port name as a OSNumber
			portNameNumber = OSNumber::withNumber(portName, CHAR_BIT * sizeof(portName));
			if (!portNameNumber) {
				OSKextLog(/* kext */ NULL,
				    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
				    "Could not create OSNumber object.");
				result = kOSKextReturnNoMemory;
				goto finish;
			}
			if (!_OSKextSetRequestArgument(request, kKextRequestArgumentCheckInToken, portNameNumber.get())) {
				OSKextLog(/* kext */ NULL,
				    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
				    "Could not set OSNumber object as request " kKextRequestArgumentCheckInToken);
				result = kOSKextReturnNoMemory;
				goto finish;
			}
		}
finish:
		if (result != kOSReturnSuccess) {
			break;
		}
	}
	return result;
}

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

	char         * response           = NULL;        // returned by reference
	uint32_t       responseLength     = 0;

	bool           taskCanManageAllKCs   = false;
	bool           taskOnlyManagesBootKC = false;

	OSSharedPtr<OSObject>     parsedXML;
	OSDictionary            * requestDict    = NULL;        // do not release
	OSSharedPtr<OSString>     errorString;

	OSSharedPtr<OSObject>     responseObject;

	OSSharedPtr<OSSerialize>  serializer;

	OSSharedPtr<OSArray>      logInfoArray;

	OSString     * predicate          = NULL;        // do not release
	OSString     * kextIdentifier     = NULL;        // do not release
	OSArray      * kextIdentifiers    = NULL;        // do not release
	OSKext       * theKext            = NULL;        // do not release
	OSBoolean    * boolArg            = NULL;        // do not release

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
	parsedXML = OSUnserializeXML((const char *)requestBuffer, errorString);
	if (parsedXML) {
		requestDict = OSDynamicCast(OSDictionary, parsedXML.get());
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

	/*
	 * All management of file sets requires an entitlement
	 */
	result = kOSKextReturnNotPrivileged;
	if (predicate->isEqualTo(kKextRequestPredicateUnload) ||
	    predicate->isEqualTo(kKextRequestPredicateStart) ||
	    predicate->isEqualTo(kKextRequestPredicateStop) ||
	    predicate->isEqualTo(kKextRequestPredicateGetKernelRequests) ||
	    predicate->isEqualTo(kKextRequestPredicateSendResource) ||
	    predicate->isEqualTo(kKextRequestPredicateLoadFileSetKC) ||
	    predicate->isEqualTo(kKextRequestPredicateLoadCodeless) ||
	    predicate->isEqualTo(kKextRequestPredicateLoadFromKC) ||
	    predicate->isEqualTo(kKextRequestPredicateMissingAuxKCBundles) ||
	    predicate->isEqualTo(kKextRequestPredicateAuxKCBundleAvailable) ||
	    predicate->isEqualTo(kKextRequestPredicateDaemonReady)) {
		if (hostPriv == HOST_PRIV_NULL) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Access Failure - must be root user.");
			goto finish;
		}
		taskCanManageAllKCs = IOTaskHasEntitlement(current_task(), kOSKextCollectionManagementEntitlement) == TRUE;
		taskOnlyManagesBootKC = IOTaskHasEntitlement(current_task(), kOSKextOnlyBootKCManagementEntitlement) == TRUE;

		if (!taskCanManageAllKCs && !taskOnlyManagesBootKC) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Access Failure - client not entitled to manage file sets.");
			goto finish;
		}

		/*
		 * The OnlyBootKC entitlement restricts the
		 * collection-management entitlement to only managing kexts in
		 * the BootKC. All other predicates that alter global state or
		 * add new KCs are disallowed.
		 */
		if (taskOnlyManagesBootKC &&
		    (predicate->isEqualTo(kKextRequestPredicateGetKernelRequests) ||
		    predicate->isEqualTo(kKextRequestPredicateSendResource) ||
		    predicate->isEqualTo(kKextRequestPredicateLoadFileSetKC) ||
		    predicate->isEqualTo(kKextRequestPredicateLoadCodeless) ||
		    predicate->isEqualTo(kKextRequestPredicateMissingAuxKCBundles) ||
		    predicate->isEqualTo(kKextRequestPredicateAuxKCBundleAvailable) ||
		    predicate->isEqualTo(kKextRequestPredicateDaemonReady))) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Access Failure - client not entitled to manage non-primary KCs");
			goto finish;
		}

		/*
		 * If we get here, then the process either has the full KC
		 * management entitlement, or it has the BootKC-only
		 * entitlement and the request is about the BootKC.
		 */
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

	if (taskOnlyManagesBootKC &&
	    theKext &&
	    theKext->isInFileset() &&
	    theKext->kc_type != KCKindPrimary) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogIPCFlag,
		    "Access Failure - client not entitled to manage kext in non-primary KC");
		result = kOSKextReturnNotPrivileged;
		goto finish;
	}

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
	} else if (predicate->isEqualTo(kKextRequestPredicateMissingAuxKCBundles)) {
		result = OSKext::setMissingAuxKCBundles(requestDict);
	} else if (predicate->isEqualTo(kKextRequestPredicateAuxKCBundleAvailable)) {
		if (!kextIdentifier) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Invalid arguments to AuxKC Bundle Available request.");
		} else {
			result = OSKext::setAuxKCBundleAvailable(kextIdentifier, requestDict);
		}
	} else if (predicate->isEqualTo(kKextRequestPredicateLoadFromKC)) {
		if (!kextIdentifier) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Invalid arguments to kext load from KC request.");
		} else if (!theKext) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Kext %s not found for load from KC request.",
			    kextIdentifier->getCStringNoCopy());
			result = kOSKextReturnNotFound;
		} else if (!theKext->isInFileset()) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Kext %s does not exist in a KC: refusing to load.",
			    kextIdentifier->getCStringNoCopy());
			result = kOSKextReturnNotLoadable;
		} else {
			result = OSKext::loadKextFromKC(theKext, requestDict);
		}
	} else if (predicate->isEqualTo(kKextRequestPredicateLoadCodeless)) {
		if (!kextIdentifier) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Invalid arguments to codeless kext load interface (missing identifier).");
		} else {
			result = OSKext::loadCodelessKext(kextIdentifier, requestDict);
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
	    predicate->isEqualTo(kKextRequestPredicateGetLoadedByUUID) ||
	    predicate->isEqualTo(kKextRequestPredicateGetKextsInCollection)) {
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
		} else if (predicate->isEqualTo(kKextRequestPredicateGetLoadedByUUID)) {
			responseObject = OSKext::copyLoadedKextInfoByUUID(kextIdentifiers, infoKeys);
		} else if (predicate->isEqualTo(kKextRequestPredicateGetKextsInCollection)) {
			responseObject = OSKext::copyKextCollectionInfo(requestDict, infoKeys);
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
		responseObject = os::move(sKernelRequests);
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
		OSKextLog(/* kext */ NULL,
		    kOSKextLogDebugLevel |
		    kOSKextLogIPCFlag,
		    "Returning load requests.");
		result = kOSReturnSuccess;
	} else if (predicate->isEqualTo(kKextRequestPredicateLoadFileSetKC)) {
		printf("KextLog: Loading FileSet KC(s)\n");
		result = OSKext::loadFileSetKexts(requestDict);
	} else if (predicate->isEqualTo(kKextRequestPredicateDaemonReady)) {
		printf("KextLog: " kIOKitDaemonName " is %s\n", sIOKitDaemonActive ? "active" : "not active");
		result = (sIOKitDaemonActive && !sOSKextWasResetAfterUserspaceReboot) ? kOSReturnSuccess : kIOReturnNotReady;
	} else {
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
		/*
		 * Before serializing the kernel requests, patch the dext launch requests so
		 * that the value for kKextRequestArgumentCheckInToken is a mach port name for the
		 * IOUserServerCheckInToken kernel object.
		 */
		if (predicate->isEqualTo(kKextRequestPredicateGetKernelRequests)) {
			OSArray * requests = OSDynamicCast(OSArray, responseObject.get());
			task_t calling_task = current_task();
			if (!requests) {
				OSKextLog(/* kext */ NULL,
				    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
				    "responseObject should be an OSArray if predicate is " kKextRequestPredicateGetKernelRequests);
				result = kOSKextReturnInternalError;
				goto finish;
			}
			result = patchDextLaunchRequests(calling_task, requests);
			if (result != kOSReturnSuccess) {
				OSKextLog(/* kext */ NULL,
				    kOSKextLogGeneralFlag | kOSKextLogErrorLevel,
				    "Failed to patch dext launch requests.");
				goto finish;
			}
		}

		if (!responseObject->serialize(serializer.get())) {
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
		(void)OSKext::serializeLogInfo(logInfoArray.get(),
		    logInfoOut, logInfoLengthOut);
	}

	IORecursiveLockUnlock(sKextLock);

	return result;
}

#if PRAGMA_MARK
#pragma mark Linked Kext Collection Support
#endif

static int
__whereIsAddr(vm_offset_t theAddr, unsigned long *segSizes, vm_offset_t *segAddrs, int segCount)
{
	for (int i = 0; i < segCount; i++) {
		vm_offset_t segStart = segAddrs[i];
		vm_offset_t segEnd = segStart + (vm_offset_t)segSizes[i];

		if (theAddr >= segStart && theAddr < segEnd) {
			return i;
		}
	}
	return -1;
}

static void
__slideOldKaslrOffsets(kernel_mach_header_t *mh,
    kernel_segment_command_t *kextTextSeg,
    OSData *kaslrOffsets)
{
	static const char *plk_segNames[] = {
		"__TEXT",
		"__TEXT_EXEC",
		"__DATA",
		"__DATA_CONST",
		"__LINKEDIT",
		"__PRELINK_TEXT",
		"__PLK_TEXT_EXEC",
		"__PRELINK_DATA",
		"__PLK_DATA_CONST",
		"__PLK_LLVM_COV",
		"__PLK_LINKEDIT",
		"__PRELINK_INFO"
	};
	static const size_t num_plk_seg = (size_t)(sizeof(plk_segNames) / sizeof(plk_segNames[0]));

	unsigned long plk_segSizes[num_plk_seg];
	vm_offset_t   plk_segAddrs[num_plk_seg];

	for (size_t i = 0; i < num_plk_seg; i++) {
		plk_segSizes[i] = 0;
		plk_segAddrs[i] = (vm_offset_t)getsegdatafromheader(mh, plk_segNames[i], &plk_segSizes[i]);
	}

	uint64_t kextTextStart = (uint64_t)kextTextSeg->vmaddr;

	int slidKextAddrCount = 0;
	int badSlideAddr = 0;
	int badSlideTarget = 0;

	struct kaslrPackedOffsets {
		uint32_t    count;          /* number of offsets */
		uint32_t    offsetsArray[];        /* offsets to slide */
	};
	const struct kaslrPackedOffsets *myOffsets = NULL;
	myOffsets = (const struct kaslrPackedOffsets *)kaslrOffsets->getBytesNoCopy();

	for (uint32_t j = 0; j < myOffsets->count; j++) {
		uint64_t   slideOffset = (uint64_t)myOffsets->offsetsArray[j];
		vm_offset_t *slideAddr = (vm_offset_t *)((uint64_t)kextTextStart + slideOffset);
		int        slideAddrSegIndex = -1;
		int        addrToSlideSegIndex = -1;

		slideAddrSegIndex = __whereIsAddr((vm_offset_t)slideAddr, &plk_segSizes[0], &plk_segAddrs[0], num_plk_seg);
		if (slideAddrSegIndex >= 0) {
			addrToSlideSegIndex = __whereIsAddr(ml_static_slide(*slideAddr), &plk_segSizes[0], &plk_segAddrs[0], num_plk_seg);
			if (addrToSlideSegIndex < 0) {
				badSlideTarget++;
				continue;
			}
		} else {
			badSlideAddr++;
			continue;
		}

		slidKextAddrCount++;
		*slideAddr = ml_static_slide(*slideAddr);
	}         // for ...
}



/********************************************************************
* addKextsFromKextCollection
*
* Input: MachO header of kext collection. The MachO is assumed to
*        have a section named 'info_seg_name,info_sect_name' that
*        contains a serialized XML info dictionary. This dictionary
*        contains a UUID, possibly a set of relocations (for older
*        kxld-built binaries), and an array of kext personalities.
*
********************************************************************/
bool
OSKext::addKextsFromKextCollection(kernel_mach_header_t *mh,
    OSDictionary *infoDict, const char *text_seg_name,
    OSData **kcUUID, kc_kind_t type)
{
	bool result = false;

	OSArray *kextArray     = NULL;        // do not release
	OSData *infoDictKCUUID = NULL;         // do not release
	OSData *kaslrOffsets   = NULL;        // do not release

	IORegistryEntry *registryRoot = NULL;         // do not release
	OSSharedPtr<OSNumber> kcKextCount;

	/* extract the KC UUID from the dictionary */
	infoDictKCUUID = OSDynamicCast(OSData, infoDict->getObject(kPrelinkInfoKCIDKey));
	if (infoDictKCUUID) {
		if (infoDictKCUUID->getLength() != sizeof(uuid_t)) {
			panic("kcUUID length is %d, expected %lu",
			    infoDictKCUUID->getLength(), sizeof(uuid_t));
		}
	}

	/* locate the array of kext dictionaries */
	kextArray = OSDynamicCast(OSArray, infoDict->getObject(kPrelinkInfoDictionaryKey));
	if (!kextArray) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "The given KC has no kext info dictionaries");
		goto finish;
	}

	/*
	 * old-style KASLR offsets may be present in the info dictionary. If
	 * we find them, use them and eventually slide them.
	 */
	kaslrOffsets = OSDynamicCast(OSData, infoDict->getObject(kPrelinkLinkKASLROffsetsKey));

	/*
	 * Before processing any kexts, locate the special kext bundle which
	 * contains a list of kexts that we are to prevent from loading.
	 */
	createExcludeListFromPrelinkInfo(kextArray);

	/*
	 * Create OSKext objects for each kext we find in the array of kext
	 * info plist dictionaries.
	 */
	for (int i = 0; i < (int)kextArray->getCount(); ++i) {
		OSDictionary *kextDict = NULL;
		kextDict = OSDynamicCast(OSDictionary, kextArray->getObject(i));
		if (!kextDict) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
			    "Kext info dictionary for kext #%d isn't a dictionary?", i);
			continue;
		}

		/*
		 * Create the kext for the entry, then release it, because the
		 * kext system keeps a reference around until the kext is
		 * explicitly removed.  Any creation/registration failures are
		 * already logged for us.
		 */
		withPrelinkedInfoDict(kextDict, (kaslrOffsets ? TRUE : FALSE), type);
	}

	/*
	 * slide old-style kxld relocations
	 * NOTE: this is still used on embedded KCs built with kcgen
	 * TODO: Remove this once we use the new kext linker everywhere!
	 */
	if (kaslrOffsets && vm_kernel_slide > 0) {
		kernel_segment_command_t *text_segment = NULL;
		text_segment = getsegbynamefromheader(mh, text_seg_name);
		if (!text_segment) {
			OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
			    "Can't find a TEXT segment named '%s' in macho header", text_seg_name);
			goto finish;
		}

		__slideOldKaslrOffsets(mh, text_segment, kaslrOffsets);
		/* All kexts covered by the old-style kaslr relocation list are now slid, set VM protections for them */
		setAllVMAttributes();
	}

	/* Store the number of prelinked kexts in the registry so we can tell
	 * when the system has been started from a prelinked kernel.
	 */
	registryRoot = IORegistryEntry::getRegistryRoot();
	assert(registryRoot);

	kcKextCount = OSNumber::withNumber((unsigned long long)infoDict->getCount(), 8 * sizeof(uint32_t));
	assert(kcKextCount);
	if (kcKextCount) {
		OSSharedPtr<OSObject> prop = registryRoot->copyProperty(kOSPrelinkKextCountKey);
		OSNumber *num;
		num = OSDynamicCast(OSNumber, prop.get());
		if (num) {
			kcKextCount->addValue(num->unsigned64BitValue());
		}
		registryRoot->setProperty(kOSPrelinkKextCountKey, kcKextCount.get());
	}

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogGeneralFlag | kOSKextLogKextBookkeepingFlag |
	    kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
	    "%u prelinked kexts", infoDict->getCount());


	if (kcUUID && infoDictKCUUID) {
		*kcUUID = OSData::withData(infoDictKCUUID).detach();
	}

	result = true;

finish:
	return result;
}

bool
OSKext::addKextsFromKextCollection(kernel_mach_header_t *mh,
    OSDictionary *infoDict, const char *text_seg_name,
    OSSharedPtr<OSData> &kcUUID, kc_kind_t type)
{
	OSData  *result = NULL;
	bool success = addKextsFromKextCollection(mh,
	    infoDict,
	    text_seg_name,
	    &result,
	    type);
	if (success) {
		kcUUID.reset(result, OSNoRetain);
	}
	return success;
}

static OSSharedPtr<OSObject> deferredAuxKCXML;
bool
OSKext::registerDeferredKextCollection(kernel_mach_header_t *mh,
    OSSharedPtr<OSObject> &parsedXML, kc_kind_t type)
{
	if (type != KCKindAuxiliary) {
		return false;
	}

	kernel_mach_header_t *_mh;
	_mh = (kernel_mach_header_t*)PE_get_kc_header(type);
	if (!_mh || _mh != mh) {
		return false;
	}

	if (deferredAuxKCXML) {
		/* only allow this to be called once */
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "An Aux KC has already been registered for deferred processing.");
		return false;
	}

	OSDictionary *infoDict = OSDynamicCast(OSDictionary, parsedXML.get());
	if (!infoDict) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "The Aux KC has info dictionary");
		return false;
	}

	OSData *kcUUID = OSDynamicCast(OSData, infoDict->getObject(kPrelinkInfoKCIDKey));
	if (!kcUUID || kcUUID->getLength() != sizeof(uuid_t)) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "The Aux KC has no UUID in %s", kPrelinkInfoKCIDKey);
		return false;
	}

	/*
	 * Copy the AuxKC UUID to make sure that the kern.auxiliaryfilesetuuid
	 * sysctl can return the UUID to user space which will check this
	 * value for errors.
	 */
	memcpy((void *)&auxkc_uuid, (const void *)kcUUID->getBytesNoCopy(),
	    kcUUID->getLength());
	uuid_unparse_upper(auxkc_uuid, auxkc_uuid_string);
	auxkc_uuid_valid = TRUE;

	deferredAuxKCXML = parsedXML;

	return true;
}

OSSharedPtr<OSObject>
OSKext::consumeDeferredKextCollection(kc_kind_t type)
{
	if (type != KCKindAuxiliary || !deferredAuxKCXML) {
		return NULL;
	}

	return os::move(deferredAuxKCXML);
}

#if PRAGMA_MARK
#pragma mark Profile-Guided-Optimization Support
#endif

// #include <InstrProfiling.h>
extern "C" {
uint64_t __llvm_profile_get_size_for_buffer_internal(const char *DataBegin,
    const char *DataEnd,
    const char *CountersBegin,
    const char *CountersEnd,
    const char *NamesBegin,
    const char *NamesEnd);
int __llvm_profile_write_buffer_internal(char *Buffer,
    const char *DataBegin,
    const char *DataEnd,
    const char *CountersBegin,
    const char *CountersEnd,
    const char *NamesBegin,
    const char *NamesEnd);
}


static
void
OSKextPgoMetadataPut(char *pBuffer,
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
void
OSKextPgoMetadataPutMax(size_t *position, const char *key, size_t value_max)
{
	*position += strlen(key) + 1 + value_max + 1;
}


static
void
OSKextPgoMetadataPutAll(OSKext *kext,
    uuid_t instance_uuid,
    char *pBuffer,
    size_t *position,
    size_t bufferSize,
    uint32_t *num_pairs)
{
	_static_assert_1_arg(sizeof(clock_sec_t) % 2 == 0);
	//log_10 2^16 ≈ 4.82
	const size_t max_secs_string_size = 5 * sizeof(clock_sec_t) / 2;
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

		OSSharedPtr<OSData> uuid_data;
		uuid_t uuid;
		uuid_string_t uuid_string;
		uuid_data = kext->copyUUID();
		if (uuid_data) {
			memcpy(uuid, uuid_data->getBytesNoCopy(), sizeof(uuid));
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
size_t
OSKextPgoMetadataSize(OSKext *kext)
{
	size_t position = 0;
	uuid_t fakeuuid = {};
	OSKextPgoMetadataPutAll(kext, fakeuuid, NULL, &position, 0, NULL);
	return position;
}

int
OSKextGrabPgoDataLocked(OSKext *kext,
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
	size_t offset_to_pairs = 0;

	sect_prf_data = kext->lookupSection("__DATA", "__llvm_prf_data");
	sect_prf_name = kext->lookupSection("__DATA", "__llvm_prf_names");
	if (!sect_prf_name) {
		// kextcache sometimes truncates the section name to 15 chars
		// <rdar://problem/52080551> 16 character section name is truncated to 15 characters by kextcache
		sect_prf_name = kext->lookupSection("__DATA", "__llvm_prf_name");
	}
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
			offset_to_pairs = sizeof(struct pgo_metadata_footer) + metadata_size;
			if (offset_to_pairs > UINT32_MAX) {
				err = E2BIG;
				goto out;
			}

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
			footer.offset_to_pairs = htonl((uint32_t)offset_to_pairs );
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
	OSSharedPtr<OSKext> kext;


	IORecursiveLockLock(sKextLock);

	kext = OSKext::lookupKextWithUUID(uuid);
	if (!kext) {
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

		kext.reset();

		IORecursiveLockSleep(sKextLock, &s, THREAD_ABORTSAFE);

		prev = s.list_head.prev;
		next = s.list_head.next;

		prev->next = next;
		next->prev = prev;

		err = s.err;
	} else {
		err = OSKextGrabPgoDataLocked(kext.get(), metadata, kext->instance_uuid, pSize, pBuffer, bufferSize);
	}

out:

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

OSSharedPtr<OSDictionary>
OSKext::copyLoadedKextInfoByUUID(
	OSArray * kextIdentifiers,
	OSArray * infoKeys)
{
	OSSharedPtr<OSDictionary> result;
	OSSharedPtr<OSDictionary> kextInfo;
	uint32_t       max_count, i, j;
	uint32_t       idCount = 0;
	uint32_t       idIndex = 0;
	IORecursiveLockLock(sKextLock);
	OSArray *list[2] = {sLoadedKexts.get(), sLoadedDriverKitKexts.get()};
	uint32_t count[2] = {sLoadedKexts->getCount(), sLoadedDriverKitKexts->getCount()};

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

	max_count = count[0] + count[1];
	result = OSDictionary::withCapacity(max_count);
	if (!result) {
		goto finish;
	}

	for (j = 0; j < (sizeof(list) / sizeof(list[0])); j++) {
		for (i = 0; i < count[j]; i++) {
			OSKext       *thisKext     = NULL;        // do not release
			Boolean       includeThis  = true;
			uuid_t        thisKextUUID;
			uuid_t        thisKextTextUUID;
			OSSharedPtr<OSData> uuid_data;
			uuid_string_t uuid_key;

			thisKext = OSDynamicCast(OSKext, list[j]->getObject(i));
			if (!thisKext) {
				continue;
			}

			uuid_data = thisKext->copyUUID();
			if (!uuid_data) {
				continue;
			}

			memcpy(&thisKextUUID, uuid_data->getBytesNoCopy(), sizeof(thisKextUUID));

			uuid_unparse(thisKextUUID, uuid_key);

			uuid_data = thisKext->copyTextUUID();
			if (!uuid_data) {
				continue;
			}
			memcpy(&thisKextTextUUID, uuid_data->getBytesNoCopy(), sizeof(thisKextTextUUID));

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

					if ((0 == uuid_compare(uuid, thisKextUUID))
					    || (0 == uuid_compare(uuid, thisKextTextUUID))) {
						includeThis = true;
						/* Only need to find the first kext if multiple match,
						 * ie. asking for the kernel uuid does not need to find
						 * interface kexts or builtin static kexts.
						 */
						kextIdentifiers->removeObject(idIndex);
						uuid_unparse(uuid, uuid_key);
						break;
					}
				}
			}

			if (!includeThis) {
				continue;
			}

			kextInfo = thisKext->copyInfo(infoKeys);
			if (kextInfo) {
				result->setObject(uuid_key, kextInfo.get());
			}

			if (kextIdentifiers && !kextIdentifiers->getCount()) {
				goto finish;
			}
		}
	}

finish:
	IORecursiveLockUnlock(sKextLock);

	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSSharedPtr<OSDictionary>
OSKext::copyKextCollectionInfo(
	OSDictionary *requestDict,
	OSArray  *infoKeys)
{
	OSSharedPtr<OSDictionary> result;
	OSString *collectionType = NULL;
	OSObject *rawLoadedState = NULL;
	OSString *loadedState    = NULL;

	kc_kind_t kc_request_kind = KCKindUnknown;
	bool onlyLoaded = false;
	bool onlyUnloaded = false;

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

	if (infoKeys && !infoKeys->getCount()) {
		infoKeys = NULL;
	}

	collectionType = OSDynamicCast(OSString,
	    _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentCollectionTypeKey));
	if (!collectionType) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogIPCFlag,
		    "Invalid '%s' argument to kext collection info request.",
		    kKextRequestArgumentCollectionTypeKey);
		goto finish;
	}
	if (collectionType->isEqualTo(kKCTypePrimary)) {
		kc_request_kind = KCKindPrimary;
	} else if (collectionType->isEqualTo(kKCTypeSystem)) {
		kc_request_kind = KCKindPageable;
	} else if (collectionType->isEqualTo(kKCTypeAuxiliary)) {
		kc_request_kind = KCKindAuxiliary;
	} else if (collectionType->isEqualTo(kKCTypeCodeless)) {
		kc_request_kind = KCKindNone;
	} else if (!collectionType->isEqualTo(kKCTypeAny)) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogIPCFlag,
		    "Invalid '%s' argument value '%s' to kext collection info request.",
		    kKextRequestArgumentCollectionTypeKey,
		    collectionType->getCStringNoCopy());
		goto finish;
	}

	rawLoadedState = _OSKextGetRequestArgument(requestDict,
	    kKextRequestArgumentLoadedStateKey);
	if (rawLoadedState) {
		loadedState = OSDynamicCast(OSString, rawLoadedState);
		if (!loadedState) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogIPCFlag,
			    "Invalid '%s' argument to kext collection info request.",
			    kKextRequestArgumentLoadedStateKey);
			goto finish;
		}
	}
	if (loadedState) {
		if (loadedState->isEqualTo("Loaded")) {
			onlyLoaded = true;
		} else if (loadedState->isEqualTo("Unloaded")) {
			onlyUnloaded = true;
		} else if (!loadedState->isEqualTo("Any")) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel | kOSKextLogLoadFlag,
			    "Invalid '%s' argument value '%s' for '%s' collection info",
			    kKextRequestArgumentLoadedStateKey,
			    loadedState->getCStringNoCopy(),
			    collectionType->getCStringNoCopy());
			goto finish;
		}
	}

	result = OSDictionary::withCapacity(sKextsByID->getCount());
	if (!result) {
		goto finish;
	}

	IORecursiveLockLock(sKextLock);
	{         // start block scope
		sKextsByID->iterateObjects(^bool (const OSSymbol *thisKextID, OSObject *obj)
		{
			OSKext       *thisKext    = NULL;  // do not release
			OSSharedPtr<OSDictionary> kextInfo;

			(void)thisKextID;

			thisKext = OSDynamicCast(OSKext, obj);
			if (!thisKext) {
			        return false;;
			}

			/*
			 * skip the kext if it came from the wrong collection type
			 * (and the caller requested a specific type)
			 */
			if ((kc_request_kind != KCKindUnknown) && (thisKext->kc_type != kc_request_kind)) {
			        return false;
			}

			/*
			 * respect the caller's desire to find only loaded or
			 * unloaded kexts
			 */
			if (onlyLoaded && (-1U == sLoadedKexts->getNextIndexOfObject(thisKext, 0))) {
			        return false;
			}
			if (onlyUnloaded && (-1U != sLoadedKexts->getNextIndexOfObject(thisKext, 0))) {
			        return false;
			}

			kextInfo = thisKext->copyInfo(infoKeys);
			if (kextInfo) {
			        result->setObject(thisKext->getIdentifier(), kextInfo.get());
			}
			return false;
		});
	} // end block scope
	IORecursiveLockUnlock(sKextLock);

finish:
	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
OSSharedPtr<OSDictionary>
OSKext::copyLoadedKextInfo(
	OSArray * kextIdentifiers,
	OSArray * infoKeys)
{
	OSSharedPtr<OSDictionary> result;
	uint32_t       idCount = 0;
	bool           onlyLoaded;

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

	onlyLoaded =  (!infoKeys || !_OSArrayContainsCString(infoKeys, kOSBundleAllPrelinkedKey));

	result = OSDictionary::withCapacity(128);
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
	{         // start block scope
		sKextsByID->iterateObjects(^bool (const OSSymbol * thisKextID, OSObject * obj)
		{
			OSKext       * thisKext     = NULL;        // do not release
			Boolean        includeThis  = true;
			OSSharedPtr<OSDictionary> kextInfo;

			thisKext = OSDynamicCast(OSKext, obj);
			if (!thisKext) {
			        return false;;
			}

			/* Skip current kext if not yet started and caller didn't request all.
			 */
			if (onlyLoaded && (-1U == sLoadedKexts->getNextIndexOfObject(thisKext, 0))) {
			        return false;;
			}

			/* Skip current kext if we have a list of bundle IDs and
			 * it isn't in the list.
			 */
			if (kextIdentifiers) {
			        includeThis = false;

			        for (uint32_t idIndex = 0; idIndex < idCount; idIndex++) {
			                const OSString * thisRequestID = OSDynamicCast(OSString,
			                kextIdentifiers->getObject(idIndex));
			                if (thisKextID->isEqualTo(thisRequestID)) {
			                        includeThis = true;
			                        break;
					}
				}
			}

			if (!includeThis) {
			        return false;
			}

			kextInfo = thisKext->copyInfo(infoKeys);
			if (kextInfo) {
			        result->setObject(thisKext->getIdentifier(), kextInfo.get());
			}
			return false;
		});
	}         // end block scope

finish:
	IORecursiveLockUnlock(sKextLock);

	return result;
}

/*********************************************************************
* Any info that needs to do allocations must goto finish on alloc
* failure. Info that is just a lookup should just not set the object
* if the info does not exist.
*********************************************************************/
#define _OSKextLoadInfoDictCapacity   (12)

OSSharedPtr<OSDictionary>
OSKext::copyInfo(OSArray * infoKeys)
{
	OSSharedPtr<OSDictionary>  result;
	bool                       success                     = false;
	OSSharedPtr<OSData>        headerData;
	OSSharedPtr<OSData>        logData;
	OSSharedPtr<OSNumber>      cpuTypeNumber;
	OSSharedPtr<OSNumber>      cpuSubtypeNumber;
	OSString                 * versionString               = NULL;        // do not release
	OSString                 * bundleType                  = NULL;        // do not release
	uint32_t                   executablePathCStringSize   = 0;
	char                     * executablePathCString       = NULL;        // must kfree
	OSSharedPtr<OSString>      executablePathString;
	OSSharedPtr<OSData>        uuid;
	OSSharedPtr<OSArray>       dependencyLoadTags;
	OSSharedPtr<OSCollectionIterator>      metaClassIterator;
	OSSharedPtr<OSArray>       metaClassInfo;
	OSSharedPtr<OSDictionary>  metaClassDict;
	OSMetaClass              * thisMetaClass               = NULL;        // do not release
	OSSharedPtr<OSString>      metaClassName;
	OSSharedPtr<OSString>      superclassName;
	kc_format_t                kcformat;
	uint32_t                   count, i;

	result = OSDictionary::withCapacity(_OSKextLoadInfoDictCapacity);
	if (!result) {
		goto finish;
	}


	/* Empty keys means no keys, but NULL is quicker to check.
	 */
	if (infoKeys && !infoKeys->getCount()) {
		infoKeys = NULL;
	}

	if (!PE_get_primary_kc_format(&kcformat)) {
		goto finish;
	}

	/* Headers, CPU type, and CPU subtype.
	 */
	if (!infoKeys ||
	    _OSArrayContainsCString(infoKeys, kOSBundleMachOHeadersKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleLogStringsKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleCPUTypeKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleCPUSubtypeKey)) {
		if (linkedExecutable && !isInterface()) {
			kernel_mach_header_t *kext_mach_hdr = (kernel_mach_header_t *)
			    linkedExecutable->getBytesNoCopy();

#if !SECURE_KERNEL || XNU_TARGET_OS_OSX
			// do not return macho header info on shipping embedded - 19095897
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

#if __arm__ || __arm64__
						// iBoot disregards zero-size segments, just set their addresses to gVirtBase
						// and unslide them to avoid vm assertion failures / kernel logging breakage.
						if (segp->vmsize == 0 && segp->vmaddr < gVirtBase) {
							segp->vmaddr = gVirtBase;
							for (secp = firstsect(segp); secp != NULL; secp = nextsect(segp, secp)) {
								secp->size = 0; // paranoia :)
								secp->addr = gVirtBase;
							}
						}
#endif

#if 0
						OSKextLog(/* kext */ NULL,
						    kOSKextLogErrorLevel |
						    kOSKextLogGeneralFlag,
						    "%s: LC_SEGMENT_KERNEL segname '%s' vmaddr 0x%llX 0x%lX vmsize %llu nsects %u",
						    __FUNCTION__, segp->segname, segp->vmaddr,
						    VM_KERNEL_UNSLIDE(segp->vmaddr),
						    segp->vmsize, segp->nsects);
						if ((VM_KERNEL_IS_SLID(segp->vmaddr) == false) &&
						    (VM_KERNEL_IS_KEXT(segp->vmaddr) == false) &&
						    (VM_KERNEL_IS_PRELINKTEXT(segp->vmaddr) == false) &&
						    (VM_KERNEL_IS_PRELINKINFO(segp->vmaddr) == false) &&
						    (VM_KERNEL_IS_KEXT_LINKEDIT(segp->vmaddr) == false)) {
							OSKextLog(/* kext */ NULL,
							    kOSKextLogErrorLevel |
							    kOSKextLogGeneralFlag,
							    "%s: not in kext range - vmaddr 0x%llX vm_kext_base 0x%lX vm_kext_top 0x%lX",
							    __FUNCTION__, segp->vmaddr, vm_kext_base, vm_kext_top);
						}
#endif
						segp->vmaddr = ml_static_unslide(segp->vmaddr);

						for (secp = firstsect(segp); secp != NULL; secp = nextsect(segp, secp)) {
							secp->addr = ml_static_unslide(secp->addr);
						}
					}
					lcp = (struct load_command *)((caddr_t)lcp + lcp->cmdsize);
				}
				result->setObject(kOSBundleMachOHeadersKey, headerData.get());
			}
#endif // !SECURE_KERNEL || XNU_TARGET_OS_OSX

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
				os_log_offset     = (uintptr_t)os_log_data - (uintptr_t)kext_mach_hdr;
				cstring_data      = getsectdatafromheader(kext_mach_hdr, "__TEXT", "__cstring", &cstring_size);
				cstring_offset    = (uintptr_t)cstring_data - (uintptr_t)kext_mach_hdr;

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
				result->setObject(kOSBundleLogStringsKey, logData.get());
			}

			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleCPUTypeKey)) {
				cpuTypeNumber = OSNumber::withNumber(
					(uint64_t) kext_mach_hdr->cputype,
					8 * sizeof(kext_mach_hdr->cputype));
				if (!cpuTypeNumber) {
					goto finish;
				}
				result->setObject(kOSBundleCPUTypeKey, cpuTypeNumber.get());
			}

			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleCPUSubtypeKey)) {
				cpuSubtypeNumber = OSNumber::withNumber(
					(uint64_t) kext_mach_hdr->cpusubtype,
					8 * sizeof(kext_mach_hdr->cpusubtype));
				if (!cpuSubtypeNumber) {
					goto finish;
				}
				result->setObject(kOSBundleCPUSubtypeKey, cpuSubtypeNumber.get());
			}
		} else {
			if (isDriverKit() && _OSArrayContainsCString(infoKeys, kOSBundleLogStringsKey)) {
				osLogDataHeaderRef *header;
				char headerBytes[offsetof(osLogDataHeaderRef, sections) + NUM_OS_LOG_SECTIONS * sizeof(header->sections[0])];
				bool res;

				header             = (osLogDataHeaderRef *) headerBytes;
				header->version    = OS_LOG_HDR_VERSION;
				header->sect_count = NUM_OS_LOG_SECTIONS;
				header->sections[OS_LOG_SECT_IDX].sect_offset  = 0;
				header->sections[OS_LOG_SECT_IDX].sect_size    = (uint32_t) 0;
				header->sections[CSTRING_SECT_IDX].sect_offset = 0;
				header->sections[CSTRING_SECT_IDX].sect_size   = (uint32_t) 0;

				logData = OSData::withBytes(header, (u_int) (sizeof(osLogDataHeaderRef)));
				if (!logData) {
					goto finish;
				}
				res = logData->appendBytes(&(header->sections[0]), (u_int)(header->sect_count * sizeof(header->sections[0])));
				if (!res) {
					goto finish;
				}
				result->setObject(kOSBundleLogStringsKey, logData.get());
			}
		}
	}

	/* CFBundleIdentifier. We set this regardless because it's just stupid not to.
	 */
	result->setObject(kCFBundleIdentifierKey, bundleID.get());

	/* CFBundlePackageType
	 */
	bundleType = infoDict ? OSDynamicCast(OSString, infoDict->getObject(kCFBundlePackageTypeKey)): NULL;
	if (bundleType) {
		result->setObject(kCFBundlePackageTypeKey, bundleType);
	}

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
			result->setObject(kOSBundlePathKey, path.get());
		}
	}


	/* OSBundleExecutablePath.
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleExecutablePathKey)) {
		if (path && executableRelPath) {
			uint32_t pathLength = path->getLength();         // gets incremented below

			// +1 for slash, +1 for \0
			executablePathCStringSize = pathLength + executableRelPath->getLength() + 2;

			executablePathCString = (char *)kheap_alloc_tag(KHEAP_TEMP,
			    executablePathCStringSize, Z_WAITOK, VM_KERN_MEMORY_OSKEXT);         // +1 for \0
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

			result->setObject(kOSBundleExecutablePathKey, executablePathString.get());
		} else if (flags.builtin) {
			result->setObject(kOSBundleExecutablePathKey, bundleID.get());
		} else if (isDriverKit()) {
			if (path) {
				// +1 for slash, +1 for \0
				uint32_t pathLength = path->getLength();
				executablePathCStringSize = pathLength + 2;

				executablePathCString = (char *)kheap_alloc_tag(KHEAP_TEMP,
				    executablePathCStringSize, Z_WAITOK, VM_KERN_MEMORY_OSKEXT);
				if (!executablePathCString) {
					goto finish;
				}
				strlcpy(executablePathCString, path->getCStringNoCopy(), executablePathCStringSize);
				executablePathCString[pathLength++] = '/';
				executablePathCString[pathLength++] = '\0';

				executablePathString = OSString::withCString(executablePathCString);

				if (!executablePathString) {
					goto finish;
				}

				result->setObject(kOSBundleExecutablePathKey, executablePathString.get());
			}
		}
	}

	/* UUID, if the kext has one.
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleUUIDKey)) {
		uuid = copyUUID();
		if (uuid) {
			result->setObject(kOSBundleUUIDKey, uuid.get());
		}
	}
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleTextUUIDKey)) {
		uuid = copyTextUUID();
		if (uuid) {
			result->setObject(kOSBundleTextUUIDKey, uuid.get());
		}
	}

	/*
	 * Info.plist digest
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSKextInfoPlistDigestKey)) {
		OSData *digest;
		digest = infoDict ? OSDynamicCast(OSData, infoDict->getObject(kOSKextInfoPlistDigestKey)) : NULL;
		if (digest) {
			result->setObject(kOSKextInfoPlistDigestKey, digest);
		}
	}

	/*
	 * Collection type
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSKextBundleCollectionTypeKey)) {
		result->setObject(kOSKextBundleCollectionTypeKey, OSString::withCString(getKCTypeString()));
	}

	/*
	 * Collection availability
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSKextAuxKCAvailabilityKey)) {
		result->setObject(kOSKextAuxKCAvailabilityKey,
		    isLoadable() ? kOSBooleanTrue : kOSBooleanFalse);
	}

	/*
	 * Allows user load
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleAllowUserLoadKey)) {
		OSBoolean *allowUserLoad = OSDynamicCast(OSBoolean, getPropertyForHostArch(kOSBundleAllowUserLoadKey));
		if (allowUserLoad) {
			result->setObject(kOSBundleAllowUserLoadKey, allowUserLoad);
		}
	}

	/*
	 * Bundle Dependencies (OSBundleLibraries)
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleLibrariesKey)) {
		OSDictionary *libraries = OSDynamicCast(OSDictionary, getPropertyForHostArch(kOSBundleLibrariesKey));
		if (libraries) {
			result->setObject(kOSBundleLibrariesKey, libraries);
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
		OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber((unsigned long long)loadTag,
		    /* numBits */ 8 * sizeof(loadTag));
		if (!scratchNumber) {
			goto finish;
		}
		result->setObject(kOSBundleLoadTagKey, scratchNumber.get());
	}

	/* LoadAddress, LoadSize.
	 */
	if (!infoKeys ||
	    _OSArrayContainsCString(infoKeys, kOSBundleLoadAddressKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleLoadSizeKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleExecLoadAddressKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleExecLoadSizeKey) ||
	    _OSArrayContainsCString(infoKeys, kOSBundleWiredSizeKey)) {
		bool is_dext = isDriverKit();
		if (isInterface() || flags.builtin || linkedExecutable || is_dext) {
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

			if (flags.builtin || linkedExecutable) {
				kernel_mach_header_t     *mh  = NULL;
				kernel_segment_command_t *seg = NULL;

				if (flags.builtin) {
					loadAddress = kmod_info->address;
					loadSize    = (uint32_t)kmod_info->size;
				} else {
					loadAddress = (uint64_t)linkedExecutable->getBytesNoCopy();
					loadSize = linkedExecutable->getLength();
				}
				mh = (kernel_mach_header_t *)loadAddress;
				loadAddress = ml_static_unslide(loadAddress);

				/* Walk through the kext, looking for the first executable
				 * segment in case we were asked for its size/address.
				 */
				for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
					if (seg->initprot & VM_PROT_EXECUTE) {
						execLoadAddress = ml_static_unslide(seg->vmaddr);
						execLoadSize = (uint32_t)seg->vmsize;
						break;
					}
				}

				/* If we have a kmod_info struct, calculated the wired size
				 * from that. Otherwise it's the full load size.
				 */
				if (kmod_info) {
					wiredSize = loadSize - (uint32_t)kmod_info->hdr_size;
				} else {
					wiredSize = loadSize;
				}
			} else if (is_dext) {
				/*
				 * DriverKit userspace executables do not have a kernel linkedExecutable,
				 * so we "fake" their address range with the LoadTag.
				 */
				if (loadTag) {
					loadAddress = execLoadAddress = loadTag;
					loadSize = execLoadSize = 1;
				}
			}

			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleLoadAddressKey)) {
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
					(unsigned long long)(loadAddress),
					/* numBits */ 8 * sizeof(loadAddress));
				if (!scratchNumber) {
					goto finish;
				}
				result->setObject(kOSBundleLoadAddressKey, scratchNumber.get());
			}
			if (kcformat == KCFormatStatic || kcformat == KCFormatKCGEN) {
				if ((!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleCacheLoadAddressKey))
				    && loadAddress && loadSize) {
					void *baseAddress = PE_get_kc_baseaddress(KCKindPrimary);
					if (!baseAddress) {
						goto finish;
					}

					OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
						(unsigned long long)ml_static_unslide((vm_offset_t)baseAddress),
						/* numBits */ 8 * sizeof(loadAddress));
					if (!scratchNumber) {
						goto finish;
					}
					result->setObject(kOSBundleCacheLoadAddressKey, scratchNumber.get());
				}
				if ((!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleKextsInKernelTextKey))
				    && (this == sKernelKext) && gBuiltinKmodsCount) {
					result->setObject(kOSBundleKextsInKernelTextKey, kOSBooleanTrue);
				}
			}

			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleExecLoadAddressKey)) {
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
					(unsigned long long)(execLoadAddress),
					/* numBits */ 8 * sizeof(execLoadAddress));
				if (!scratchNumber) {
					goto finish;
				}
				result->setObject(kOSBundleExecLoadAddressKey, scratchNumber.get());
			}
			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleLoadSizeKey)) {
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
					(unsigned long long)(loadSize),
					/* numBits */ 8 * sizeof(loadSize));
				if (!scratchNumber) {
					goto finish;
				}
				result->setObject(kOSBundleLoadSizeKey, scratchNumber.get());
			}
			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleExecLoadSizeKey)) {
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
					(unsigned long long)(execLoadSize),
					/* numBits */ 8 * sizeof(execLoadSize));
				if (!scratchNumber) {
					goto finish;
				}
				result->setObject(kOSBundleExecLoadSizeKey, scratchNumber.get());
			}
			if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleWiredSizeKey)) {
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
					(unsigned long long)(wiredSize),
					/* numBits */ 8 * sizeof(wiredSize));
				if (!scratchNumber) {
					goto finish;
				}
				result->setObject(kOSBundleWiredSizeKey, scratchNumber.get());
			}
		}
	}

	/* OSBundleDependencies. In descending order for
	 * easy compatibility with kextstat(8).
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleDependenciesKey)) {
		if ((count = getNumDependencies())) {
			dependencyLoadTags = OSArray::withCapacity(count);
			result->setObject(kOSBundleDependenciesKey, dependencyLoadTags.get());

			i = count - 1;
			do {
				OSKext * dependency = OSDynamicCast(OSKext,
				    dependencies->getObject(i));

				if (!dependency) {
					continue;
				}
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
					(unsigned long long)dependency->getLoadTag(),
					/* numBits*/ 8 * sizeof(loadTag));
				if (!scratchNumber) {
					goto finish;
				}
				dependencyLoadTags->setObject(scratchNumber.get());
			} while (i--);
		}
	}

	/* OSBundleMetaClasses.
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleClassesKey)) {
		if (metaClasses && metaClasses->getCount()) {
			metaClassIterator = OSCollectionIterator::withCollection(metaClasses.get());
			metaClassInfo = OSArray::withCapacity(metaClasses->getCount());
			if (!metaClassIterator || !metaClassInfo) {
				goto finish;
			}
			result->setObject(kOSBundleClassesKey, metaClassInfo.get());

			while ((thisMetaClass = OSDynamicCast(OSMetaClass,
			    metaClassIterator->getNextObject()))) {
				metaClassDict = OSDictionary::withCapacity(3);
				if (!metaClassDict) {
					goto finish;
				}

				metaClassName = OSString::withCString(thisMetaClass->getClassName());
				if (thisMetaClass->getSuperClass()) {
					superclassName = OSString::withCString(
						thisMetaClass->getSuperClass()->getClassName());
				}
				OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(thisMetaClass->getInstanceCount(),
				    8 * sizeof(unsigned int));

				/* Bail if any of the essentials is missing. The root class lacks a superclass,
				 * of course.
				 */
				if (!metaClassDict || !metaClassName || !scratchNumber) {
					goto finish;
				}

				metaClassInfo->setObject(metaClassDict.get());
				metaClassDict->setObject(kOSMetaClassNameKey, metaClassName.get());
				if (superclassName) {
					metaClassDict->setObject(kOSMetaClassSuperclassNameKey, superclassName.get());
				}
				metaClassDict->setObject(kOSMetaClassTrackingCountKey, scratchNumber.get());
			}
		}
	}

	/* OSBundleRetainCount.
	 */
	if (!infoKeys || _OSArrayContainsCString(infoKeys, kOSBundleRetainCountKey)) {
		{
			int kextRetainCount = getRetainCount() - 1;
			if (isLoaded()) {
				kextRetainCount--;
			}
			OSSharedPtr<OSNumber> scratchNumber = OSNumber::withNumber(
				(int)kextRetainCount,
				/* numBits*/ 8 * sizeof(int));
			if (scratchNumber) {
				result->setObject(kOSBundleRetainCountKey, scratchNumber.get());
			}
		}
	}

	success = true;

finish:
	if (executablePathCString) {
		kheap_free(KHEAP_TEMP, executablePathCString, executablePathCStringSize);
	}
	if (!success) {
		result.reset();
	}
	return result;
}

/*********************************************************************
*********************************************************************/
/* static */
bool
OSKext::copyUserExecutablePath(const OSSymbol * bundleID, char * pathResult, size_t pathSize)
{
	bool ok;
	OSSharedPtr<OSKext> kext;

	IORecursiveLockLock(sKextLock);
	kext.reset(OSDynamicCast(OSKext, sKextsByID->getObject(bundleID)), OSRetain);
	IORecursiveLockUnlock(sKextLock);

	if (!kext || !kext->path || !kext->userExecutableRelPath) {
		return false;
	}
	snprintf(pathResult, pathSize, "%s/Contents/MacOS/%s",
	    kext->path->getCStringNoCopy(),
	    kext->userExecutableRelPath->getCStringNoCopy());
	ok = true;

	return ok;
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
	OSReturn                        result = kOSReturnError;
	OSSharedPtr<OSKext>             callbackKext;        // looked up

	OSKextRequestTag   requestTag      = -1;
	OSSharedPtr<OSNumber>           requestTagNum;
	OSSharedPtr<OSDictionary>       requestDict;
	OSSharedPtr<OSString>           kextIdentifier;
	OSSharedPtr<OSString>           resourceName;

	OSSharedPtr<OSDictionary>       callbackRecord;
	OSSharedPtr<OSData>             callbackWrapper;

	OSSharedPtr<OSData>             contextWrapper;

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
	    requestDict);
	if (result != kOSReturnSuccess) {
		goto finish;
	}

	kextIdentifier = OSString::withCString(kextIdentifierCString);
	resourceName   = OSString::withCString(resourceNameCString);
	requestTagNum  = OSNumber::withNumber((long long unsigned int)requestTag,
	    8 * sizeof(requestTag));
	if (!kextIdentifier ||
	    !resourceName ||
	    !requestTagNum ||
	    !_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentBundleIdentifierKey, kextIdentifier.get()) ||
	    !_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentNameKey, resourceName.get()) ||
	    !_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentRequestTagKey, requestTagNum.get())) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}

	callbackRecord = OSDynamicPtrCast<OSDictionary>(requestDict->copyCollection());
	if (!callbackRecord) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}
	// we validate callback address at call time
	callbackWrapper = OSData::withBytes((void *)&callback, sizeof(void *));
	if (context) {
		contextWrapper = OSData::withBytes((void *)&context, sizeof(void *));
	}
	if (!callbackWrapper || !_OSKextSetRequestArgument(callbackRecord.get(),
	    kKextRequestArgumentCallbackKey, callbackWrapper.get())) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}

	if (context) {
		if (!contextWrapper || !_OSKextSetRequestArgument(callbackRecord.get(),
		    kKextRequestArgumentContextKey, contextWrapper.get())) {
			result = kOSKextReturnNoMemory;
			goto finish;
		}
	}

	/* Only post the requests after all the other potential failure points
	 * have been passed.
	 */
	if (!sKernelRequests->setObject(requestDict.get()) ||
	    !sRequestCallbackRecords->setObject(callbackRecord.get())) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}

	OSKext::pingIOKitDaemon();

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

		index = sKernelRequests->getNextIndexOfObject(requestDict.get(), 0);
		if (index != (unsigned int)-1) {
			sKernelRequests->removeObject(index);
		}
		index = sRequestCallbackRecords->getNextIndexOfObject(callbackRecord.get(), 0);
		if (index != (unsigned int)-1) {
			sRequestCallbackRecords->removeObject(index);
		}
	}

	OSKext::considerUnloads(/* rescheduleOnly? */ true);

	IORecursiveLockUnlock(sKextLock);

	return result;
}

OSReturn
OSKext::requestDaemonLaunch(
	OSString *kextIdentifier,
	OSString *serverName,
	OSNumber *serverTag,
	OSSharedPtr<IOUserServerCheckInToken> &checkInToken)
{
	OSReturn result;
	IOUserServerCheckInToken * checkInTokenRaw = NULL;

	result = requestDaemonLaunch(kextIdentifier, serverName,
	    serverTag, &checkInTokenRaw);

	if (kOSReturnSuccess == result) {
		checkInToken.reset(checkInTokenRaw, OSNoRetain);
	}

	return result;
}

OSReturn
OSKext::requestDaemonLaunch(
	OSString *kextIdentifier,
	OSString *serverName,
	OSNumber *serverTag,
	IOUserServerCheckInToken ** checkInToken)
{
	OSReturn       result        = kOSReturnError;
	OSSharedPtr<OSDictionary> requestDict;
	OSSharedPtr<IOUserServerCheckInToken> token;

	if (!kextIdentifier || !serverName || !serverTag) {
		result = kOSKextReturnInvalidArgument;
		goto finish;
	}

	IORecursiveLockLock(sKextLock);

	OSKextLog(/* kext */ NULL,
	    kOSKextLogDebugLevel |
	    kOSKextLogGeneralFlag,
	    "Requesting daemon launch for %s with serverName %s and tag %llu",
	    kextIdentifier->getCStringNoCopy(),
	    serverName->getCStringNoCopy(),
	    serverTag->unsigned64BitValue()
	    );

	result = _OSKextCreateRequest(kKextRequestPredicateRequestDaemonLaunch, requestDict);
	if (result != kOSReturnSuccess) {
		goto finish;
	}

	token.reset(IOUserServerCheckInToken::create(), OSNoRetain);
	if (!token) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}

	if (!_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentBundleIdentifierKey, kextIdentifier) ||
	    !_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentDriverExtensionServerName, serverName) ||
	    !_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentDriverExtensionServerTag, serverTag) ||
	    !_OSKextSetRequestArgument(requestDict.get(),
	    kKextRequestArgumentCheckInToken, token.get())) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}

	/* Only post the requests after all the other potential failure points
	 * have been passed.
	 */
	if (!sKernelRequests->setObject(requestDict.get())) {
		result = kOSKextReturnNoMemory;
		goto finish;
	}
	*checkInToken = token.detach();
	OSKext::pingIOKitDaemon();

	result = kOSReturnSuccess;
finish:
	IORecursiveLockUnlock(sKextLock);
	return result;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::dequeueCallbackForRequestTag(
	OSKextRequestTag    requestTag,
	OSSharedPtr<OSDictionary>     &callbackRecordOut)
{
	OSDictionary * callbackRecordOutRaw = NULL;
	OSReturn result;

	result = dequeueCallbackForRequestTag(requestTag,
	    &callbackRecordOutRaw);

	if (kOSReturnSuccess == result) {
		callbackRecordOut.reset(callbackRecordOutRaw, OSNoRetain);
	}

	return result;
}
OSReturn
OSKext::dequeueCallbackForRequestTag(
	OSKextRequestTag    requestTag,
	OSDictionary     ** callbackRecordOut)
{
	OSReturn   result = kOSReturnError;
	OSSharedPtr<OSNumber> requestTagNum;

	requestTagNum  = OSNumber::withNumber((long long unsigned int)requestTag,
	    8 * sizeof(requestTag));
	if (!requestTagNum) {
		goto finish;
	}

	result = OSKext::dequeueCallbackForRequestTag(requestTagNum.get(),
	    callbackRecordOut);

finish:
	return result;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::dequeueCallbackForRequestTag(
	OSNumber     *    requestTagNum,
	OSSharedPtr<OSDictionary>     &callbackRecordOut)
{
	OSDictionary * callbackRecordOutRaw = NULL;
	OSReturn result;

	result = dequeueCallbackForRequestTag(requestTagNum,
	    &callbackRecordOutRaw);

	if (kOSReturnSuccess == result) {
		callbackRecordOut.reset(callbackRecordOutRaw, OSNoRetain);
	}

	return result;
}
OSReturn
OSKext::dequeueCallbackForRequestTag(
	OSNumber     *    requestTagNum,
	OSDictionary ** callbackRecordOut)
{
	OSReturn        result          = kOSKextReturnInvalidArgument;
	OSDictionary  * callbackRecord  = NULL;        // retain if matched!
	OSNumber      * callbackTagNum  = NULL;        // do not release
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
OSKext::pendingIOKitDaemonRequests(void)
{
	return sRequestCallbackRecords && sRequestCallbackRecords->getCount();
}

/*********************************************************************
* Acquires and releases sKextLock
*
* This function is designed to be called exactly once on boot by
* the IOKit management daemon, kernelmanagerd. It gathers all codeless
* kext and dext personalities, and then attempts to map a System
* (pageable) KC and an Auxiliary (aux) KC.
*
* Even if the pageable or aux KC fail to load - this function will
* not allow a second call. This avoids security issues where
* kernelmanagerd has been compromised or the pageable kc has been
* tampered with and the attacker attempts to re-load a malicious
* variant.
*
* Return: if a KC fails to load the return value will contain:
*         kOSKextReturnKCLoadFailure. If the pageable KC fails,
*         the return value will contain kOSKextReturnKCLoadFailureSystemKC.
*         Similarly, if the aux kc load fails, the return value will
*         contain kOSKextReturnKCLoadFailureAuxKC. The two values
*         compose with each other and with kOSKextReturnKCLoadFailure.
*********************************************************************/
/* static */
OSReturn
OSKext::loadFileSetKexts(OSDictionary * requestDict __unused)
{
	static bool daemon_ready = false;

	OSReturn ret = kOSKextReturnInvalidArgument;
	OSReturn kcerr = 0;
	bool start_matching = false;

	bool allow_fileset_load = !daemon_ready;
#if !(defined(__x86_64__) || defined(__i386__))
	/* never allow KCs full of kexts on non-x86 machines */
	allow_fileset_load = false;
#endif

	/*
	 * Get the args from the request. Right now we need the file
	 * name for the pageable and the aux kext collection file sets.
	 */
	OSDictionary * requestArgs                = NULL;        // do not release
	OSString     * pageable_filepath          = NULL;        // do not release
	OSString     * aux_filepath               = NULL;        // do not release
	OSArray      * codeless_kexts             = NULL;        // do not release

	kernel_mach_header_t *akc_mh              = NULL;

	requestArgs = OSDynamicCast(OSDictionary,
	    requestDict->getObject(kKextRequestArgumentsKey));

	if (requestArgs == NULL) {
		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "KextLog: No arguments in plist for loading fileset kext\n");
		printf("KextLog: No arguments in plist for loading fileset kext\n");
		return ret;
	}

	ret = kOSKextReturnDisabled;

	IORecursiveLockLock(sKextLock);

	if (!sLoadEnabled) {
		OSKextLog(NULL, kOSKextLogErrorLevel | kOSKextLogIPCFlag,
		    "KextLog: Kext loading is disabled (attempt to load KCs).");
		IORecursiveLockUnlock(sKextLock);
		return ret;
	}

	pageable_filepath = OSDynamicCast(OSString,
	    requestArgs->getObject(kKextRequestArgumentPageableKCFilename));

	if (allow_fileset_load && pageable_filepath != NULL) {
		printf("KextLog: Loading Pageable KC from file %s\n", pageable_filepath->getCStringNoCopy());

		ret = OSKext::loadKCFileSet(pageable_filepath->getCStringNoCopy(), KCKindPageable);
		if (ret) {
			OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
			    "KextLog: loadKCFileSet for Pageable KC returned %d\n", ret);

			printf("KextLog: loadKCFileSet for Pageable KC returned %d\n", ret);
			ret = kOSKextReturnKCLoadFailure;
			kcerr |= kOSKextReturnKCLoadFailureSystemKC;
			goto try_auxkc;
		}
		/*
		 * Even if the AuxKC fails to load, we still want to send
		 * the System KC personalities to the catalog for matching
		 */
		start_matching = true;
	} else if (pageable_filepath != NULL) {
		OSKextLog(/* kext */ NULL, kOSKextLogBasicLevel | kOSKextLogIPCFlag,
		    "KextLog: ignoring Pageable KC load from %s\n", pageable_filepath->getCStringNoCopy());
		ret = kOSKextReturnUnsupported;
	}

try_auxkc:
	akc_mh = (kernel_mach_header_t*)PE_get_kc_header(KCKindAuxiliary);
	if (akc_mh) {
		/*
		 * If we try to load a deferred AuxKC, then don't ever attempt
		 * a filesystem map of a file
		 */
		allow_fileset_load = false;

		/*
		 * This function is only called once per boot, so we haven't
		 * yet loaded an AuxKC. If we have registered the AuxKC mach
		 * header, that means that the kext collection has been placed
		 * in memory for us by the booter, and is waiting for us to
		 * process it.  Grab the deferred XML plist of info
		 * dictionaries and add all the kexts.
		 */
		OSSharedPtr<OSObject>  parsedXML;
		OSSharedPtr<OSData>    loaded_kcUUID;
		OSDictionary          *infoDict;
		parsedXML = consumeDeferredKextCollection(KCKindAuxiliary);
		infoDict = OSDynamicCast(OSDictionary, parsedXML.get());
		if (infoDict) {
			bool added;
			printf("KextLog: Adding kexts from in-memory AuxKC\n");
			added = OSKext::addKextsFromKextCollection(akc_mh, infoDict,
			    kPrelinkTextSegment, loaded_kcUUID, KCKindAuxiliary);
			if (!loaded_kcUUID) {
				OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
				    "KextLog: WARNING: did not find UUID in deferred Aux KC!");
			} else if (!added) {
				OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
				    "KextLog: WARNING: Failed to load AuxKC from memory.");
			}
			/* only return success if the pageable load (above) was successful */
			if (ret != kOSKextReturnKCLoadFailure) {
				ret = kOSReturnSuccess;
			}
			/* the registration of the AuxKC parsed out the KC's UUID already */
		} else {
			if (daemon_ready) {
				/*
				 * Complain, but don't return an error if this isn't the first time the
				 * IOKit daemon is checking in. If the daemon ever restarts, we will
				 * hit this case because we've already consumed the deferred personalities.
				 * We return success here so that a call to this function from a restarted
				 * daemon with no codeless kexts will succeed.
				 */
				OSKextLog(/* kext */ NULL, kOSKextLogBasicLevel | kOSKextLogIPCFlag,
				    "KextLog: can't re-parse deferred AuxKC personalities on IOKit daemon restart");
				if (ret != kOSKextReturnKCLoadFailure) {
					ret = kOSReturnSuccess;
				}
			} else {
				/* this is a real error case */
				OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogIPCFlag,
				    "KextLog: ERROR loading deferred AuxKC: PRELINK_INFO wasn't an OSDictionary");
				printf("KextLog: ERROR loading deferred AuxKC: PRELINK_INFO wasn't an OSDictionary\n");
				ret = kOSKextReturnKCLoadFailure;
				kcerr |= kOSKextReturnKCLoadFailureAuxKC;
			}
		}
	}

	aux_filepath = OSDynamicCast(OSString,
	    requestArgs->getObject(kKextRequestArgumentAuxKCFilename));
	if (allow_fileset_load && aux_filepath != NULL) {
		printf("KextLog: Loading Aux KC from file %s\n", aux_filepath->getCStringNoCopy());

		ret = OSKext::loadKCFileSet(aux_filepath->getCStringNoCopy(), KCKindAuxiliary);
		if (ret) {
			OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
			    "KextLog: loadKCFileSet for Aux KC returned %d\n", ret);

			printf("KextLog: loadKCFileSet for Aux KC returned %d\n", ret);
			ret = kOSKextReturnKCLoadFailure;
			kcerr |= kOSKextReturnKCLoadFailureAuxKC;
			goto try_codeless;
		}
		start_matching = true;
	} else if (aux_filepath != NULL) {
		OSKextLog(/* kext */ NULL, kOSKextLogBasicLevel | kOSKextLogIPCFlag,
		    "KextLog: Ignoring AuxKC load from %s\n", aux_filepath->getCStringNoCopy());
		if (ret != kOSKextReturnKCLoadFailure) {
			ret = kOSKextReturnUnsupported;
		}
	}

try_codeless:
	/*
	 * Load codeless kexts last so that there is no possibilty of a
	 * codeless kext bundle ID preventing a kext in the system KC from
	 * loading
	 */
	codeless_kexts = OSDynamicCast(OSArray,
	    requestArgs->getObject(kKextRequestArgumentCodelessPersonalities));
	if (codeless_kexts != NULL) {
		uint32_t count = codeless_kexts->getCount();
		OSKextLog(NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "KextLog: loading %d codeless kexts/dexts", count);
		for (uint32_t i = 0; i < count; i++) {
			OSDictionary *infoDict;
			infoDict = OSDynamicCast(OSDictionary,
			    codeless_kexts->getObject(i));
			if (!infoDict) {
				continue;
			}
			// instantiate a new kext, and don't hold a reference
			// (the kext subsystem will hold one implicitly)
			OSKext::withCodelessInfo(infoDict);
		}
		/* ignore errors that are not KC load failures */
		if (ret != kOSKextReturnKCLoadFailure) {
			ret = kOSReturnSuccess;
		}
		start_matching = true;
	}

	/* send personalities to the IOCatalog once */
	if (ret == kOSReturnSuccess || start_matching || sOSKextWasResetAfterUserspaceReboot) {
		OSKext::sendAllKextPersonalitiesToCatalog(true);
		/*
		 * This request necessarily came from the IOKit daemon (kernelmanagerd), so mark
		 * things as active and start all the delayed matching: the
		 * dext and codeless kext personalities should have all been
		 * delivered via this one call.
		 */
		if (!daemon_ready) {
			OSKext::setIOKitDaemonActive();
			OSKext::setDeferredLoadSucceeded(TRUE);
			IOService::iokitDaemonLaunched();
		}
		if (sOSKextWasResetAfterUserspaceReboot) {
			sOSKextWasResetAfterUserspaceReboot = false;
			OSKext::setIOKitDaemonActive();
			IOService::startDeferredMatches();
		}
	}

	if (ret == kOSKextReturnKCLoadFailure) {
		ret |= kcerr;
	}

	/*
	 * Only allow this function to attempt to load the pageable and
	 * aux KCs once per boot.
	 */
	daemon_ready = true;

	IORecursiveLockUnlock(sKextLock);

	return ret;
}

OSReturn
OSKext::resetMutableSegments(void)
{
	kernel_segment_command_t *seg = NULL;
	kernel_mach_header_t *k_mh = (kernel_mach_header_t *)kmod_info->address;
	u_int index = 0;
	OSKextSavedMutableSegment *savedSegment = NULL;
	uintptr_t kext_slide = PE_get_kc_slide(kc_type);
	OSReturn err;

	if (!savedMutableSegments) {
		OSKextLog(this, kOSKextLogErrorLevel | kOSKextLogLoadFlag,
		    "Kext %s cannot be reset, mutable segments were not saved.", getIdentifierCString());
		err = kOSKextReturnInternalError;
		goto finish;
	}

	for (seg = firstsegfromheader(k_mh), index = 0; seg; seg = nextsegfromheader(k_mh, seg)) {
		if (!segmentIsMutable(seg)) {
			continue;
		}
		uint64_t unslid_vmaddr = seg->vmaddr - kext_slide;
		uint64_t vmsize = seg->vmsize;
		err = kOSKextReturnInternalError;
		for (index = 0; index < savedMutableSegments->getCount(); index++) {
			savedSegment = OSDynamicCast(OSKextSavedMutableSegment, savedMutableSegments->getObject(index));
			assert(savedSegment);
			if (savedSegment->getVMAddr() == seg->vmaddr && savedSegment->getVMSize() == seg->vmsize) {
				OSKextLog(this, kOSKextLogDebugLevel | kOSKextLogLoadFlag,
				    "Resetting kext %s, mutable segment %.*s %llx->%llx.", getIdentifierCString(), (int)strnlen(seg->segname, sizeof(seg->segname)), seg->segname, unslid_vmaddr, unslid_vmaddr + vmsize - 1);
				err = savedSegment->restoreContents(seg);
				if (err != kOSReturnSuccess) {
					panic("Kext %s cannot be reset, mutable segment %llx->%llx could not be restored.", getIdentifierCString(), unslid_vmaddr, unslid_vmaddr + vmsize - 1);
				}
			}
		}
		if (err != kOSReturnSuccess) {
			panic("Kext %s cannot be reset, could not find saved mutable segment for %llx->%llx.", getIdentifierCString(), unslid_vmaddr, unslid_vmaddr + vmsize - 1);
		}
	}
	err = kOSReturnSuccess;
finish:
	return err;
}


/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::loadKCFileSet(
	const char *filepath,
	kc_kind_t   type)
{
#if VM_MAPPED_KEXTS
	/* we only need to load filesets on systems that support VM_MAPPED kexts */
	OSReturn err;
	struct vnode *vp = NULL;
	void *fileset_control;
	off_t fsize;
	bool pageable = (type == KCKindPageable);

	if ((pageable && pageableKCloaded) ||
	    (!pageable && auxKCloaded)) {
		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "KC FileSet of type %s is already loaded", (pageable ? "Pageable" : "Aux"));

		return kOSKextReturnInvalidArgument;
	}

	/* Do not allow AuxKC to load if Pageable KC is not loaded */
	if (!pageable && !pageableKCloaded) {
		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "Trying to load the Aux KC without loading the Pageable KC");
		return kOSKextReturnInvalidArgument;
	}

	fileset_control = ubc_getobject_from_filename(filepath, &vp, &fsize);

	if (fileset_control == NULL) {
		printf("Could not get memory control object for file %s", filepath);

		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "Could not get memory control object for file %s", filepath);
		return kOSKextReturnInvalidArgument;
	}
	if (vp == NULL) {
		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "Could not find vnode for file %s", filepath);
		return kOSKextReturnInvalidArgument;
	}

	kernel_mach_header_t *mh = NULL;
	uintptr_t slide = 0;

#if CONFIG_CSR
	/*
	 * When SIP is enabled, the KC we map must be SIP-protected
	 */
	if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0) {
		struct vnode_attr va;
		int error;
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_flags);
		error = vnode_getattr(vp, &va, vfs_context_current());
		if (error) {
			OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
			    "vnode_getattr(%s) failed (error=%d)", filepath, error);
			err = kOSKextReturnInternalError;
			goto finish;
		}
		if (!(va.va_flags & SF_RESTRICTED)) {
			OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
			    "Path to KC '%s' is not SIP-protected", filepath);
			err = kOSKextReturnInvalidArgument;
			goto finish;
		}
	}
#endif

	err = OSKext::mapKCFileSet(fileset_control, (vm_size_t)fsize, &mh, 0, &slide, pageable, NULL);
	if (err) {
		printf("KextLog: mapKCFileSet returned %d\n", err);

		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "mapKCFileSet returned %d\n", err);

		err = kOSKextReturnInvalidArgument;
	}

#if CONFIG_CSR
finish:
#endif
	/* Drop the vnode ref returned by ubc_getobject_from_filename if mapKCFileSet failed */
	assert(vp != NULL);
	if (err == kOSReturnSuccess) {
		PE_set_kc_vp(type, vp);
		if (pageable) {
			pageableKCloaded = true;
		} else {
			auxKCloaded = true;
		}
	} else {
		vnode_put(vp);
	}

	return err;
#else
	(void)filepath;
	(void)type;
	return kOSKextReturnUnsupported;
#endif // VM_MAPPED_KEXTS
}

#if defined(__x86_64__) || defined(__i386__)
/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::mapKCFileSet(
	void                 *control,
	vm_size_t            fsize,
	kernel_mach_header_t **mhp,
	off_t                file_offset,
	uintptr_t            *slidep,
	bool                 pageable,
	void                 *map_entry_list)
{
	bool fileset_load = false;
	kern_return_t ret;
	OSReturn err;
	kernel_section_t *infoPlistSection = NULL;
	OSDictionary *infoDict = NULL;

	OSSharedPtr<OSObject> parsedXML;
	OSSharedPtr<OSString> errorString;
	OSSharedPtr<OSData> loaded_kcUUID;

	/* Check if initial load for file set */
	if (*mhp == NULL) {
		fileset_load = true;

		/* Get a page aligned address from kext map to map the file */
		vm_map_offset_t pagealigned_addr = get_address_from_kext_map(fsize);
		if (pagealigned_addr == 0) {
			return kOSKextReturnNoMemory;
		}

		*mhp = (kernel_mach_header_t *)pagealigned_addr;

		/* Allocate memory for bailout mechanism */
		map_entry_list = allocate_kcfileset_map_entry_list();
		if (map_entry_list == NULL) {
			return kOSKextReturnNoMemory;
		}
	}

	uintptr_t *slideptr = fileset_load ? slidep : NULL;
	err = mapKCTextSegment(control, mhp, file_offset, slideptr, map_entry_list);
	/* mhp and slideptr are updated by mapKCTextSegment */
	if (err) {
		if (fileset_load) {
			deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, TRUE, pageable);
		}
		return err;
	}

	/* Initialize the kc header globals */
	if (fileset_load) {
		if (pageable) {
			PE_set_kc_header(KCKindPageable, *mhp, *slidep);
		} else {
			PE_set_kc_header(KCKindAuxiliary, *mhp, *slidep);
		}
	}

	/* Iterate through all the segments and map necessary segments */
	struct load_command *lcp = (struct load_command *) (*mhp + 1);
	for (unsigned int i = 0; i < (*mhp)->ncmds; i++, lcp = (struct load_command *)((uintptr_t)lcp + lcp->cmdsize)) {
		vm_map_offset_t start;
		kernel_mach_header_t *k_mh = NULL;
		kernel_segment_command_t * seg = NULL;
		struct fileset_entry_command *fse = NULL;

		if (lcp->cmd == LC_SEGMENT_KERNEL) {
			seg = (kernel_segment_command_t *)lcp;
			start = ((uintptr_t)(seg->vmaddr)) + *slidep;
		} else if (lcp->cmd == LC_FILESET_ENTRY) {
			fse = (struct fileset_entry_command *)lcp;
			k_mh = (kernel_mach_header_t *)(((uintptr_t)(fse->vmaddr)) + *slidep);

			/* Map the segments of the mach-o binary */
			err = OSKext::mapKCFileSet(control, 0, &k_mh, fse->fileoff, slidep, pageable, map_entry_list);
			if (err) {
				deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, TRUE, pageable);
				return kOSKextReturnInvalidArgument;
			}
			continue;
		} else if (lcp->cmd == LC_DYLD_CHAINED_FIXUPS) {
			/* Check if the Aux KC is built pageable style */
			if (!pageable && !fileset_load && !auxKCloaded) {
				resetAuxKCSegmentOnUnload = true;
			}
			continue;
		} else {
			continue;
		}

		if (fileset_load) {
			if (seg->vmsize == 0) {
				continue;
			}

			/* Only map __PRELINK_INFO, __BRANCH_STUBS, __BRANCH_GOTS and __LINKEDIT sections */
			if (strncmp(seg->segname, kPrelinkInfoSegment, sizeof(seg->segname)) != 0 &&
			    strncmp(seg->segname, kKCBranchStubs, sizeof(seg->segname)) != 0 &&
			    strncmp(seg->segname, kKCBranchGots, sizeof(seg->segname)) != 0 &&
			    strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) != 0) {
				continue;
			}
		} else {
			if (seg->vmsize == 0) {
				continue;
			}

			/* Skip the __LINKEDIT, __LINKINFO and __TEXT segments */
			if (strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) == 0 ||
			    strncmp(seg->segname, SEG_LINKINFO, sizeof(seg->segname)) == 0 ||
			    strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
				continue;
			}
		}

		ret = vm_map_kcfileset_segment(
			&start, seg->vmsize,
			(memory_object_control_t)control, seg->fileoff, seg->maxprot);

		if (ret != KERN_SUCCESS) {
			if (fileset_load) {
				deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, TRUE, pageable);
			}
			return kOSKextReturnInvalidArgument;
		}
		add_kcfileset_map_entry(map_entry_list, start, seg->vmsize);
	}

	/* Return if regular mach-o */
	if (!fileset_load) {
		return 0;
	}

	/*
	 * Fixup for the Pageable KC and the Aux KC is done by
	 * i386_slide_kext_collection_mh_addrs, but it differs in
	 * following ways:
	 *
	 * PageableKC: Fixup only __BRANCH_STUBS segment and top level load commands.
	 * The fixup of kext segments and kext load commands are done at kext
	 * load time by calling i386_slide_individual_kext.
	 *
	 * AuxKC old style: Fixup all the segments and all the load commands.
	 *
	 * AuxKC pageable style: Same as the Pageable KC.
	 */
	bool adjust_mach_header = (pageable ? true : ((resetAuxKCSegmentOnUnload) ? true : false));
	ret = i386_slide_kext_collection_mh_addrs(*mhp, *slidep, adjust_mach_header);
	if (ret != KERN_SUCCESS) {
		deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, TRUE, pageable);
		return kOSKextReturnInvalidArgument;
	}

	/* Get the prelink info dictionary */
	infoPlistSection = getsectbynamefromheader(*mhp, kPrelinkInfoSegment, kPrelinkInfoSection);
	parsedXML = OSUnserializeXML((const char *)infoPlistSection->addr, errorString);
	if (parsedXML) {
		infoDict = OSDynamicCast(OSDictionary, parsedXML.get());
	}

	if (!infoDict) {
		const char *errorCString = "(unknown error)";

		if (errorString && errorString->getCStringNoCopy()) {
			errorCString = errorString->getCStringNoCopy();
		} else if (parsedXML) {
			errorCString = "not a dictionary";
		}
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "Error unserializing kext info plist section: %s.", errorCString);
		deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, TRUE, pageable);
		return kOSKextReturnInvalidArgument;
	}

	/* Validate that the Kext Collection is prelinked to the loaded KC */
	err = OSKext::validateKCFileSetUUID(infoDict, pageable ? KCKindPageable : KCKindAuxiliary);
	if (err) {
		deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, TRUE, pageable);
		return kOSKextReturnInvalidArgument;
	}

	/* Set Protection of Segments */
	OSKext::protectKCFileSet(*mhp, pageable ? KCKindPageable : KCKindAuxiliary);

	OSKext::addKextsFromKextCollection(*mhp,
	    infoDict, kPrelinkTextSegment,
	    loaded_kcUUID, pageable ? KCKindPageable : KCKindAuxiliary);

	/* Copy in the KC UUID */
	if (!loaded_kcUUID) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "WARNING: did not find UUID in prelinked %s KC!", pageable ? "Pageable" : "Aux");
	} else if (pageable) {
		pageablekc_uuid_valid = TRUE;
		memcpy((void *)&pageablekc_uuid, (const void *)loaded_kcUUID->getBytesNoCopy(), loaded_kcUUID->getLength());
		uuid_unparse_upper(pageablekc_uuid, pageablekc_uuid_string);
	} else {
		auxkc_uuid_valid = TRUE;
		memcpy((void *)&auxkc_uuid, (const void *)loaded_kcUUID->getBytesNoCopy(), loaded_kcUUID->getLength());
		uuid_unparse_upper(auxkc_uuid, auxkc_uuid_string);
	}

	deallocate_kcfileset_map_entry_list_and_unmap_entries(map_entry_list, FALSE, pageable);

	return 0;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::mapKCTextSegment(
	void                 *control,
	kernel_mach_header_t **mhp,
	off_t                file_offset,
	uintptr_t            *slidep,
	void                 *map_entry_list)
{
	kern_return_t ret;
	vm_map_offset_t mach_header_map_size = vm_map_round_page(sizeof(kernel_mach_header_t),
	    PAGE_MASK);
	vm_map_offset_t load_command_map_size = 0;
	kernel_mach_header_t *base_mh = *mhp;

	/* Map the mach header at start of fileset for now (vmaddr = 0) */
	ret = vm_map_kcfileset_segment(
		(vm_map_offset_t *)&base_mh, mach_header_map_size,
		(memory_object_control_t)control, file_offset, (VM_PROT_READ | VM_PROT_WRITE));

	if (ret != KERN_SUCCESS) {
		printf("Kext Log: mapKCTextSegment failed to map mach header of fileset %x", ret);

		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "Failed to map mach header of kc fileset with error %d", ret);
		return kOSKextReturnInvalidArgument;
	}

	if (slidep) {
		/* Verify that it's an MH_FILESET */
		if (base_mh->filetype != MH_FILESET) {
			printf("Kext Log: mapKCTextSegment mach header filetype"
			    " is not an MH_FILESET, it is %x", base_mh->filetype);

			OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
			    "mapKCTextSegment mach header filetype is not an MH_FILESET, it is %x", base_mh->filetype);

			/* Unmap the mach header */
			vm_unmap_kcfileset_segment((vm_map_offset_t *)&base_mh, mach_header_map_size);
			return kOSKextReturnInvalidArgument;
		}
	}

	/* Map the remaining pages of load commands */
	if (base_mh->sizeofcmds > mach_header_map_size) {
		vm_map_offset_t load_command_addr = ((vm_map_offset_t)base_mh) + mach_header_map_size;
		load_command_map_size = base_mh->sizeofcmds - mach_header_map_size;

		/* Map the load commands */
		ret = vm_map_kcfileset_segment(
			&load_command_addr, load_command_map_size,
			(memory_object_control_t)control, file_offset + mach_header_map_size,
			(VM_PROT_READ | VM_PROT_WRITE));

		if (ret != KERN_SUCCESS) {
			printf("KextLog: mapKCTextSegment failed to map load commands of fileset %x", ret);
			OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
			    "Failed to map load commands of kc fileset with error %d", ret);

			/* Unmap the mach header */
			vm_unmap_kcfileset_segment((vm_map_offset_t *)&base_mh, mach_header_map_size);
			return kOSKextReturnInvalidArgument;
		}
	}

	kernel_segment_command_t *text_seg;
	text_seg = getsegbynamefromheader((kernel_mach_header_t *)base_mh, SEG_TEXT);

	/* Calculate the slide and vm addr of mach header */
	if (slidep) {
		*mhp = (kernel_mach_header_t *)((uintptr_t)base_mh + text_seg->vmaddr);
		*slidep = ((uintptr_t)*mhp) - text_seg->vmaddr;
	}

	/* Cache the text segment size and file offset before unmapping */
	vm_map_offset_t text_segment_size = text_seg->vmsize;
	vm_object_offset_t text_segment_fileoff = text_seg->fileoff;
	vm_prot_t text_maxprot = text_seg->maxprot;

	/* Unmap the first page and loadcommands and map the text segment */
	ret = vm_unmap_kcfileset_segment((vm_map_offset_t *)&base_mh, mach_header_map_size);
	assert(ret == KERN_SUCCESS);

	if (load_command_map_size) {
		vm_map_offset_t load_command_addr = ((vm_map_offset_t)base_mh) + mach_header_map_size;
		ret = vm_unmap_kcfileset_segment(&load_command_addr, load_command_map_size);
		assert(ret == KERN_SUCCESS);
	}

	/* Map the text segment at actual vm addr specified in fileset */
	ret = vm_map_kcfileset_segment((vm_map_offset_t *)mhp, text_segment_size,
	    (memory_object_control_t)control, text_segment_fileoff, text_maxprot);
	if (ret != KERN_SUCCESS) {
		OSKextLog(/* kext */ NULL, kOSKextLogDebugLevel | kOSKextLogIPCFlag,
		    "Failed to map Text segment of kc fileset with error %d", ret);
		return kOSKextReturnInvalidArgument;
	}

	add_kcfileset_map_entry(map_entry_list, (vm_map_offset_t)*mhp, text_segment_size);
	return 0;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::protectKCFileSet(
	kernel_mach_header_t *mh,
	kc_kind_t            type)
{
	vm_map_t                    kext_map        = g_kext_map;
	kernel_segment_command_t  * seg             = NULL;
	vm_map_offset_t             start           = 0;
	vm_map_offset_t             end             = 0;
	OSReturn                    ret             = 0;

	/* Set VM permissions */
	seg = firstsegfromheader((kernel_mach_header_t *)mh);
	while (seg) {
		start = round_page(seg->vmaddr);
		end = trunc_page(seg->vmaddr + seg->vmsize);

		/*
		 * Wire down and protect __TEXT, __BRANCH_STUBS and __BRANCH_GOTS
		 * for the Pageable KC and the Aux KC, wire down and protect __LINKEDIT
		 * for the Aux KC as well.
		 */
		if (strncmp(seg->segname, kKCBranchGots, sizeof(seg->segname)) == 0 ||
		    strncmp(seg->segname, kKCBranchStubs, sizeof(seg->segname)) == 0 ||
		    strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0 ||
		    (type == KCKindAuxiliary && !resetAuxKCSegmentOnUnload &&
		    strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) == 0)) {
			ret = OSKext_protect((kernel_mach_header_t *)mh,
			    kext_map, start, end, seg->maxprot, TRUE, type);
			if (ret != KERN_SUCCESS) {
				printf("OSKext protect failed with error %d", ret);
				return kOSKextReturnInvalidArgument;
			}

			ret = OSKext_protect((kernel_mach_header_t *)mh,
			    kext_map, start, end, seg->initprot, FALSE, type);
			if (ret != KERN_SUCCESS) {
				printf("OSKext protect failed with error %d", ret);
				return kOSKextReturnInvalidArgument;
			}

			ret = OSKext_wire((kernel_mach_header_t *)mh,
			    kext_map, start, end, seg->initprot, FALSE, type);
			if (ret != KERN_SUCCESS) {
				printf("OSKext wire failed with error %d", ret);
				return kOSKextReturnInvalidArgument;
			}
		}

		seg = nextsegfromheader((kernel_mach_header_t *) mh, seg);
	}

	return 0;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
void
OSKext::freeKCFileSetcontrol(void)
{
	PE_reset_all_kc_vp();
}

/*********************************************************************
* Assumes sKextLock is held.
*
* resetKCFileSetSegments: Kext start function expects data segment to
* be pristine on every load, unmap the dirty segments on unload and
* remap them from FileSet on disk. Remap all segments of kext since
* fixups are done per kext and not per segment.
*********************************************************************/
OSReturn
OSKext::resetKCFileSetSegments(void)
{
	kernel_segment_command_t *seg = NULL;
	kernel_segment_command_t *text_seg;
	uint32_t text_fileoff;
	kernel_mach_header_t *k_mh = NULL;
	uintptr_t slide;
	struct vnode *vp = NULL;
	void *fileset_control = NULL;
	bool pageable = (kc_type == KCKindPageable);
	OSReturn err;
	kern_return_t kr;

	/* Check the vnode reference is still available */
	vp = (struct vnode *)PE_get_kc_vp(kc_type);
	if (vp == NULL) {
		OSKextLog(this, kOSKextLogProgressLevel | kOSKextLogLoadFlag,
		    "Kext %s could not be reset, since reboot released the vnode ref", getIdentifierCString());
		return kOSKextReturnInternalError;
	}

	fileset_control = ubc_getobject(vp, 0);
	assert(fileset_control != NULL);

	OSKextLog(this, kOSKextLogProgressLevel | kOSKextLogLoadFlag,
	    "Kext %s resetting all segments", getIdentifierCString());

	k_mh = (kernel_mach_header_t *)kmod_info->address;
	text_seg = getsegbynamefromheader((kernel_mach_header_t *)kmod_info->address, SEG_TEXT);
	text_fileoff = text_seg->fileoff;
	slide = PE_get_kc_slide(kc_type);

	seg = firstsegfromheader((kernel_mach_header_t *)k_mh);
	while (seg) {
		if (seg->vmsize == 0) {
			seg = nextsegfromheader((kernel_mach_header_t *) k_mh, seg);
			continue;
		}

		/* Skip the __LINKEDIT, __LINKINFO and __TEXT segments */
		if (strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) == 0 ||
		    strncmp(seg->segname, SEG_LINKINFO, sizeof(seg->segname)) == 0 ||
		    strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
			seg = nextsegfromheader((kernel_mach_header_t *) k_mh, seg);
			continue;
		}

		kr = vm_unmap_kcfileset_segment(&seg->vmaddr, seg->vmsize);
		assert(kr == KERN_SUCCESS);
		seg = nextsegfromheader((kernel_mach_header_t *) k_mh, seg);
	}

	/* Unmap the text segment */
	kr = vm_unmap_kcfileset_segment(&text_seg->vmaddr, text_seg->vmsize);
	assert(kr == KERN_SUCCESS);

	/* Map all the segments of the kext */
	err = OSKext::mapKCFileSet(fileset_control, 0, &k_mh, text_fileoff, &slide, pageable, NULL);
	if (err) {
		panic("Could not reset segments of a mapped kext, error %x", err);
	}

	/* Update address in kmod_info, since it has been reset */
	if (kmod_info->address) {
		kmod_info->address = (((uintptr_t)(kmod_info->address)) + slide);
	}

	return 0;
}

/*********************************************************************
* Mechanism to track all segment mapping while mapping KC fileset.
*********************************************************************/

struct kcfileset_map_entry {
	vm_map_offset_t me_start;
	vm_map_offset_t me_size;
};

struct kcfileset_map_entry_list {
	int                        kme_list_count;
	int                        kme_list_index;
	struct kcfileset_map_entry kme_list[];
};

#define KCFILESET_MAP_ENTRY_MAX (16380)

static void *
allocate_kcfileset_map_entry_list(void)
{
	struct kcfileset_map_entry_list *entry_list;

	entry_list = (struct kcfileset_map_entry_list *)kalloc(sizeof(struct kcfileset_map_entry_list) +
	    (sizeof(struct kcfileset_map_entry) * KCFILESET_MAP_ENTRY_MAX));

	entry_list->kme_list_count = KCFILESET_MAP_ENTRY_MAX;
	entry_list->kme_list_index = 0;
	return entry_list;
}

static void
add_kcfileset_map_entry(
	void            *map_entry_list,
	vm_map_offset_t start,
	vm_map_offset_t size)
{
	if (map_entry_list == NULL) {
		return;
	}

	struct kcfileset_map_entry_list *entry_list = (struct kcfileset_map_entry_list *)map_entry_list;

	if (entry_list->kme_list_index >= entry_list->kme_list_count) {
		panic("Ran out of map kc fileset list\n");
	}

	entry_list->kme_list[entry_list->kme_list_index].me_start = start;
	entry_list->kme_list[entry_list->kme_list_index].me_size = size;

	entry_list->kme_list_index++;
}

static void
deallocate_kcfileset_map_entry_list_and_unmap_entries(
	void      *map_entry_list,
	boolean_t unmap_entries,
	bool      pageable)
{
	struct kcfileset_map_entry_list *entry_list = (struct kcfileset_map_entry_list *)map_entry_list;

	if (unmap_entries) {
		for (int i = 0; i < entry_list->kme_list_index; i++) {
			kern_return_t ret;
			ret = vm_unmap_kcfileset_segment(
				&(entry_list->kme_list[i].me_start),
				entry_list->kme_list[i].me_size);
			assert(ret == KERN_SUCCESS);
		}

		PE_reset_kc_header(pageable ? KCKindPageable : KCKindAuxiliary);
	}

	kfree(entry_list, sizeof(struct kcfileset_map_entry_list) +
	    (sizeof(struct kcfileset_map_entry) * KCFILESET_MAP_ENTRY_MAX));
}

/*********************************************************************
* Mechanism to map kext segment.
*********************************************************************/

kern_return_t
vm_map_kcfileset_segment(
	vm_map_offset_t    *start,
	vm_map_offset_t    size,
	void               *control,
	vm_object_offset_t fileoffset,
	vm_prot_t          max_prot)
{
	vm_map_kernel_flags_t vmk_flags;
	vmk_flags.vmkf_no_copy_on_read = 1;
	vmk_flags.vmkf_cs_enforcement = 0;
	vmk_flags.vmkf_cs_enforcement_override = 1;
	kern_return_t ret;

	/* Add Write to max prot to allow fixups */
	max_prot = max_prot | VM_PROT_WRITE;

	/*
	 * Map the segments from file as COPY mappings to
	 * make sure changes on disk to the file does not affect
	 * mapped segments.
	 */
	ret = vm_map_enter_mem_object_control(
		g_kext_map,
		start,
		size,
		(mach_vm_offset_t)0,
		VM_FLAGS_FIXED,
		vmk_flags,
		VM_KERN_MEMORY_OSKEXT,
		(memory_object_control_t)control,
		fileoffset,
		TRUE,         /* copy */
		(VM_PROT_READ | VM_PROT_WRITE), max_prot,
		VM_INHERIT_NONE);

	return ret;
}

kern_return_t
vm_unmap_kcfileset_segment(
	vm_map_offset_t    *start,
	vm_map_offset_t    size)
{
	return mach_vm_deallocate(g_kext_map, *start, size);
}

#endif //(__x86_64__) || defined(__i386__)

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::validateKCFileSetUUID(
	OSDictionary         *infoDict,
	kc_kind_t            type)
{
	OSReturn ret           = kOSReturnSuccess;

	if (!kernelcache_uuid_valid) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "validateKCFileSetUUID Boot KC UUID was not set at boot.");
		ret = kOSKextReturnInvalidArgument;
		goto finish;
	}
	ret = OSKext::validateKCUUIDfromPrelinkInfo(&kernelcache_uuid, type, infoDict, kPrelinkInfoBootKCIDKey);
	if (ret != 0) {
		goto finish;
	}

#if defined(__x86_64__) || defined(__i386__)
	/* Check if the Aux KC is prelinked to correct Pageable KC */
	if (type == KCKindAuxiliary) {
		if (!pageablekc_uuid_valid) {
			OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
			    "validateKCFileSetUUID Pageable KC UUID was not set while loading Pageable KC.");
			ret = kOSKextReturnInvalidArgument;
			goto finish;
		}
		ret = OSKext::validateKCUUIDfromPrelinkInfo(&pageablekc_uuid, type, infoDict, kPrelinkInfoPageableKCIDKey);
		if (ret != 0) {
			goto finish;
		}
	}
#endif //(__x86_64__) || defined(__i386__)

	printf("KextLog: Collection UUID matches with loaded KCs.\n");
finish:
	return ret;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::validateKCUUIDfromPrelinkInfo(
	uuid_t               *loaded_kcuuid,
	kc_kind_t             type,
	OSDictionary         *infoDict,
	const char           *uuid_key)
{
	/* extract the UUID from the dictionary */
	OSData *prelinkinfoKCUUID = OSDynamicCast(OSData, infoDict->getObject(uuid_key));
	if (!prelinkinfoKCUUID) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "validateKCUUID Info plist does not contain %s KC UUID key.", uuid_key);
		return kOSKextReturnInvalidArgument;
	}

	if (prelinkinfoKCUUID->getLength() != sizeof(uuid_t)) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "validateKCUUID %s KC UUID has wrong length: %d.", uuid_key, prelinkinfoKCUUID->getLength());
		return kOSKextReturnInvalidArgument;
	}

	if (memcmp((void *)loaded_kcuuid, (const void *)prelinkinfoKCUUID->getBytesNoCopy(),
	    prelinkinfoKCUUID->getLength())) {
		OSData       *info_dict_uuid;
		uuid_string_t info_dict_uuid_str = {};
		uuid_string_t expected_uuid_str = {};
		uuid_string_t given_uuid_str = {};
		uuid_t        given_uuid;

		/* extract the KC UUID from the dictionary */
		info_dict_uuid = OSDynamicCast(OSData, infoDict->getObject(kPrelinkInfoKCIDKey));
		if (info_dict_uuid && info_dict_uuid->getLength() == sizeof(uuid_t)) {
			uuid_t tmp_uuid;
			memcpy(tmp_uuid, (const void *)info_dict_uuid->getBytesNoCopy(), sizeof(tmp_uuid));
			uuid_unparse(tmp_uuid, info_dict_uuid_str);
		}

		uuid_unparse(*loaded_kcuuid, expected_uuid_str);
		memcpy(given_uuid, (const void *)prelinkinfoKCUUID->getBytesNoCopy(), sizeof(given_uuid));
		uuid_unparse(given_uuid, given_uuid_str);

		printf("KextLog: ERROR: UUID from key:%s %s != expected %s (KC UUID: %s)\n", uuid_key,
		    given_uuid_str, expected_uuid_str, info_dict_uuid_str);
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "KextLog: ERROR: UUID from key:%s %s != expected %s (KC UUID: %s)\n", uuid_key,
		    given_uuid_str, expected_uuid_str, info_dict_uuid_str);
		if (type == KCKindPageable && sPanicOnKCMismatch) {
			panic("System KC UUID %s linked against %s, but %s is loaded",
			    info_dict_uuid_str, given_uuid_str, expected_uuid_str);
		}
		return kOSKextReturnInvalidArgument;
	}

	return 0;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::dispatchResource(OSDictionary * requestDict)
{
	OSReturn                        result          = kOSReturnError;
	OSSharedPtr<OSDictionary>       callbackRecord;
	OSNumber                      * requestTag      = NULL;        // do not release
	OSNumber                      * requestResult   = NULL;        // do not release
	OSData                        * dataObj         = NULL;        // do not release
	uint32_t                        dataLength      = 0;
	const void                    * dataPtr         = NULL;        // do not free
	OSData                        * callbackWrapper = NULL;        // do not release
	OSKextRequestResourceCallback   callback        = NULL;
	OSData                        * contextWrapper  = NULL;        // do not release
	void                          * context         = NULL;        // do not free
	OSSharedPtr<OSKext>             callbackKext;

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
	result = dequeueCallbackForRequestTag(requestTag, callbackRecord);
	if (result != kOSReturnSuccess) {
		goto finish;
	}

	/*****
	 * Get the context pointer of the callback record (if there is one).
	 */
	contextWrapper = OSDynamicCast(OSData, _OSKextGetRequestArgument(callbackRecord.get(),
	    kKextRequestArgumentContextKey));
	context = _OSKextExtractPointer(contextWrapper);
	if (contextWrapper && !context) {
		goto finish;
	}

	callbackWrapper = OSDynamicCast(OSData,
	    _OSKextGetRequestArgument(callbackRecord.get(),
	    kKextRequestArgumentCallbackKey));
	callback = _OSKextExtractCallbackPointer(callbackWrapper);
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
	return result;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::setMissingAuxKCBundles(OSDictionary * requestDict)
{
	OSSharedPtr<OSDictionary> missingIDs;
	OSArray *bundleIDList     = NULL; // do not release

	bundleIDList = OSDynamicCast(OSArray, _OSKextGetRequestArgument(
		    requestDict, kKextRequestArgumentMissingBundleIDs));
	if (!bundleIDList) {
		return kOSKextReturnInvalidArgument;
	}

	missingIDs = OSDictionary::withCapacity(bundleIDList->getCount());
	if (!missingIDs) {
		return kOSKextReturnNoMemory;
	}

	uint32_t count, i;
	count = bundleIDList->getCount();
	for (i = 0; i < count; i++) {
		OSString *thisID = OSDynamicCast(OSString, bundleIDList->getObject(i));
		if (thisID) {
			missingIDs->setObject(thisID, kOSBooleanFalse);
		}
	}

	sNonLoadableKextsByID.reset(missingIDs.get(), OSRetain);

	return kOSReturnSuccess;
}

/*********************************************************************
* Assumes sKextLock is held.
*********************************************************************/
/* static */
OSReturn
OSKext::setAuxKCBundleAvailable(OSString *kextIdentifier, OSDictionary *requestDict)
{
	bool loadable = true;
	if (!kextIdentifier) {
		return kOSKextReturnInvalidArgument;
	}

	if (requestDict) {
		OSBoolean *loadableArg;
		loadableArg = OSDynamicCast(OSBoolean, _OSKextGetRequestArgument(
			    requestDict, kKextRequestArgumentBundleAvailability));
		/* If we find the "Bundle Available" arg, and it's false, then
		 * mark the bundle ID as _not_ loadable
		 */
		if (loadableArg && !loadableArg->getValue()) {
			loadable = false;
		}
	}

	if (!sNonLoadableKextsByID) {
		sNonLoadableKextsByID = OSDictionary::withCapacity(1);
	}

	sNonLoadableKextsByID->setObject(kextIdentifier, OSBoolean::withBoolean(loadable));

	OSKextLog(/* kext */ NULL,
	    kOSKextLogBasicLevel | kOSKextLogIPCFlag,
	    "KextLog: AuxKC bundle %s marked as %s",
	    kextIdentifier->getCStringNoCopy(),
	    (loadable ? "loadable" : "NOT loadable"));

	return kOSReturnSuccess;
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
	OSSharedPtr<OSNumber> resultNum;

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
	    resultNum.get());

	if (predicate->isEqualTo(kKextRequestPredicateRequestResource)) {
		/* This removes the pending callback record.
		 */
		OSKext::dispatchResource(callbackRecord);
	}

finish:
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
	OSSharedPtr<OSDictionary> callbackRecord;
	OSData       * contextWrapper = NULL;        // do not release

	IORecursiveLockLock(sKextLock);
	result = OSKext::dequeueCallbackForRequestTag(requestTag,
	    callbackRecord);
	IORecursiveLockUnlock(sKextLock);

	if (result == kOSReturnSuccess && contextOut) {
		contextWrapper = OSDynamicCast(OSData,
		    _OSKextGetRequestArgument(callbackRecord.get(),
		    kKextRequestArgumentContextKey));
		*contextOut = _OSKextExtractPointer(contextWrapper);
	}

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
		    ptrauth_strip(_OSKextExtractPointer(callbackWrapper), ptrauth_key_function_pointer);

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
		    ptrauth_strip(_OSKextExtractPointer(callbackWrapper), ptrauth_key_function_pointer);

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
static OSReturn
_OSKextCreateRequest(
	const char    * predicate,
	OSSharedPtr<OSDictionary> & requestR)
{
	OSReturn result = kOSKextReturnNoMemory;
	OSSharedPtr<OSDictionary> request;

	request = OSDictionary::withCapacity(2);
	if (!request) {
		goto finish;
	}
	result = _OSDictionarySetCStringValue(request.get(),
	    kKextRequestPredicateKey, predicate);
	if (result != kOSReturnSuccess) {
		goto finish;
	}
	result = kOSReturnSuccess;

finish:
	if (result == kOSReturnSuccess) {
		requestR = os::move(request);
	}

	return result;
}

/*********************************************************************
*********************************************************************/
static OSString *
_OSKextGetRequestPredicate(OSDictionary * requestDict)
{
	return OSDynamicCast(OSString,
	           requestDict->getObject(kKextRequestPredicateKey));
}

/*********************************************************************
*********************************************************************/
static OSObject *
_OSKextGetRequestArgument(
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
static bool
_OSKextSetRequestArgument(
	OSDictionary * requestDict,
	const char   * argName,
	OSObject     * value)
{
	OSDictionary * args = OSDynamicCast(OSDictionary,
	    requestDict->getObject(kKextRequestArgumentsKey));
	OSSharedPtr<OSDictionary> newArgs;
	if (!args) {
		newArgs = OSDictionary::withCapacity(2);
		args = newArgs.get();
		if (!args) {
			goto finish;
		}
		requestDict->setObject(kKextRequestArgumentsKey, args);
	}
	if (args) {
		return args->setObject(argName, value);
	}
finish:
	return false;
}

/*********************************************************************
*********************************************************************/
static void *
_OSKextExtractPointer(OSData * wrapper)
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
static OSKextRequestResourceCallback
_OSKextExtractCallbackPointer(OSData * wrapper)
{
	OSKextRequestResourceCallback       result = NULL;
	const void * resultPtr = NULL;

	if (!wrapper) {
		goto finish;
	}
	resultPtr = wrapper->getBytesNoCopy();
	result = *(OSKextRequestResourceCallback *)resultPtr;
finish:
	return result;
}


/*********************************************************************
*********************************************************************/
static OSReturn
_OSDictionarySetCStringValue(
	OSDictionary * dict,
	const char   * cKey,
	const char   * cValue)
{
	OSReturn result = kOSKextReturnNoMemory;
	OSSharedPtr<const OSSymbol> key;
	OSSharedPtr<OSString> value;

	key = OSSymbol::withCString(cKey);
	value = OSString::withCString(cValue);
	if (!key || !value) {
		goto finish;
	}
	if (dict->setObject(key.get(), value.get())) {
		result = kOSReturnSuccess;
	}

finish:
	return result;
}

/*********************************************************************
*********************************************************************/
static bool
_OSArrayContainsCString(
	OSArray    * array,
	const char * cString)
{
	bool             result = false;
	OSSharedPtr<const OSSymbol> symbol;
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
	return result;
}

#if CONFIG_KXLD
/*********************************************************************
* We really only care about boot / system start up related kexts.
* We return true if we're less than REBUILD_MAX_TIME since start up,
* otherwise return false.
*********************************************************************/
bool
_OSKextInPrelinkRebuildWindow(void)
{
	static bool     outside_the_window = false;
	AbsoluteTime    my_abstime;
	UInt64          my_ns;
	SInt32          my_secs;

	if (outside_the_window) {
		return false;
	}
	clock_get_uptime(&my_abstime);
	absolutetime_to_nanoseconds(my_abstime, &my_ns);
	my_secs = (SInt32)(my_ns / NSEC_PER_SEC);
	if (my_secs > REBUILD_MAX_TIME) {
		outside_the_window = true;
		return false;
	}
	return true;
}
#endif /* CONFIG_KXLD */

/*********************************************************************
*********************************************************************/
bool
_OSKextInUnloadedPrelinkedKexts( const OSSymbol * theBundleID )
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
		const OSSymbol *    myBundleID;        // do not release

		myBundleID = OSDynamicCast(OSSymbol, sUnloadedPrelinkedKexts->getObject(i));
		if (!myBundleID) {
			continue;
		}
		if (theBundleID->isEqualTo(myBundleID->getCStringNoCopy())) {
			result = true;
			break;
		}
	}
finish:
	IORecursiveLockUnlock(sKextLock);
	return result;
}

#if PRAGMA_MARK
#pragma mark Personalities (IOKit Drivers)
#endif
/*********************************************************************
*********************************************************************/
/* static */
OSSharedPtr<OSArray>
OSKext::copyAllKextPersonalities(bool filterSafeBootFlag)
{
	OSSharedPtr<OSArray>              result;
	OSSharedPtr<OSCollectionIterator> kextIterator;
	OSSharedPtr<OSArray>              personalities;

	OSString             * kextID                = NULL;        // do not release
	OSKext               * theKext               = NULL;        // do not release

	IORecursiveLockLock(sKextLock);

	/* Let's conservatively guess that any given kext has around 3
	 * personalities for now.
	 */
	result = OSArray::withCapacity(sKextsByID->getCount() * 3);
	if (!result) {
		goto finish;
	}

	kextIterator = OSCollectionIterator::withCollection(sKextsByID.get());
	if (!kextIterator) {
		goto finish;
	}

	while ((kextID = OSDynamicCast(OSString, kextIterator->getNextObject()))) {
		theKext = OSDynamicCast(OSKext, sKextsByID->getObject(kextID));
		if (theKext->flags.requireExplicitLoad) {
			OSKextLog(theKext,
			    kOSKextLogDebugLevel |
			    kOSKextLogLoadFlag,
			    "Kext %s requires an explicit kextload; "
			    "omitting its personalities.",
			    theKext->getIdentifierCString());
		} else if (!sSafeBoot || !filterSafeBootFlag || theKext->isLoadableInSafeBoot()) {
			personalities = theKext->copyPersonalitiesArray();
			if (!personalities) {
				continue;
			}
			result->merge(personalities.get());
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

	OSSharedPtr<OSArray> personalities = OSKext::copyAllKextPersonalities(
		/* filterSafeBootFlag */ true);

	if (personalities) {
		gIOCatalogue->addDrivers(personalities.get(), startMatching);
		numPersonalities = personalities->getCount();
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
OSSharedPtr<OSArray>
OSKext::copyPersonalitiesArray(void)
{
	OSSharedPtr<OSArray>              result;
	OSDictionary         * personalities               = NULL;        // do not release
	OSSharedPtr<OSCollectionIterator> personalitiesIterator;

	OSString             * personalityName             = NULL;        // do not release
	OSString             * personalityBundleIdentifier = NULL;        // do not release

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
			personality->setObject(kCFBundleIdentifierKey, bundleID.get());
		} else if (!personalityBundleIdentifier->isEqualTo(bundleID.get())) {
			personality->setObject(kIOPersonalityPublisherKey, bundleID.get());
		}

		result->setObject(personality);
	}

finish:
	return result;
}

/*********************************************************************
*   Might want to change this to a bool return?
*********************************************************************/
OSReturn
OSKext::sendPersonalitiesToCatalog(
	bool      startMatching,
	OSArray * personalityNames)
{
	OSReturn       result              = kOSReturnSuccess;
	OSSharedPtr<OSArray> personalitiesToSend;
	OSDictionary * kextPersonalities   = NULL;        // do not release
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
		gIOCatalogue->addDrivers(personalitiesToSend.get(), startMatching);
	}
finish:
	return result;
}

/*********************************************************************
* xxx - We should allow removing the kext's declared personalities,
* xxx - even with other bundle identifiers.
*********************************************************************/
void
OSKext::removePersonalitiesFromCatalog(void)
{
	OSSharedPtr<OSDictionary> personality;

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
	gIOCatalogue->removeDrivers(personality.get(), /* startMatching */ true);

finish:
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
OSSharedPtr<OSArray>
OSKext::clearUserSpaceLogFilter(void)
{
	OSSharedPtr<OSArray>       result;
	OSKextLogSpec   oldLogFilter;
	OSKextLogSpec   newLogFilter = kOSKextLogSilentFilter;

	/* Do not call any function that takes sKextLoggingLock during
	 * this critical block. That means do logging after.
	 */
	IOLockLock(sKextLoggingLock);

	result = OSArray::withCapacity(2);
	if (result) {
		result->setObject(sUserSpaceLogSpecArray.get());
		result->setObject(sUserSpaceLogMessageArray.get());
	}
	sUserSpaceLogSpecArray.reset();
	sUserSpaceLogMessageArray.reset();

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

inline const char *
colorForFlags(OSKextLogSpec flags)
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
		return "";         // white
	}
}

inline bool
logSpecMatch(
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
	char           * allocBuffer       = NULL;        // must kfree
	OSSharedPtr<OSNumber> logSpecNum;
	OSSharedPtr<OSString> logString;
	char           * buffer            = stackBuffer;        // do not free

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

	if (!(logForKernel || logForUser)) {
		goto finish;
	}

	/* No goto from here until past va_end()!
	 */
	va_copy(argList, srcArgList);
	length = vsnprintf(stackBuffer, sizeof(stackBuffer), format, argList);
	va_end(argList);

	if (length + 1 >= sizeof(stackBuffer)) {
		allocBuffer = (char *)kheap_alloc_tag(KHEAP_TEMP,
		    length + 1, Z_WAITOK, VM_KERN_MEMORY_OSKEXT);
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
			sUserSpaceLogSpecArray->setObject(logSpecNum.get());
			sUserSpaceLogMessageArray->setObject(logString.get());
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
			const char * color = "";         // do not free
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
		kheap_free(KHEAP_TEMP, allocBuffer, (length + 1) * sizeof(char));
	}
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

extern vm_offset_t       vm_kernel_stext;
extern vm_offset_t       vm_kernel_etext;
extern mach_vm_offset_t kext_alloc_base;
extern mach_vm_offset_t kext_alloc_max;

bool ScanForAddrInObject(OSObject * theObject,
    int indent );

bool
ScanForAddrInObject(OSObject * theObject,
    int indent)
{
	const OSMetaClass *     myTypeID;
	OSSharedPtr<OSCollectionIterator>  myIter;
	OSSymbol *              myKey;
	OSObject *              myValue;
	bool                    myResult = false;

	if (theObject == NULL) {
		IOLog("%s: theObject is NULL \n",
		    __FUNCTION__);
		return myResult;
	}

	myTypeID = OSTypeIDInst(theObject);

	if (myTypeID == OSTypeID(OSDictionary)) {
		OSDictionary *      myDictionary;

		myDictionary = OSDynamicCast(OSDictionary, theObject);
		myIter = OSCollectionIterator::withCollection( myDictionary );
		if (myIter == NULL) {
			return myResult;
		}

		// !! reset the iterator
		myIter->reset();

		while ((myKey = OSDynamicCast(OSSymbol, myIter->getNextObject()))) {
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

		// !! release the iterator
		myIter.reset();
	} else if (myTypeID == OSTypeID(OSArray)) {
		OSArray *   myArray;

		myArray = OSDynamicCast(OSArray, theObject);
		myIter = OSCollectionIterator::withCollection(myArray);
		if (myIter == NULL) {
			return myResult;
		}
		// !! reset the iterator
		myIter->reset();

		while ((myValue = myIter->getNextObject())) {
			bool        myTempResult;
			myTempResult = ScanForAddrInObject(myValue, (indent + 4));
			if (myTempResult) {
				// if we ever get a true result return true
				myResult = true;
				IOLOG_INDENT(indent);
				IOLog("OSArray: \n");
			}
		}
		// !! release the iterator
		myIter.reset();
	} else if (myTypeID == OSTypeID(OSString) || myTypeID == OSTypeID(OSSymbol)) {
		// should we look for addresses in strings?
	} else if (myTypeID == OSTypeID(OSData)) {
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
				UInt64 numberValue = (UInt64) * (myPtrPtr);

				if (kext_alloc_max != 0 &&
				    numberValue >= kext_alloc_base &&
				    numberValue < kext_alloc_max) {
					OSSharedPtr<OSKext> myKext;
					// IOLog("found OSData %p in kext map %p to %p  \n",
					//       *(myPtrPtr),
					//       (void *) kext_alloc_base,
					//       (void *) kext_alloc_max);

					myKext = OSKext::lookupKextWithAddress((vm_address_t) *(myPtrPtr));
					if (myKext) {
						IOLog("found addr %p from an OSData obj within kext \"%s\"  \n",
						    *(myPtrPtr),
						    myKext->getIdentifierCString());
					}
					myResult = true;
				}
				if (vm_kernel_etext != 0 &&
				    numberValue >= vm_kernel_stext &&
				    numberValue < vm_kernel_etext) {
					IOLog("found addr %p from an OSData obj within kernel text segment %p to %p  \n",
					    *(myPtrPtr),
					    (void *) vm_kernel_stext,
					    (void *) vm_kernel_etext);
					myResult = true;
				}
				myPtrPtr++;
			}
		}
	} else if (myTypeID == OSTypeID(OSBoolean)) {
		// do nothing here...
	} else if (myTypeID == OSTypeID(OSNumber)) {
		OSNumber * number = OSDynamicCast(OSNumber, theObject);

		UInt64 numberValue = number->unsigned64BitValue();

		if (kext_alloc_max != 0 &&
		    numberValue >= kext_alloc_base &&
		    numberValue < kext_alloc_max) {
			OSSharedPtr<OSKext> myKext;
			IOLog("found OSNumber in kext map %p to %p  \n",
			    (void *) kext_alloc_base,
			    (void *) kext_alloc_max);
			IOLog("OSNumber 0x%08llx (%llu) \n", numberValue, numberValue);

			myKext = OSKext::lookupKextWithAddress((vm_address_t) numberValue );
			if (myKext) {
				IOLog("found in kext \"%s\"  \n",
				    myKext->getIdentifierCString());
			}

			myResult = true;
		}
		if (vm_kernel_etext != 0 &&
		    numberValue >= vm_kernel_stext &&
		    numberValue < vm_kernel_etext) {
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
		if (myMetaClass) {
			IOLog("class %s \n", myMetaClass->getClassName());
		} else {
			IOLog("Unknown object \n" );
		}
	}
#endif

	return myResult;
}
#endif // KASLR_KEXT_DEBUG
};         /* extern "C" */

#if PRAGMA_MARK
#pragma mark Backtrace Dump & kmod_get_info() support
#endif
/*********************************************************************
* This function must be safe to call in panic context.
*********************************************************************/
/* static */
void
OSKext::printKextsInBacktrace(
	vm_offset_t  * addr __unused,
	unsigned int   cnt __unused,
	int         (* printf_func)(const char *fmt, ...) __unused,
	uint32_t       flags __unused)
{
	addr64_t    summary_page = 0;
	addr64_t    last_summary_page = 0;
	bool        found_kmod = false;
	u_int       i = 0;

	if (kPrintKextsLock & flags) {
		if (!sKextSummariesLock) {
			return;
		}
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
#if  __has_feature(ptrauth_calls)
		kscan_addr = (vm_offset_t)VM_KERNEL_STRIP_PTR(kscan_addr);
#endif /*  __has_feature(ptrauth_calls) */
		if ((kscan_addr >= summary->text_exec_address) &&
		    (kscan_addr < (summary->text_exec_address + summary->text_exec_size))) {
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
OSKext::summaryForAddress(uintptr_t addr)
{
#if  __has_feature(ptrauth_calls)
	addr = (uintptr_t)VM_KERNEL_STRIP_PTR(addr);
#endif /*  __has_feature(ptrauth_calls) */
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
OSKext::kextForAddress(const void *address)
{
	void                * image = NULL;
	OSKextActiveAccount * active;
	OSKext              * kext = NULL;
	uint32_t              baseIdx;
	uint32_t              lim;
	uintptr_t             addr = (uintptr_t) address;
	size_t                i;

	if (!addr) {
		return NULL;
	}
#if  __has_feature(ptrauth_calls)
	addr = (uintptr_t)VM_KERNEL_STRIP_PTR(addr);
#endif /*  __has_feature(ptrauth_calls) */

	if (sKextAccountsCount) {
		IOSimpleLockLock(sKextAccountsLock);
		// bsearch sKextAccounts list
		for (baseIdx = 0, lim = sKextAccountsCount; lim; lim >>= 1) {
			active = &sKextAccounts[baseIdx + (lim >> 1)];
			if ((addr >= active->address) && (addr < active->address_end)) {
				kext = active->account->kext;
				if (kext && kext->kmod_info) {
					image = (void *) kext->kmod_info->address;
				}
				break;
			} else if (addr > active->address) {
				// move right
				baseIdx += (lim >> 1) + 1;
				lim--;
			}
			// else move left
		}
		IOSimpleLockUnlock(sKextAccountsLock);
	}
	if (!image && (addr >= vm_kernel_stext) && (addr < vm_kernel_etext)) {
		image = (void *) &_mh_execute_header;
	}
	if (!image && gLoadedKextSummaries) {
		IOLockLock(sKextSummariesLock);
		for (i = 0; i < gLoadedKextSummaries->numSummaries; i++) {
			OSKextLoadedKextSummary *summary = gLoadedKextSummaries->summaries + i;
			if (addr >= summary->address && addr < summary->address + summary->size) {
				image = (void *)summary->address;
			}
		}
		IOLockUnlock(sKextSummariesLock);
	}

	return image;
}

/*
 * Find a OSKextLoadedKextSummary given the ID from a kmod_info_t *
 * Safe to call in panic context.
 */
static OSKextLoadedKextSummary *
findSummary(uint32_t tagID)
{
	OSKextLoadedKextSummary * summary;
	for (size_t i = 0; i < gLoadedKextSummaries->numSummaries; ++i) {
		summary = gLoadedKextSummaries->summaries + i;
		if (summary->loadTag == tagID) {
			return summary;
		}
	}
	return NULL;
}

/*********************************************************************
* This function must be safe to call in panic context.
*********************************************************************/
void
OSKext::printSummary(
	OSKextLoadedKextSummary * summary,
	int                    (* printf_func)(const char *fmt, ...),
	uint32_t                  flags)
{
	kmod_reference_t * kmod_ref = NULL;
	uuid_string_t uuid;
	char version[kOSKextVersionMaxLength];
	uint64_t tmpAddr;
	uint64_t tmpSize;
	OSKextLoadedKextSummary *dependencySummary;

	if (!OSKextVersionGetString(summary->version, version, sizeof(version))) {
		strlcpy(version, "unknown version", sizeof(version));
	}
	(void) uuid_unparse(summary->uuid, uuid);

#if defined(__arm__) || defined(__arm64__)
	tmpAddr = summary->text_exec_address;
	tmpSize = summary->text_exec_size;
#else
	tmpAddr = summary->address;
	tmpSize = summary->size;
#endif
	if (kPrintKextsUnslide & flags) {
		tmpAddr = ml_static_unslide(tmpAddr);
	}
	(*printf_func)("%s%s(%s)[%s]@0x%llx->0x%llx\n",
	    (kPrintKextsTerse & flags) ? "" : "         ",
	    summary->name, version, uuid,
	    tmpAddr, tmpAddr + tmpSize - 1);

	if (kPrintKextsTerse & flags) {
		return;
	}

	/* print dependency info */
	for (kmod_ref = (kmod_reference_t *) summary->reference_list;
	    kmod_ref;
	    kmod_ref = kmod_ref->next) {
		kmod_info_t * rinfo;

		if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)kmod_ref)) == 0) {
			(*printf_func)("            kmod dependency scan stopped "
			    "due to missing dependency page: %p\n",
			    (kPrintKextsUnslide & flags) ? (void *)ml_static_unslide((vm_offset_t)kmod_ref) : kmod_ref);
			break;
		}
		rinfo = kmod_ref->info;

		if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)rinfo)) == 0) {
			(*printf_func)("            kmod dependency scan stopped "
			    "due to missing kmod page: %p\n",
			    (kPrintKextsUnslide & flags) ? (void *)ml_static_unslide((vm_offset_t)rinfo) : rinfo);
			break;
		}

		if (!rinfo->address) {
			continue;         // skip fake entries for built-ins
		}

		dependencySummary = findSummary(rinfo->id);
		uuid[0] = 0x00;
		tmpAddr = rinfo->address;
		tmpSize = rinfo->size;
		if (dependencySummary) {
			(void) uuid_unparse(dependencySummary->uuid, uuid);
#if defined(__arm__) || defined(__arm64__)
			tmpAddr = dependencySummary->text_exec_address;
			tmpSize = dependencySummary->text_exec_size;
#endif
		}

		if (kPrintKextsUnslide & flags) {
			tmpAddr = ml_static_unslide(tmpAddr);
		}
		(*printf_func)("            dependency: %s(%s)[%s]@%p->%p\n",
		    rinfo->name, rinfo->version, uuid, tmpAddr, tmpAddr + tmpSize - 1);
	}
	return;
}


#if !defined(__arm__) && !defined(__arm64__)
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
	size_t substring_length = strnlen(substring, KMOD_MAX_NAME - 1);

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
#endif /* !defined(__arm__) && !defined(__arm64__) */

/*******************************************************************************
* assemble_identifier_and_version() adds to a string buffer a compacted
* bundle identifier followed by a version string.
*******************************************************************************/

/* identPlusVers must be at least 2*KMOD_MAX_NAME in length.
 */
static size_t assemble_identifier_and_version(
	kmod_info_t * kmod_info,
	char        * identPlusVers,
	size_t        bufSize);

static size_t
assemble_identifier_and_version(
	kmod_info_t * kmod_info,
	char        * identPlusVers,
	size_t        bufSize)
{
	size_t result = 0;

#if defined(__arm__) || defined(__arm64__)
	result = strlcpy(identPlusVers, kmod_info->name, KMOD_MAX_NAME);
#else
	compactIdentifier(kmod_info->name, identPlusVers, NULL);
	result = strnlen(identPlusVers, KMOD_MAX_NAME - 1);
#endif
	identPlusVers[result++] = '\t';         // increment for real char
	identPlusVers[result] = '\0';         // don't increment for nul char
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
		size_t        identPlusVersLength;
		size_t        tempLen;
		char          identPlusVers[2 * KMOD_MAX_NAME];

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
	newlist = (char *)kheap_alloc_tag(KHEAP_DATA_BUFFERS, newlist_size,
	    Z_WAITOK, VM_KERN_MEMORY_OSKEXT);

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
		kheap_free(KHEAP_DATA_BUFFERS, loaded_kext_paniclist,
		    loaded_kext_paniclist_size);
	}
	loaded_kext_paniclist = newlist;
	newlist = NULL;
	loaded_kext_paniclist_size = newlist_size;

finish:
	if (newlist) {
		kheap_free(KHEAP_TEMP, newlist, newlist_size);
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
		return;         // do not goto finish here b/c of lock
	}

	len = assemble_identifier_and_version( kmod_info,
	    (isLoading) ? last_loaded_str_buf : last_unloaded_str_buf,
	    (isLoading) ? sizeof(last_loaded_str_buf) : sizeof(last_unloaded_str_buf));
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
		printf_func("last started kext at %llu: %.*s (addr %p, size %lu)\n",
		    AbsoluteTime_to_scalar(&last_loaded_timestamp),
		    last_loaded_strlen, last_loaded_str_buf,
		    last_loaded_address, last_loaded_size);
	}

	if (last_unloaded_strlen) {
		printf_func("last stopped kext at %llu: %.*s (addr %p, size %lu)\n",
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

	if (!maxKexts) {
		goto finish;
	}
	if (maxKexts < kOSKextTypicalLoadCount) {
		maxKexts = kOSKextTypicalLoadCount;
	}

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
		if (result != KERN_SUCCESS) {
			goto finish;
		}
		summaryHeader = summaryHeaderAlloc;
		summarySize = size;
	} else {
		summaryHeader = gLoadedKextSummaries;
		summarySize = sLoadedKextSummariesAllocSize;

		start = (vm_map_offset_t) summaryHeader;
		end = start + summarySize;
		result = vm_map_protect(kernel_map,
		    start,
		    end,
		    VM_PROT_DEFAULT,
		    FALSE);
		if (result != KERN_SUCCESS) {
			goto finish;
		}
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
		for (idx = 0; idx < accountingListCount; idx++) {
			if (activeAccount.address < accountingList[idx].address) {
				break;
			}
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
	if (result != KERN_SUCCESS) {
		goto finish;
	}

	gLoadedKextSummaries = summaryHeader;
	gLoadedKextSummariesTimestamp = mach_absolute_time();
	sLoadedKextSummariesAllocSize = summarySize;
	summaryHeaderAlloc = NULL;

	/* Call the magic breakpoint function through a static function pointer so
	 * the compiler can't optimize the function away.
	 */
	if (sLoadedKextSummariesUpdated) {
		(*sLoadedKextSummariesUpdated)();
	}

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
	OSSharedPtr<OSData> uuid;

	strlcpy(summary->name, getIdentifierCString(),
	    sizeof(summary->name));

	uuid = copyUUID();
	if (uuid) {
		memcpy(summary->uuid, uuid->getBytesNoCopy(), sizeof(summary->uuid));
	}

	if (flags.builtin) {
//      this value will stop lldb from parsing the mach-o header
//      summary->address = UINT64_MAX;
//      summary->size = 0;
		summary->address = kmod_info->address;
		summary->size = kmod_info->size;
	} else {
		summary->address = kmod_info->address;
		summary->size = kmod_info->size;
	}
	summary->version = getVersion();
	summary->loadTag = kmod_info->id;
	summary->flags = 0;
	summary->reference_list = (uint64_t) kmod_info->reference_list;

	summary->text_exec_address = (uint64_t) getsegdatafromheader((kernel_mach_header_t *)summary->address, "__TEXT_EXEC", &summary->text_exec_size);
	if (summary->text_exec_address == 0) {
		// Fallback to __TEXT
		summary->text_exec_address = (uint64_t) getsegdatafromheader((kernel_mach_header_t *)summary->address, "__TEXT", &summary->text_exec_size);
	}
	return;
}

/*********************************************************************
*********************************************************************/

void
OSKext::updateActiveAccount(OSKextActiveAccount *accountp)
{
	kernel_mach_header_t     *hdr = NULL;
	kernel_segment_command_t *seg = NULL;

	bzero(accountp, sizeof(*accountp));

	hdr = (kernel_mach_header_t *)kmod_info->address;
	if (getcommandfromheader(hdr, LC_SEGMENT_SPLIT_INFO) || isInFileset()) {
		/*
		 * If this kext supports split segments (or is in a new
		 * MH_FILESET kext collection), use the first
		 * executable segment as the range for instructions
		 * (and thus for backtracing.
		 */
		for (seg = firstsegfromheader(hdr); seg != NULL; seg = nextsegfromheader(hdr, seg)) {
			if (seg->initprot & VM_PROT_EXECUTE) {
				break;
			}
		}
	}
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

bool
OSKext::isDriverKit(void)
{
	OSString *bundleType;

	if (infoDict) {
		bundleType = OSDynamicCast(OSString, infoDict->getObject(kCFBundlePackageTypeKey));
		if (bundleType && bundleType->isEqualTo(kOSKextBundlePackageTypeDriverKit)) {
			return TRUE;
		}
	}
	return FALSE;
}

bool
OSKext::isInFileset(void)
{
	if (!kmod_info) {
		goto check_prelinked;
	}

	if (kmod_info->address && kernel_mach_header_is_in_fileset((kernel_mach_header_t *)kmod_info->address)) {
		return true;
	}

check_prelinked:
	if (isPrelinked()) {
		/*
		 * If we haven't setup kmod_info yet, but we know
		 * we're loading a prelinked kext in an MH_FILESET KC,
		 * then return true
		 */
		kc_format_t kc_format;
		if (PE_get_primary_kc_format(&kc_format) && kc_format == KCFormatFileset) {
			return true;
		}
	}
	return false;
}

bool
OSKextSavedMutableSegment::initWithSegment(kernel_segment_command_t *seg)
{
	kern_return_t result;
	if (!super::init()) {
		return false;
	}
	if (seg == nullptr) {
		return false;
	}
	result = kmem_alloc_pageable(kernel_map, (vm_offset_t *)&data, seg->vmsize, VM_KERN_MEMORY_KEXT);
	if (result != KERN_SUCCESS) {
		return false;
	}
	memcpy((void *)data, (const void *)seg->vmaddr, seg->vmsize);
	savedSegment = seg;
	vmsize = seg->vmsize;
	vmaddr = seg->vmaddr;
	return true;
}

OSSharedPtr<OSKextSavedMutableSegment>
OSKextSavedMutableSegment::withSegment(kernel_segment_command_t *seg)
{
	OSSharedPtr<OSKextSavedMutableSegment> me = OSMakeShared<OSKextSavedMutableSegment>();
	if (me && !me->initWithSegment(seg)) {
		return nullptr;
	}
	return me;
}

void
OSKextSavedMutableSegment::free(void)
{
	if (data) {
		kmem_free(kernel_map, (vm_offset_t)data, vmsize);
	}
}

vm_offset_t
OSKextSavedMutableSegment::getVMAddr() const
{
	return vmaddr;
}

vm_offset_t
OSKextSavedMutableSegment::getVMSize() const
{
	return vmsize;
}

OSReturn
OSKextSavedMutableSegment::restoreContents(kernel_segment_command_t *seg)
{
	if (seg != savedSegment) {
		return kOSKextReturnInvalidArgument;
	}
	if (seg->vmaddr != vmaddr || seg->vmsize != vmsize) {
		return kOSKextReturnInvalidArgument;
	}
	memcpy((void *)seg->vmaddr, data, vmsize);
	return kOSReturnSuccess;
}

extern "C" const vm_allocation_site_t *
OSKextGetAllocationSiteForCaller(uintptr_t address)
{
	OSKextActiveAccount *  active;
	vm_allocation_site_t * site;
	vm_allocation_site_t * releasesite;

	uint32_t baseIdx;
	uint32_t lim;
#if  __has_feature(ptrauth_calls)
	address = (uintptr_t)VM_KERNEL_STRIP_PTR(address);
#endif /*  __has_feature(ptrauth_calls) */

	IOSimpleLockLock(sKextAccountsLock);
	site = releasesite = NULL;

	// bsearch sKextAccounts list
	for (baseIdx = 0, lim = sKextAccountsCount; lim; lim >>= 1) {
		active = &sKextAccounts[baseIdx + (lim >> 1)];
		if ((address >= active->address) && (address < active->address_end)) {
			site = &active->account->site;
			if (!site->tag) {
				vm_tag_alloc_locked(site, &releasesite);
			}
			break;
		} else if (address > active->address) {
			// move right
			baseIdx += (lim >> 1) + 1;
			lim--;
		}
		// else move left
	}
	IOSimpleLockUnlock(sKextAccountsLock);
	if (releasesite) {
		kern_allocation_name_release(releasesite);
	}

	return site;
}

extern "C" uint32_t
OSKextGetKmodIDForSite(const vm_allocation_site_t * site, char * name, vm_size_t namelen)
{
	OSKextAccount * account = (typeof(account))site;
	const char    * kname;

	if (name) {
		if (account->kext) {
			kname = account->kext->getIdentifierCString();
		} else {
			kname = "<>";
		}
		strlcpy(name, kname, namelen);
	}

	return account->loadTag;
}

extern "C" void
OSKextFreeSite(vm_allocation_site_t * site)
{
	OSKextAccount * freeAccount = (typeof(freeAccount))site;
	IODelete(freeAccount, OSKextAccount, 1);
}

/*********************************************************************
*********************************************************************/

#if CONFIG_IMAGEBOOT
int
OSKextGetUUIDForName(const char *name, uuid_t uuid)
{
	OSSharedPtr<OSKext> kext = OSKext::lookupKextWithIdentifier(name);
	if (!kext) {
		return 1;
	}

	OSSharedPtr<OSData> uuid_data = kext->copyUUID();
	if (uuid_data) {
		memcpy(uuid, uuid_data->getBytesNoCopy(), sizeof(uuid_t));
		return 0;
	}

	return 1;
}
#endif

static int
sysctl_willuserspacereboot
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value = 0, old_value = 0, changed = 0;
	int error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);
	if (error) {
		return error;
	}
	if (changed) {
		OSKext::willUserspaceReboot();
	}
	return 0;
}

static SYSCTL_PROC(_kern, OID_AUTO, willuserspacereboot,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    NULL, 0, sysctl_willuserspacereboot, "I", "");
