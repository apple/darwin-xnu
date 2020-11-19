/*
 * Copyright (c) 2008-2019 Apple Inc. All rights reserved.
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

#ifndef _LIBKERN_OSKEXT_H
#define _LIBKERN_OSKEXT_H

extern "C" {
#include <kern/thread_call.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/kxld.h>
#include <mach/kmod.h>

#ifdef XNU_KERNEL_PRIVATE
#include <kern/thread_call.h>
#endif /* XNU_KERNEL_PRIVATE */
}


#include <libkern/OSKextLib.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSContainers.h>

#include <libkern/c++/OSPtr.h>
#include <IOKit/IOLocks.h>

/*********************************************************************
* C functions used for callbacks.
*********************************************************************/
#ifdef XNU_KERNEL_PRIVATE
extern "C" {
void osdata_kmem_free(void * ptr, unsigned int length);
void osdata_phys_free(void * ptr, unsigned int length);
void osdata_vm_deallocate(void * ptr, unsigned int length);
void osdata_kext_free(void * ptr, unsigned int length);
void kxld_log_callback(
	KXLDLogSubsystem    subsystem,
	KXLDLogLevel        level,
	const char        * format,
	va_list             argList,
	void              * user_data);
};
#endif /* XNU_KERNEL_PRIVATE */

/*********************************************************************
* C Function Prototypes for Friend Declarations.
*********************************************************************/
class OSKext;

extern "C" {
void OSKextLog(
	OSKext         * aKext,
	OSKextLogSpec    msgLogSpec,
	const char     * format, ...)
__attribute__((format(printf, 3, 4)));

void OSKextVLog(
	OSKext         * aKext,
	OSKextLogSpec    msgLogSpec,
	const char     * format,
	va_list          srcArgList);

#ifdef XNU_KERNEL_PRIVATE
void OSKextRemoveKextBootstrap(void);

kern_return_t OSRuntimeInitializeCPP(
	OSKext * kext);
kern_return_t OSRuntimeFinalizeCPP(
	OSKext * kext);
void OSRuntimeUnloadCPPForSegment(
	kernel_segment_command_t * segment);
void
OSRuntimeSignStructors(
	kernel_mach_header_t * header);
void
OSRuntimeSignStructorsInFileset(
	kernel_mach_header_t * fileset_header);

kern_return_t is_io_catalog_send_data(
	mach_port_t              masterPort,
	uint32_t                 flag,
	io_buf_ptr_t             inData,
	mach_msg_type_number_t   inDataCount,
	kern_return_t          * result);

void kmod_dump_log(vm_offset_t*, unsigned int, boolean_t);
void *OSKextKextForAddress(const void *addr);

#endif /* XNU_KERNEL_PRIVATE */
};

/********************************************************************/
#if PRAGMA_MARK
#pragma mark -
#endif

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

struct OSKextGrabPgoStruct {
	bool metadata;
	uint64_t *pSize;
	char *pBuffer;
	uint64_t bufferSize;
	int err;
	struct list_head list_head;
};

#ifndef container_of
#define container_of(ptr, type, member) ((type*)(((uintptr_t)ptr) - offsetof(type, member)))
#endif
/********************************************************************/

#if XNU_KERNEL_PRIVATE

struct OSKextAccount {
	vm_allocation_site_t site;
	uint32_t             loadTag;
	OSKext             * kext;
};

struct OSKextActiveAccount {
	uintptr_t       address;
	uintptr_t       address_end;
	OSKextAccount * account;
};
typedef struct OSKextActiveAccount OSKextActiveAccount;

class OSKextSavedMutableSegment : public OSObject {
	OSDeclareDefaultStructors(OSKextSavedMutableSegment);
public:
	static OSPtr<OSKextSavedMutableSegment> withSegment(kernel_segment_command_t *seg);
	OSReturn restoreContents(kernel_segment_command_t *seg);
	vm_offset_t getVMAddr() const;
	vm_size_t getVMSize() const;
	virtual void free(void) APPLE_KEXT_OVERRIDE;
private:
	bool initWithSegment(kernel_segment_command_t *seg);
	kernel_segment_command_t *savedSegment;
	vm_offset_t vmaddr;
	vm_size_t   vmsize;
	void      * data;
};

#endif /* XNU_KERNEL_PRIVATE */

/*
 * @class OSKext
 */
/********************************************************************/
class OSKext : public OSObject
{
	OSDeclareDefaultStructors(OSKext);

#if PRAGMA_MARK
/**************************************/
#pragma mark Friend Declarations
/**************************************/
#endif
	friend class IOCatalogue;
	friend class KLDBootstrap;
	friend class OSMetaClass;

	friend int OSKextGrabPgoData(uuid_t uuid,
	    uint64_t *pSize,
	    char *pBuffer,
	    uint64_t bufferSize,
	    int wait_for_unload,
	    int metadata);

#ifdef XNU_KERNEL_PRIVATE
	friend void OSKextVLog(
		OSKext         * aKext,
		OSKextLogSpec    msgLogSpec,
		const char     * format,
		va_list          srcArgList);

	friend void OSKextRemoveKextBootstrap(void);
	friend OSReturn OSKextUnloadKextWithLoadTag(uint32_t);

	friend kern_return_t kext_request(
		host_priv_t                             hostPriv,
		/* in only */ uint32_t                 clientLogSpec,
		/* in only */ vm_offset_t              requestIn,
		/* in only */ mach_msg_type_number_t   requestLengthIn,
		/* out only */ vm_offset_t            * responseOut,
		/* out only */ mach_msg_type_number_t * responseLengthOut,
		/* out only */ vm_offset_t            * logDataOut,
		/* out only */ mach_msg_type_number_t * logDataLengthOut,
		/* out only */ kern_return_t          * op_result);

	friend kxld_addr_t kern_allocate(
		u_long              size,
		KXLDAllocateFlags * flags,
		void              * user_data);

	friend void kxld_log_shim(
		KXLDLogSubsystem    subsystem,
		KXLDLogLevel        level,
		const char        * format,
		va_list             argList,
		void              * user_data);

	friend void _OSKextConsiderUnloads(
		__unused thread_call_param_t p0,
		__unused thread_call_param_t p1);

	friend kern_return_t OSRuntimeInitializeCPP(
		OSKext * kext);
	friend kern_return_t OSRuntimeFinalizeCPP(
		OSKext * kext);
	friend void OSRuntimeUnloadCPPForSegment(
		kernel_segment_command_t * segment);

	friend kern_return_t is_io_catalog_send_data(
		mach_port_t              masterPort,
		uint32_t                 flag,
		io_buf_ptr_t             inData,
		mach_msg_type_number_t   inDataCount,
		kern_return_t          * result);

	friend void kmod_panic_dump(vm_offset_t*, unsigned int);
	friend void kmod_dump_log(vm_offset_t*, unsigned int, boolean_t);
	friend void kext_dump_panic_lists(int (*printf_func)(const char * fmt, ...));
	friend void *OSKextKextForAddress(const void *addr);

#endif /* XNU_KERNEL_PRIVATE */

private:

/*************************
* Instance variables
*************************/
	OSPtr<OSDictionary>  infoDict;

	OSPtr<const OSSymbol>    bundleID;
	OSPtr<OSString>    path;           // not necessarily correct :-/
	OSPtr<OSString>    executableRelPath;// relative to bundle
	OSPtr<OSString>    userExecutableRelPath;// relative to bundle

	OSKextVersion    version;        // parsed
	OSKextVersion    compatibleVersion;// parsed

/* These fields are required for tracking loaded kexts and
 * will always have values for a loaded kext.
 */
	OSKextLoadTag    loadTag;        // 'id' from old kmod_info;
	                                 // kOSKextInvalidLoadTag invalid
	kmod_info_t    * kmod_info;      // address into linkedExec./alloced for interface

	OSPtr<OSArray>     dependencies;   // kernel resource does not have any;
	// links directly to kernel

/* Only real kexts have these; interface kexts do not.
 */
	OSPtr<OSData>       linkedExecutable;
	OSPtr<OSSet>        metaClasses;       // for C++/OSMetaClass kexts

/* Only interface kexts have these; non-interface kexts can get at them
 * in the linked Executable.
 */
	OSPtr<OSData>       interfaceUUID;
	OSPtr<OSData>       driverKitUUID;

	struct {
		unsigned int loggingEnabled:1;

		unsigned int hasAllDependencies:1;
		unsigned int hasBleedthrough:1;

		unsigned int interface:1;
		unsigned int kernelComponent:1;
		unsigned int prelinked:1;
		unsigned int builtin:1;
		unsigned int loaded:1;
		unsigned int dtraceInitialized:1;
		unsigned int starting:1;
		unsigned int started:1;
		unsigned int stopping:1;
		unsigned int unloading:1;
		unsigned int resetSegmentsFromVnode:1;

		unsigned int requireExplicitLoad:1;
		unsigned int autounloadEnabled:1;
		unsigned int delayAutounload:1; // for development

		unsigned int CPPInitialized:1;
		unsigned int jettisonLinkeditSeg:1;
		unsigned int resetSegmentsFromImmutableCopy:1;
	} flags;

	uint32_t matchingRefCount;
	kc_kind_t kc_type;

	struct list_head pendingPgoHead;
	uuid_t instance_uuid;
	OSKextAccount * account;
	uint32_t builtinKmodIdx;
	OSPtr<OSArray> savedMutableSegments;

#if PRAGMA_MARK
/**************************************/
#pragma mark Private Functions
/**************************************/
#endif

#ifdef XNU_KERNEL_PRIVATE
/* Startup/shutdown phases.
 */
public:
	static void           initialize(void);
	static OSPtr<OSDictionary> copyKexts(void);
	static OSReturn       removeKextBootstrap(void);
	static void           willShutdown(void);// called by IOPMrootDomain on shutdown
	static void           willUserspaceReboot(void);
	static void           resetAfterUserspaceReboot(void);
	static  void reportOSMetaClassInstances(
		const char     * kextIdentifier,
		OSKextLogSpec    msgLogSpec);
	static void OSKextLogDriverKitInfoLoad(OSKext *kext);
#endif /* XNU_KERNEL_PRIVATE */

private:
/* Called by power management at sleep/shutdown.
 */
	static bool setLoadEnabled(bool flag);
	static bool setUnloadEnabled(bool flag);
	static bool setAutounloadsEnabled(bool flag);
	static bool setKernelRequestsEnabled(bool flag);

// all getters subject to race condition, caller beware
	static bool getLoadEnabled(void);
	static bool getUnloadEnabled(void);
	static bool getAutounloadEnabled(void);
	static bool getKernelRequestsEnabled(void);

/* Instance life cycle.
 */
	static OSPtr<OSKext> withBooterData(
		OSString * deviceTreeName,
		OSData   * booterData);
	virtual bool initWithBooterData(
		OSString * deviceTreeName,
		OSData   * booterData);

	static OSPtr<OSKext> withPrelinkedInfoDict(
		OSDictionary * infoDict,
		bool doCoalesedSlides, kc_kind_t type);
	virtual bool initWithPrelinkedInfoDict(
		OSDictionary * infoDict,
		bool doCoalesedSlides, kc_kind_t type);

	static OSSharedPtr<OSKext> withCodelessInfo(
		OSDictionary * infoDict);
	virtual bool initWithCodelessInfo(
		OSDictionary * infoDict);

	static void setAllVMAttributes(void);

	virtual bool setInfoDictionaryAndPath(
		OSDictionary * aDictionary,
		OSString     * aPath);
	virtual bool setExecutable(
		OSData       * anExecutable,
		OSData       * externalData        = NULL,
		bool           externalDataIsMkext = false);
	virtual bool registerIdentifier(void);

	virtual void free(void) APPLE_KEXT_OVERRIDE;

	static OSReturn removeKext(
		OSKext * aKext,
		bool     terminateServicesAndRemovePersonalitiesFlag = false);

	virtual bool isInExcludeList(void);
	virtual bool isLoadable(void);

/* Mkexts.
 */
#if CONFIG_KXLD
	static OSPtr<OSKext> withMkext2Info(
		OSDictionary * anInfoDict,
		OSData       * mkextData);
	virtual bool initWithMkext2Info(
		OSDictionary * anInfoDict,
		OSData       * mkextData);

	static OSReturn readMkextArchive(
		OSData   * mkextData,
		uint32_t * checksumPtr = NULL);
	static OSReturn readMkext2Archive(
		OSData * mkextData,
		OSDictionary ** mkextPlistOut,
		uint32_t * checksumPtr = NULL);

	static OSReturn readMkext2Archive(
		OSData * mkextData,
		OSSharedPtr<OSDictionary> &mkextPlistOut,
		uint32_t * checksumPtr = NULL);

	virtual OSPtr<OSData> createMkext2FileEntry(
		OSData * mkextData,
		OSNumber * offsetNum,
		const char * entryName);
	virtual OSPtr<OSData> extractMkext2FileData(
		UInt8      * data,
		const char * name,
		uint32_t     compressedSize,
		uint32_t     fullSize);
#endif // CONFIG_KXLD

/* Dependencies.
 */
	virtual bool resolveDependencies(
		OSArray * loopStack = NULL); // priv/prot
	virtual bool addBleedthroughDependencies(OSArray * anArray);
	virtual bool flushDependencies(bool forceFlag = false); // priv/prot
	virtual uint32_t  getNumDependencies(void);
	virtual OSArray * getDependencies(void);

/* User-space requests (load/generic).
 */
	static OSReturn loadFromMkext(
		OSKextLogSpec   clientLogSpec,
		char          * mkextBuffer,
		uint32_t        mkextBufferLength,
		char         ** logInfoOut,
		uint32_t      * logInfoLengthOut);
	static OSReturn handleRequest(
		host_priv_t     hostPriv,
		OSKextLogSpec   clientLogSpec,
		char          * requestBuffer,
		uint32_t        requestLength,
		char         ** responseOut,
		uint32_t      * responseLengthOut,
		char         ** logInfoOut,
		uint32_t      * logInfoLengthOut);
	static OSReturn loadCodelessKext(
		OSString      * kextIdentifier,
		OSDictionary  * requestDict);
	static OSReturn serializeLogInfo(
		OSArray   * logInfoArray,
		char     ** logInfoOut,
		uint32_t  * logInfoLengthOut);

/* Loading.
 */
	static bool addKextsFromKextCollection(kernel_mach_header_t *mh,
	    OSDictionary *infoDict, const char *text_seg_name,
	    OSData **kcUUID, kc_kind_t type);

	static bool addKextsFromKextCollection(kernel_mach_header_t *mh,
	    OSDictionary *infoDict, const char *text_seg_name,
	    OSSharedPtr<OSData> &kcUUID, kc_kind_t type);

	static bool registerDeferredKextCollection(kernel_mach_header_t *mh,
	    OSSharedPtr<OSObject> &parsedXML, kc_kind_t type);
	static OSSharedPtr<OSObject> consumeDeferredKextCollection(kc_kind_t type);

	virtual OSReturn load(
		OSKextExcludeLevel   startOpt         = kOSKextExcludeNone,
		OSKextExcludeLevel   startMatchingOpt = kOSKextExcludeAll,
		OSArray            * personalityNames = NULL);// priv/prot
	virtual OSReturn unload(void);
	virtual OSReturn queueKextNotification(
		const char * notificationName,
		OSString   * kextIdentifier);

	static void recordIdentifierRequest(
		OSString * kextIdentifier);

	virtual OSReturn slidePrelinkedExecutable(bool doCoalesedSlides);
	virtual OSReturn loadExecutable(void);
	virtual void     jettisonLinkeditSegment(void);
	virtual void     jettisonDATASegmentPadding(void);
	static  void     considerDestroyingLinkContext(void);
	virtual OSData * getExecutable(void);
	virtual void     setLinkedExecutable(OSData * anExecutable);

#if CONFIG_DTRACE
	friend  void OSKextRegisterKextsWithDTrace(void);
	static  void registerKextsWithDTrace(void);
	virtual void registerWithDTrace(void);
	virtual void unregisterWithDTrace(void);
#endif /* CONFIG_DTRACE */

	virtual OSReturn start(bool startDependenciesFlag = true);
	virtual OSReturn stop(void);
	virtual OSReturn setVMAttributes(bool protect, bool wire);
	virtual boolean_t segmentShouldBeWired(kernel_segment_command_t *seg);
	virtual OSReturn validateKextMapping(bool startFlag);
	virtual boolean_t verifySegmentMapping(kernel_segment_command_t *seg);

	static OSPtr<OSArray> copyAllKextPersonalities(
		bool filterSafeBootFlag = false);

	static  void  setPrelinkedPersonalities(OSArray * personalitiesArray);

	static  void  sendAllKextPersonalitiesToCatalog(
		bool startMatching = false);
	virtual OSReturn  sendPersonalitiesToCatalog(
		bool      startMatching    = false,
		OSArray * personalityNames = NULL);

	static bool canUnloadKextWithIdentifier(
		OSString * kextIdentifier,
		bool       checkClassesFlag = true);

	static OSReturn autounloadKext(OSKext * aKext);

/* Sync with user space.
 */
	static OSReturn pingIOKitDaemon(void);

/* Getting info about loaded kexts (kextstat).
 */
	static  OSPtr<OSDictionary> copyLoadedKextInfo(
		OSArray * kextIdentifiers = NULL,
		OSArray * keys = NULL);
	static  OSPtr<OSDictionary> copyLoadedKextInfoByUUID(
		OSArray * kextIdentifiers = NULL,
		OSArray * keys = NULL);
	static  OSPtr<OSDictionary> copyKextCollectionInfo(
		OSDictionary *requestDict,
		OSArray  *infoKeys = NULL);
	static OSPtr<OSData> copyKextUUIDForAddress(OSNumber *address = NULL);
	virtual OSPtr<OSDictionary> copyInfo(OSArray * keys = NULL);

/* Logging to user space.
 */
	static OSKextLogSpec setUserSpaceLogFilter(
		OSKextLogSpec  userLogSpec,
		bool           captureFlag = false);
	static OSPtr<OSArray> clearUserSpaceLogFilter(void);
	static OSKextLogSpec getUserSpaceLogFilter(void);

/* OSMetaClasses defined by kext.
 */
	virtual OSReturn addClass(
		OSMetaClass * aClass,
		uint32_t     numClasses);
	virtual OSReturn removeClass(
		OSMetaClass * aClass);
	virtual bool    hasOSMetaClassInstances(void);
	virtual OSSet * getMetaClasses(void);

	virtual void reportOSMetaClassInstances(
		OSKextLogSpec msgLogSpec);

/* Resource requests and other callback stuff.
 */
	static OSReturn loadFileSetKexts(OSDictionary * requestDict);

	static OSReturn loadKCFileSet(const char *filepath, kc_kind_t type);

#if defined(__x86_64__) || defined(__i386__)
	static OSReturn mapKCFileSet(
		void                 *control,
		vm_size_t            fsize,
		kernel_mach_header_t **mh,
		off_t                file_offset,
		uintptr_t            *slide,
		bool                 pageable,
		void                 *map_entry_buffer);
	static OSReturn protectKCFileSet(
		kernel_mach_header_t *mh,
		kc_kind_t            type);
	static OSReturn mapKCTextSegment(
		void                 *control,
		kernel_mach_header_t **mhp,
		off_t                file_offset,
		uintptr_t            *slide,
		void                 *map_entry_list);
	static void freeKCFileSetcontrol(void);
	OSReturn resetKCFileSetSegments(void);
	static void jettisonFileSetLinkeditSegment(kernel_mach_header_t *mh);
#endif //(__x86_64__) || defined(__i386__)

	static OSReturn validateKCFileSetUUID(
		OSDictionary         *infoDict,
		kc_kind_t            type);

	static OSReturn validateKCUUIDfromPrelinkInfo(
		uuid_t               *loaded_kcuuid,
		kc_kind_t             type,
		OSDictionary         *infoDict,
		const char           *uuid_key);

	static OSReturn dispatchResource(OSDictionary * requestDict);

	static OSReturn setMissingAuxKCBundles(OSDictionary * requestDict);

	static OSReturn setAuxKCBundleAvailable(OSString *kextIdentifier,
	    OSDictionary *requestDict);

	static OSReturn dequeueCallbackForRequestTag(
		OSKextRequestTag    requestTag,
		LIBKERN_RETURNS_RETAINED OSDictionary     ** callbackRecordOut);
	static OSReturn dequeueCallbackForRequestTag(
		OSNumber     *    requestTagNum,
		LIBKERN_RETURNS_RETAINED OSDictionary ** callbackRecordOut);

	static OSReturn dequeueCallbackForRequestTag(
		OSKextRequestTag    requestTag,
		OSSharedPtr<OSDictionary> &callbackRecordOut);
	static OSReturn dequeueCallbackForRequestTag(
		OSNumber     *    requestTagNum,
		OSSharedPtr<OSDictionary> &callbackRecordOut);

	static void invokeRequestCallback(
		OSDictionary * callbackRecord,
		OSReturn         requestResult);
	virtual void invokeOrCancelRequestCallbacks(
		OSReturn callbackResult,
		bool     invokeFlag = true);
	virtual uint32_t countRequestCallbacks(void);
	OSReturn resetMutableSegments(void);

/* panic() support.
 */
public:
	enum {
		kPrintKextsLock    = 0x01,
		kPrintKextsUnslide = 0x02,
		kPrintKextsTerse   = 0x04
	};
	static void printKextsInBacktrace(
		vm_offset_t   * addr,
		unsigned int    cnt,
		int          (* printf_func)(const char *fmt, ...),
		uint32_t        flags);
	bool isDriverKit(void);
	bool isInFileset(void);
private:
	static OSKextLoadedKextSummary *summaryForAddress(const uintptr_t addr);
	static void *kextForAddress(const void *addr);
	static boolean_t summaryIsInBacktrace(
		OSKextLoadedKextSummary * summary,
		vm_offset_t             * addr,
		unsigned int              cnt);
	static void printSummary(
		OSKextLoadedKextSummary * summary,
		int                    (* printf_func)(const char *fmt, ...),
		uint32_t                  flags);

	static int saveLoadedKextPanicListTyped(
		const char * prefix,
		int          invertFlag,
		int          libsFlag,
		char       * paniclist,
		uint32_t     list_size);
	static void saveLoadedKextPanicList(void);
	void savePanicString(bool isLoading);
	static void printKextPanicLists(int (*printf_func)(const char *fmt, ...));

/* Kext summary support.
 */
	static void updateLoadedKextSummaries(void);
	void updateLoadedKextSummary(OSKextLoadedKextSummary *summary);
	void updateActiveAccount(OSKextActiveAccount *accountp);

#ifdef XNU_KERNEL_PRIVATE
public:
#endif /* XNU_KERNEL_PRIVATE */

/* C++ Initialization.
 */
	virtual void               setCPPInitialized(bool initialized = true);

#if PRAGMA_MARK
/**************************************/
#pragma mark Public Functions
/**************************************/
#endif
public:
	// caller must release
	static OSPtr<OSKext> lookupKextWithIdentifier(const char * kextIdentifier);
	static OSPtr<OSKext> lookupKextWithIdentifier(OSString * kextIdentifier);
	static OSPtr<OSKext> lookupKextWithLoadTag(OSKextLoadTag aTag);
	static OSPtr<OSKext> lookupKextWithAddress(vm_address_t address);
	static OSPtr<OSKext> lookupKextWithUUID(uuid_t uuid);

	kernel_section_t *lookupSection(const char *segname, const char*secname);

	static bool isKextWithIdentifierLoaded(const char * kextIdentifier);

	static OSReturn loadKextWithIdentifier(
		const char       * kextIdentifier,
		Boolean            allowDeferFlag      = true,
		Boolean            delayAutounloadFlag = false,
		OSKextExcludeLevel startOpt            = kOSKextExcludeNone,
		OSKextExcludeLevel startMatchingOpt    = kOSKextExcludeAll,
		OSArray          * personalityNames    = NULL);

	static OSReturn loadKextWithIdentifier(
		OSString         * kextIdentifier,
		LIBKERN_RETURNS_RETAINED_ON_ZERO OSObject        ** kextRef,
		Boolean            allowDeferFlag      = true,
		Boolean            delayAutounloadFlag = false,
		OSKextExcludeLevel startOpt            = kOSKextExcludeNone,
		OSKextExcludeLevel startMatchingOpt    = kOSKextExcludeAll,
		OSArray          * personalityNames    = NULL);

	static OSReturn loadKextWithIdentifier(
		OSString         *    kextIdentifier,
		OSSharedPtr<OSObject> &kextRef,
		Boolean                allowDeferFlag      = true,
		Boolean                delayAutounloadFlag = false,
		OSKextExcludeLevel     startOpt            = kOSKextExcludeNone,
		OSKextExcludeLevel     startMatchingOpt    = kOSKextExcludeAll,
		OSArray              * personalityNames    = NULL);

	static OSReturn loadKextFromKC(OSKext *theKext, OSDictionary *requestDict);

	static void dropMatchingReferences(
		OSSet * kexts);

	bool hasDependency(const OSSymbol * depID);

	static OSReturn removeKextWithIdentifier(
		const char * kextIdentifier,
		bool         terminateServicesAndRemovePersonalitiesFlag = false);
	static OSReturn removeKextWithLoadTag(
		OSKextLoadTag loadTag,
		bool          terminateServicesAndRemovePersonalitiesFlag = false);
	static OSReturn requestDaemonLaunch(
		OSString        * kextIdentifier,
		OSString        * serverName,
		OSNumber        * serverTag,
		class IOUserServerCheckInToken ** checkInToken);

	static OSReturn requestDaemonLaunch(
		OSString        * kextIdentifier,
		OSString        * serverName,
		OSNumber        * serverTag,
		OSSharedPtr<class IOUserServerCheckInToken> &checkInToken);

	static OSReturn requestResource(
		const char                    * kextIdentifier,
		const char                    * resourceName,
		OSKextRequestResourceCallback   callback,
		void                          * context,
		OSKextRequestTag              * requestTagOut);
	static OSReturn cancelRequest(
		OSKextRequestTag    requestTag,
		void             ** contextOut);

	static void     considerUnloads(Boolean rescheduleOnlyFlag = false);
	static void     flushNonloadedKexts(Boolean flushPrelinkedKexts);
	static void     setIOKitDaemonActive(bool active = true);
	static void     setDeferredLoadSucceeded(Boolean succeeded = true);
	static void     considerRebuildOfPrelinkedKernel(void);
	static void     createExcludeListFromBooterData(
		OSDictionary * theDictionary,
		OSCollectionIterator * theIterator);
	static void     createExcludeListFromPrelinkInfo(OSArray * theInfoArray);
	static boolean_t updateExcludeList(OSDictionary * infoDict);

	static bool     pendingIOKitDaemonRequests(void);

	virtual bool    setAutounloadEnabled(bool flag);

	virtual const OSSymbol   * getIdentifier(void);
	virtual const char       * getIdentifierCString(void);
	virtual OSKextVersion      getVersion(void);
	virtual OSKextVersion      getCompatibleVersion(void);
	virtual bool               isLibrary(void);
	virtual bool               isCompatibleWithVersion(OSKextVersion aVersion);
	virtual OSObject         * getPropertyForHostArch(const char * key);

	virtual OSKextLoadTag      getLoadTag(void);
	virtual void               getSizeInfo(uint32_t *loadSize, uint32_t *wiredSize);
	virtual OSPtr<OSData>          copyUUID(void);
	OSPtr<OSData>                  copyTextUUID(void);
	OSPtr<OSData>                  copyMachoUUID(const kernel_mach_header_t * header);
	virtual OSPtr<OSArray>         copyPersonalitiesArray(void);
	static bool                copyUserExecutablePath(const OSSymbol * bundleID, char * pathResult, size_t pathSize);
	virtual void               setDriverKitUUID(OSData *uuid);
/* This removes personalities naming the kext (by CFBundleIdentifier),
 * not all personalities defined by the kext (IOPersonalityPublisher or CFBundleIdentifier).
 */
	virtual void               removePersonalitiesFromCatalog(void);

/* Converts common string-valued properties to OSSymbols for lower memory consumption.
 */
	static void uniquePersonalityProperties(OSDictionary * personalityDict);
#ifdef XNU_KERNEL_PRIVATE
	static void uniquePersonalityProperties(OSDictionary * personalityDict, bool defaultAddKernelBundleIdentifier);
#endif

	virtual bool               declaresExecutable(void); // might be missing
	virtual bool               isInterface(void);
	virtual bool               isKernel(void);
	virtual bool               isKernelComponent(void);
	virtual bool               isExecutable(void);
	virtual bool               isLoadableInSafeBoot(void);
	virtual bool               isPrelinked(void);
	virtual bool               isLoaded(void);
	virtual bool               isStarted(void);
	virtual bool               isCPPInitialized(void);

	const char *
	getKCTypeString(void)
	{
		switch (kc_type) {
		case KCKindPrimary:
			return kKCTypePrimary;
		case KCKindPageable:
			return kKCTypeSystem;
		case KCKindAuxiliary:
			return kKCTypeAuxiliary;
		case KCKindNone:
			return kKCTypeCodeless;
		default:
			return "??";
		}
	}
};

extern "C" void OSKextResetAfterUserspaceReboot(void);

#endif /* !_LIBKERN_OSKEXT_H */
