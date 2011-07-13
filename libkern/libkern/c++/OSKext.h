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
#include <IOKit/IOLocks.h>

/*********************************************************************
* C functions used for callbacks.
*********************************************************************/
#ifdef XNU_KERNEL_PRIVATE
extern "C" {
void osdata_kmem_free(void * ptr, unsigned int length);
void osdata_phys_free(void * ptr, unsigned int length);
void osdata_vm_deallocate(void * ptr, unsigned int length);
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
void IOSystemShutdownNotification(void);

kern_return_t OSRuntimeInitializeCPP(
    kmod_info_t * kmodInfo,
    void *        data);
kern_return_t OSRuntimeFinalizeCPP(
    kmod_info_t * kmodInfo,
    void        * data);

kern_return_t is_io_catalog_send_data(
    mach_port_t              masterPort,
    uint32_t                 flag,
    io_buf_ptr_t             inData,
    mach_msg_type_number_t   inDataCount,
    kern_return_t          * result);

void kmod_dump_log(vm_offset_t*, unsigned int);

#if __i386__
kern_return_t kext_get_kmod_info(
    kmod_info_array_t      * kmod_list,
    mach_msg_type_number_t * kmodCount);
#endif /* __i386__ */

#endif /* XNU_KERNEL_PRIVATE */
};

/********************************************************************/
#if PRAGMA_MARK
#pragma mark -
#endif
/*
 * @class OSKext
 */
/********************************************************************/
class OSKext : public OSObject
{
    OSDeclareDefaultStructors(OSKext)

#if PRAGMA_MARK
/**************************************/
#pragma mark Friend Declarations
/**************************************/
#endif
    friend class IOCatalogue;
    friend class KLDBootstrap;
    friend class OSMetaClass;

#ifdef XNU_KERNEL_PRIVATE
    friend void OSKextVLog(
        OSKext         * aKext,
        OSKextLogSpec    msgLogSpec,
        const char     * format,
        va_list          srcArgList);

    friend void OSKextRemoveKextBootstrap(void);
    friend void IOSystemShutdownNotification(void);
    friend OSReturn OSKextUnloadKextWithLoadTag(uint32_t);

    friend kern_return_t kext_request(
        host_priv_t                             hostPriv,
        /* in only */  uint32_t                 clientLogSpec,
        /* in only */  vm_offset_t              requestIn,
        /* in only */  mach_msg_type_number_t   requestLengthIn,
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
        kmod_info_t * kmodInfo,
        void *        data);
    friend kern_return_t OSRuntimeFinalizeCPP(
        kmod_info_t * kmodInfo,
        void        * data);

    friend kern_return_t is_io_catalog_send_data(
            mach_port_t              masterPort,
            uint32_t                 flag,
            io_buf_ptr_t             inData,
            mach_msg_type_number_t   inDataCount,
            kern_return_t          * result);

    friend void kmod_panic_dump(vm_offset_t*, unsigned int);
    friend void kmod_dump_log(vm_offset_t*, unsigned int);
    friend void kext_dump_panic_lists(int (*printf_func)(const char * fmt, ...));

#if __i386__
    friend kern_return_t kext_get_kmod_info(
        kmod_info_array_t      * kmod_list,
        mach_msg_type_number_t * kmodCount);
#endif /* __i386__ */

#endif /* XNU_KERNEL_PRIVATE */

private:

   /*************************
    * Instance variables
    *************************/
    OSDictionary   * infoDict;

    const OSSymbol * bundleID;
    OSString       * path;               // not necessarily correct :-/
    OSString       * executableRelPath;  // relative to bundle

    OSKextVersion    version;            // parsed
    OSKextVersion    compatibleVersion;  // parsed

   /* These fields are required for tracking loaded kexts and
    * will always have values for a loaded kext.
    */
    OSKextLoadTag    loadTag;            // 'id' from old kmod_info; 
                                         // kOSKextInvalidLoadTag invalid
    kmod_info_t    * kmod_info;          // address into linkedExec./alloced for interface

    OSArray        * dependencies;       // kernel resource does not have any;
                                         // links directly to kernel

   /* Only real kexts have these; interface kexts do not.
    */
    OSData         * linkedExecutable;
    OSSet          * metaClasses;           // for C++/OSMetaClass kexts
    
   /* Only interface kexts have these; non-interface kexts can get at them
    * in the linked Executable.
    */
    OSData         * interfaceUUID;

    struct {
        unsigned int loggingEnabled:1;

        unsigned int hasAllDependencies:1;
        unsigned int hasBleedthrough:1;

        unsigned int interface:1;
        unsigned int kernelComponent:1;
        unsigned int prelinked:1;
        unsigned int loaded:1;
        unsigned int dtraceInitialized:1;
        unsigned int starting:1;
        unsigned int started:1;
        unsigned int stopping:1;
        unsigned int unloading:1;

        unsigned int autounloadEnabled:1;
        unsigned int delayAutounload:1;    // for development

        unsigned int CPPInitialized:1;
    } flags;

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
    static OSDictionary * copyKexts(void);
    static OSReturn       removeKextBootstrap(void);
    static void           willShutdown(void);  // called by IOPMrootDomain on shutdown
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
    static OSKext * withBooterData(
        OSString * deviceTreeName,
        OSData   * booterData);
    virtual bool initWithBooterData(
        OSString * deviceTreeName,
        OSData   * booterData);

    static OSKext * withPrelinkedInfoDict(
        OSDictionary * infoDict);
    virtual bool initWithPrelinkedInfoDict(
        OSDictionary * infoDict);

    static OSKext * withMkext2Info(
        OSDictionary * anInfoDict,
        OSData       * mkextData);
    virtual bool initWithMkext2Info(
        OSDictionary * anInfoDict,
        OSData       * mkextData);

    virtual bool setInfoDictionaryAndPath(
        OSDictionary * aDictionary,
        OSString     * aPath);
    virtual bool setExecutable(
        OSData       * anExecutable,
        OSData       * externalData        = NULL,
        bool           externalDataIsMkext = false);
    virtual bool registerIdentifier(void);

    virtual void free(void);

    static OSReturn removeKext(
        OSKext * aKext,
        bool     terminateServicesAndRemovePersonalitiesFlag = false);

   /* Mkexts.
    */
    static OSReturn readMkextArchive(
        OSData   * mkextData,
        uint32_t * checksumPtr = NULL);
    static OSReturn readMkext2Archive(
        OSData * mkextData,
        OSDictionary ** mkextPlistOut,
        uint32_t * checksumPtr = NULL);
    virtual OSData * createMkext2FileEntry(
        OSData * mkextData,
        OSNumber * offsetNum,
        const char * entryName);
    virtual OSData * extractMkext2FileData(
        UInt8      * data,
        const char * name,
        uint32_t     compressedSize,
        uint32_t     fullSize);

    static OSReturn readMkext1Archive(
        OSData   * mkextData,
        uint32_t * checksumPtr);
    bool initWithMkext1Info(
        OSDictionary * anInfoDict,
        OSData       * executableWrapper,
        OSData       * mkextData);
    static OSData * extractMkext1Entry(
        const void * mkextFileBase,
        const void * entry);

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
    static OSReturn serializeLogInfo(
        OSArray   * logInfoArray,
        char     ** logInfoOut,
        uint32_t  * logInfoLengthOut);

   /* Loading.
    */
    virtual OSReturn load(
        OSKextExcludeLevel   startOpt         = kOSKextExcludeNone,
        OSKextExcludeLevel   startMatchingOpt = kOSKextExcludeAll,
        OSArray            * personalityNames = NULL); // priv/prot
    virtual OSReturn unload(void);
    virtual OSReturn queueKextNotification(
        const char * notificationName,
        OSString   * kextIdentifier);

    static void recordIdentifierRequest(
        OSString * kextIdentifier);

    virtual OSReturn loadExecutable(void);
    virtual void     jettisonLinkeditSegment(void);
    virtual OSReturn removeLinkeditHeaders(kernel_segment_command_t *linkedit);
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
    virtual OSReturn setVMProtections(void);
    virtual boolean_t segmentShouldBeWired(kernel_segment_command_t *seg);
    virtual OSReturn validateKextMapping(bool startFlag);
    virtual boolean_t verifySegmentMapping(kernel_segment_command_t *seg);

    static OSArray * copyAllKextPersonalities(
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
    static OSReturn pingKextd(void);

   /* Getting info about loaded kexts (kextstat).
    */
    static  OSDictionary * copyLoadedKextInfo(
        OSArray * kextIdentifiers = NULL,
        OSArray * keys = NULL);
    virtual OSDictionary * copyInfo(OSArray * keys = NULL);

    static  OSData       * copySanitizedKernelImage(void);

   /* Logging to user space.
    */
    static OSKextLogSpec setUserSpaceLogFilter(
        OSKextLogSpec  userLogSpec,
        bool           captureFlag = false);
    static OSArray * clearUserSpaceLogFilter(void);
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
    static  void reportOSMetaClassInstances(
        const char     * kextIdentifier,
        OSKextLogSpec    msgLogSpec);
    virtual void reportOSMetaClassInstances(
        OSKextLogSpec msgLogSpec);

   /* Resource requests and other callback stuff.
    */
    static OSReturn dispatchResource(OSDictionary * requestDict);

    static OSReturn dequeueCallbackForRequestTag(
        OSKextRequestTag    requestTag,
        OSDictionary     ** callbackRecordOut);
    static OSReturn dequeueCallbackForRequestTag(
        OSNumber     *    requestTagNum,
        OSDictionary ** callbackRecordOut);
    static void invokeRequestCallback(
        OSDictionary * callbackRecord,
        OSReturn         requestResult);
    virtual void invokeOrCancelRequestCallbacks(
        OSReturn callbackResult,
        bool     invokeFlag = true);
    virtual uint32_t countRequestCallbacks(void);

   /* panic() support.
    */
    static void printKextsInBacktrace(
        vm_offset_t   * addr,
        unsigned int    cnt,
        int          (* printf_func)(const char *fmt, ...),
        bool            lockFlag);
    static boolean_t summaryIsInBacktrace(
        OSKextLoadedKextSummary * summary,
        vm_offset_t             * addr,
        unsigned int              cnt);
    static void printSummary(
        OSKextLoadedKextSummary * summary,
        int                    (* printf_func)(const char *fmt, ...));

    static uint32_t saveLoadedKextPanicListTyped(
        const char * prefix,
        int          invertFlag,
        int          libsFlag,
        char       * paniclist,
        uint32_t     list_size,
        uint32_t   * list_length_ptr);
    static void saveLoadedKextPanicList(void);
    void savePanicString(bool isLoading);
    static void printKextPanicLists(int (*printf_func)(const char *fmt, ...));

   /* Kext summary support.
    */
    static void updateLoadedKextSummaries(void);
    void updateLoadedKextSummary(OSKextLoadedKextSummary *summary);

    /* C++ Initialization.
     */
    virtual void               setCPPInitialized(bool initialized=true);

#if __i386__
   /* Backward compatibility for kmod_get_info() MIG call.
    */
    static kern_return_t getKmodInfo(
        kmod_info_array_t      * kmodList,
        mach_msg_type_number_t * kmodCount);
#endif /* __i386__ */


#if PRAGMA_MARK
/**************************************/
#pragma mark Public Functions
/**************************************/
#endif
public:
    // caller must release
    static OSKext * lookupKextWithIdentifier(const char * kextIdentifier);
    static OSKext * lookupKextWithIdentifier(OSString * kextIdentifier);
    static OSKext * lookupKextWithLoadTag(OSKextLoadTag aTag);
    static OSKext * lookupKextWithAddress(vm_address_t address);
    
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
        Boolean            allowDeferFlag      = true,
        Boolean            delayAutounloadFlag = false,
        OSKextExcludeLevel startOpt            = kOSKextExcludeNone,
        OSKextExcludeLevel startMatchingOpt    = kOSKextExcludeAll,
        OSArray          * personalityNames    = NULL);
    static OSReturn removeKextWithIdentifier(
        const char * kextIdentifier,
        bool         terminateServicesAndRemovePersonalitiesFlag = false);
    static OSReturn removeKextWithLoadTag(
        OSKextLoadTag loadTag,
        bool          terminateServicesAndRemovePersonalitiesFlag = false);

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
    static void     setKextdActive(Boolean active = true);
    static void     setDeferredLoadSucceeded(Boolean succeeded = true);
    static void     considerRebuildOfPrelinkedKernel(OSString * moduleName);

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
    virtual OSData           * copyUUID(void);
    virtual OSArray          * copyPersonalitiesArray(void);
    
   /* This removes personalities naming the kext (by CFBundleIdentifier),
    * not all personalities defined by the kext (IOPersonalityPublisher or CFBundleIdentifier).
    */
    virtual void               removePersonalitiesFromCatalog(void);

   /* Converts common string-valued properties to OSSymbols for lower memory consumption.
    */
    static void uniquePersonalityProperties(OSDictionary * personalityDict);

    virtual bool               declaresExecutable(void);     // might be missing
    virtual bool               isInterface(void);
    virtual bool               isKernel(void);
    virtual bool               isKernelComponent(void);
    virtual bool               isExecutable(void);
    virtual bool               isLoadableInSafeBoot(void);
    virtual bool               isPrelinked(void);
    virtual bool               isLoaded(void);
    virtual bool               isStarted(void);
    virtual bool               isCPPInitialized(void);
};


#endif /* !_LIBKERN_OSKEXT_H */
