/*
 * Copyright (c) 1998-2016 Apple Inc. All rights reserved.
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

#include <IOKit/system.h>
#include <IOKit/IOService.h>
#include <libkern/OSDebug.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/c++/OSKext.h>
#include <libkern/Block.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOCommand.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterrupts.h>
#include <IOKit/IOInterruptController.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOUserServer.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOInterruptAccountingPrivate.h>
#include <IOKit/IOKernelReporters.h>
#include <IOKit/AppleKeyStoreInterface.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/IOCPU.h>
#include <mach/sync_policy.h>
#include <mach/thread_info.h>
#include <IOKit/assert.h>
#include <sys/errno.h>
#include <sys/kdebug.h>
#include <string.h>

#include <machine/pal_routines.h>

#define LOG kprintf
//#define LOG IOLog
#define MATCH_DEBUG     0
#define IOSERVICE_OBFUSCATE(x) ((void *)(VM_KERNEL_ADDRPERM(x)))

// disabled since lockForArbitration() can be held externally
#define DEBUG_NOTIFIER_LOCKED   0

enum{
	kIOUserServerCheckInTimeoutSecs = 120ULL
};

#include "IOServicePrivate.h"
#include "IOKitKernelInternal.h"

// take lockForArbitration before LOCKNOTIFY

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IORegistryEntry

OSDefineMetaClassAndStructors(IOService, IORegistryEntry)

OSDefineMetaClassAndStructors(_IOServiceNotifier, IONotifier)
OSDefineMetaClassAndStructors(_IOServiceNullNotifier, IONotifier)

OSDefineMetaClassAndStructors(_IOServiceInterestNotifier, IONotifier)

OSDefineMetaClassAndStructors(_IOConfigThread, OSObject)

OSDefineMetaClassAndStructors(_IOServiceJob, OSObject)

OSDefineMetaClassAndStructors(IOResources, IOService)
OSDefineMetaClassAndStructors(IOUserResources, IOService)

OSDefineMetaClassAndStructors(_IOOpenServiceIterator, OSIterator)

OSDefineMetaClassAndAbstractStructors(IONotifier, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOPlatformExpert *       gIOPlatform;
static class IOPMrootDomain *   gIOPMRootDomain;
const IORegistryPlane *         gIOServicePlane;
const IORegistryPlane *         gIOPowerPlane;
const OSSymbol *                gIODeviceMemoryKey;
const OSSymbol *                gIOInterruptControllersKey;
const OSSymbol *                gIOInterruptSpecifiersKey;

const OSSymbol *                gIOResourcesKey;
const OSSymbol *                gIOUserResourcesKey;
const OSSymbol *                gIOResourceMatchKey;
const OSSymbol *                gIOResourceMatchedKey;
const OSSymbol *                gIOResourceIOKitKey;

const OSSymbol *                gIOProviderClassKey;
const OSSymbol *                gIONameMatchKey;
const OSSymbol *                gIONameMatchedKey;
const OSSymbol *                gIOPropertyMatchKey;
const OSSymbol *                gIOPropertyExistsMatchKey;
const OSSymbol *                gIOLocationMatchKey;
const OSSymbol *                gIOParentMatchKey;
const OSSymbol *                gIOPathMatchKey;
const OSSymbol *                gIOMatchCategoryKey;
const OSSymbol *                gIODefaultMatchCategoryKey;
const OSSymbol *                gIOMatchedServiceCountKey;
const OSSymbol *                gIOMatchedPersonalityKey;
const OSSymbol *                gIORematchPersonalityKey;
const OSSymbol *                gIORematchCountKey;
const OSSymbol *                gIODEXTMatchCountKey;
const OSSymbol *                gIOSupportedPropertiesKey;
const OSSymbol *                gIOUserServicePropertiesKey;
#if !CONFIG_EMBEDDED
const OSSymbol *                gIOServiceLegacyMatchingRegistryIDKey;
#endif

const OSSymbol *                gIOMapperIDKey;
const OSSymbol *                gIOUserClientClassKey;

const OSSymbol *                gIOUserClassKey;
const OSSymbol *                gIOUserServerClassKey;
const OSSymbol *                gIOUserServerNameKey;
const OSSymbol *                gIOUserServerTagKey;
const OSSymbol *                gIOUserServerCDHashKey;
const OSSymbol *                gIOUserUserClientKey;

const OSSymbol *                gIOKitDebugKey;

const OSSymbol *                gIOCommandPoolSizeKey;

const OSSymbol *                gIOConsoleLockedKey;
const OSSymbol *                gIOConsoleUsersKey;
const OSSymbol *                gIOConsoleSessionUIDKey;
const OSSymbol *                gIOConsoleSessionAuditIDKey;
const OSSymbol *                gIOConsoleUsersSeedKey;
const OSSymbol *                gIOConsoleSessionOnConsoleKey;
const OSSymbol *                gIOConsoleSessionLoginDoneKey;
const OSSymbol *                gIOConsoleSessionSecureInputPIDKey;
const OSSymbol *                gIOConsoleSessionScreenLockedTimeKey;
const OSSymbol *                gIOConsoleSessionScreenIsLockedKey;
clock_sec_t                     gIOConsoleLockTime;
static bool                     gIOConsoleLoggedIn;
#if HIBERNATION
static OSBoolean *              gIOConsoleBooterLockState;
static uint32_t                 gIOScreenLockState;
#endif
static IORegistryEntry *        gIOChosenEntry;

static int                      gIOResourceGenerationCount;

const OSSymbol *                gIOServiceKey;
const OSSymbol *                gIOPublishNotification;
const OSSymbol *                gIOFirstPublishNotification;
const OSSymbol *                gIOMatchedNotification;
const OSSymbol *                gIOFirstMatchNotification;
const OSSymbol *                gIOTerminatedNotification;
const OSSymbol *                gIOWillTerminateNotification;

const OSSymbol *                gIOServiceDEXTEntitlementsKey;
const OSSymbol *                gIODriverKitEntitlementKey;
const OSSymbol *                gIODriverKitUserClientEntitlementsKey;
const OSSymbol *                gIODriverKitUserClientEntitlementAllowAnyKey;
const OSSymbol *                gIOMatchDeferKey;

const OSSymbol *                gIOGeneralInterest;
const OSSymbol *                gIOBusyInterest;
const OSSymbol *                gIOAppPowerStateInterest;
const OSSymbol *                gIOPriorityPowerStateInterest;
const OSSymbol *                gIOConsoleSecurityInterest;

const OSSymbol *                gIOBSDKey;
const OSSymbol *                gIOBSDNameKey;
const OSSymbol *                gIOBSDMajorKey;
const OSSymbol *                gIOBSDMinorKey;
const OSSymbol *                gIOBSDUnitKey;

const  OSSymbol *               gAKSGetKey;
#if defined(__i386__) || defined(__x86_64__)
const OSSymbol *                gIOCreateEFIDevicePathSymbol;
#endif

static OSDictionary *           gNotifications;
static IORecursiveLock *        gNotificationLock;

static IOService *              gIOResources;
static IOService *              gIOUserResources;
static IOService *              gIOServiceRoot;

static OSOrderedSet *           gJobs;
static semaphore_port_t         gJobsSemaphore;
static IOLock *                 gJobsLock;
static int                      gOutstandingJobs;
static int                      gNumConfigThreads;
static int                      gNumWaitingThreads;
static IOLock *                 gIOServiceBusyLock;
bool                            gCPUsRunning;
bool                                                    gKextdWillTerminate;

static thread_t                 gIOTerminateThread;
static thread_t                 gIOTerminateWorkerThread;
static UInt32                   gIOTerminateWork;
static OSArray *                gIOTerminatePhase2List;
static OSArray *                gIOStopList;
static OSArray *                gIOStopProviderList;
static OSArray *                gIOFinalizeList;

#if !NO_KEXTD
static OSArray *                gIOMatchDeferList;
#endif

static SInt32                   gIOConsoleUsersSeed;
static OSData *                 gIOConsoleUsersSeedValue;

extern const OSSymbol *         gIODTPHandleKey;

const OSSymbol *                gIOPlatformFunctionHandlerSet;


static IOLock *                 gIOConsoleUsersLock;
static thread_call_t            gIOConsoleLockCallout;
static IONotifier *             gIOServiceNullNotifier;

static uint32_t                 gIODextRelaunchMax = 1000;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define LOCKREADNOTIFY()        \
    IORecursiveLockLock( gNotificationLock )
#define LOCKWRITENOTIFY()       \
    IORecursiveLockLock( gNotificationLock )
#define LOCKWRITE2READNOTIFY()
#define UNLOCKNOTIFY()          \
    IORecursiveLockUnlock( gNotificationLock )
#define SLEEPNOTIFY(event) \
    IORecursiveLockSleep( gNotificationLock, (void *)(event), THREAD_UNINT )
#define SLEEPNOTIFYTO(event, deadline) \
    IORecursiveLockSleepDeadline( gNotificationLock, (void *)(event), deadline, THREAD_UNINT )
#define WAKEUPNOTIFY(event) \
	IORecursiveLockWakeup( gNotificationLock, (void *)(event), /* wake one */ false )

#define randomDelay()   \
	int del = read_processor_clock();                               \
	del = (((int)IOThreadSelf()) ^ del ^ (del >> 10)) & 0x3ff;      \
	IOSleep( del );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define queue_element(entry, element, type, field) do { \
	vm_address_t __ele = (vm_address_t) (entry);    \
	__ele -= -4 + ((size_t)(&((type) 4)->field));   \
	(element) = (type) __ele;                       \
    } while(0)

#define iterqueue(que, elt)                             \
	for (queue_entry_t elt = queue_first(que);      \
	     !queue_end(que, elt);                      \
	     elt = queue_next(elt))

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOInterruptAccountingReporter {
	IOSimpleReporter * reporter; /* Reporter responsible for communicating the statistics */
	IOInterruptAccountingData * statistics; /* The live statistics values, if any */
};

struct ArbitrationLockQueueElement {
	queue_chain_t link;
	IOThread      thread;
	IOService *   service;
	unsigned      count;
	bool          required;
	bool          aborted;
};

static queue_head_t gArbitrationLockQueueActive;
static queue_head_t gArbitrationLockQueueWaiting;
static queue_head_t gArbitrationLockQueueFree;
static IOLock *     gArbitrationLockQueueLock;

bool
IOService::isInactive( void ) const
{
	return 0 != (kIOServiceInactiveState & getState());
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(__i386__) || defined(__x86_64__)

// Only used by the intel implementation of
//     IOService::requireMaxBusStall(UInt32 ns)
//     IOService::requireMaxInterruptDelay(uint32_t ns)
struct CpuDelayEntry {
	IOService * fService;
	UInt32      fMaxDelay;
	UInt32      fDelayType;
};

enum {
	kCpuDelayBusStall, kCpuDelayInterrupt,
	kCpuNumDelayTypes
};

static OSData          *sCpuDelayData = OSData::withCapacity(8 * sizeof(CpuDelayEntry));
static IORecursiveLock *sCpuDelayLock = IORecursiveLockAlloc();
static OSArray         *sCpuLatencyHandlers[kCpuNumDelayTypes];
const OSSymbol         *sCPULatencyFunctionName[kCpuNumDelayTypes];
static OSNumber * sCPULatencyHolder[kCpuNumDelayTypes];
static char sCPULatencyHolderName[kCpuNumDelayTypes][128];
static OSNumber * sCPULatencySet[kCpuNumDelayTypes];

static void
requireMaxCpuDelay(IOService * service, UInt32 ns, UInt32 delayType);
static IOReturn
setLatencyHandler(UInt32 delayType, IOService * target, bool enable);

#endif /* defined(__i386__) || defined(__x86_64__) */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

namespace IOServicePH
{
IONotifier          * fRootNotifier;
OSArray             * fUserServers;
OSArray             * fUserServersWait;
OSArray             * fMatchingWork;
OSArray             * fMatchingDelayed;
IOService           * fSystemPowerAckTo;
uint32_t              fSystemPowerAckRef;
uint8_t               fSystemOff;
uint8_t               fUserServerOff;

void lock();
void unlock();

void init(IOPMrootDomain * root);

IOReturn systemPowerChange(
	void * target,
	void * refCon,
	UInt32 messageType, IOService * service,
	void * messageArgument, vm_size_t argSize);

bool matchingStart(IOService * service);
void matchingEnd(IOService * service);
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOService::initialize( void )
{
	kern_return_t       err;

	gIOServicePlane     = IORegistryEntry::makePlane( kIOServicePlane );
	gIOPowerPlane       = IORegistryEntry::makePlane( kIOPowerPlane );

	gIOProviderClassKey = OSSymbol::withCStringNoCopy( kIOProviderClassKey );
	gIONameMatchKey     = OSSymbol::withCStringNoCopy( kIONameMatchKey );
	gIONameMatchedKey   = OSSymbol::withCStringNoCopy( kIONameMatchedKey );
	gIOPropertyMatchKey = OSSymbol::withCStringNoCopy( kIOPropertyMatchKey );
	gIOPropertyExistsMatchKey = OSSymbol::withCStringNoCopy( kIOPropertyExistsMatchKey );
	gIOPathMatchKey     = OSSymbol::withCStringNoCopy( kIOPathMatchKey );
	gIOLocationMatchKey = OSSymbol::withCStringNoCopy( kIOLocationMatchKey );
	gIOParentMatchKey   = OSSymbol::withCStringNoCopy( kIOParentMatchKey );

	gIOMatchCategoryKey = OSSymbol::withCStringNoCopy( kIOMatchCategoryKey );
	gIODefaultMatchCategoryKey  = OSSymbol::withCStringNoCopy(
		kIODefaultMatchCategoryKey );
	gIOMatchedServiceCountKey   = OSSymbol::withCStringNoCopy(
		kIOMatchedServiceCountKey );
	gIOMatchedPersonalityKey = OSSymbol::withCStringNoCopy(
		kIOMatchedPersonalityKey );
	gIORematchPersonalityKey = OSSymbol::withCStringNoCopy(
		kIORematchPersonalityKey );
	gIORematchCountKey = OSSymbol::withCStringNoCopy(
		kIORematchCountKey );
	gIODEXTMatchCountKey = OSSymbol::withCStringNoCopy(
		kIODEXTMatchCountKey );

#if !CONFIG_EMBEDDED
	gIOServiceLegacyMatchingRegistryIDKey = OSSymbol::withCStringNoCopy(
		kIOServiceLegacyMatchingRegistryIDKey );
#endif

	PE_parse_boot_argn("dextrelaunch", &gIODextRelaunchMax, sizeof(gIODextRelaunchMax));

	gIOUserClientClassKey = OSSymbol::withCStringNoCopy( kIOUserClientClassKey );

	gIOUserClassKey       = OSSymbol::withCStringNoCopy(kIOUserClassKey);

	gIOUserServerClassKey  = OSSymbol::withCStringNoCopy(kIOUserServerClassKey);
	gIOUserServerNameKey   = OSSymbol::withCStringNoCopy(kIOUserServerNameKey);
	gIOUserServerTagKey    = OSSymbol::withCStringNoCopy(kIOUserServerTagKey);
	gIOUserServerCDHashKey = OSSymbol::withCStringNoCopy(kIOUserServerCDHashKey);
	gIOUserUserClientKey   = OSSymbol::withCStringNoCopy(kIOUserUserClientKey);

	gIOResourcesKey       = OSSymbol::withCStringNoCopy( kIOResourcesClass );
	gIOResourceMatchKey   = OSSymbol::withCStringNoCopy( kIOResourceMatchKey );
	gIOResourceMatchedKey = OSSymbol::withCStringNoCopy( kIOResourceMatchedKey );
	gIOResourceIOKitKey   = OSSymbol::withCStringNoCopy("IOKit");

	gIODeviceMemoryKey  = OSSymbol::withCStringNoCopy( "IODeviceMemory" );
	gIOInterruptControllersKey
	        = OSSymbol::withCStringNoCopy("IOInterruptControllers");
	gIOInterruptSpecifiersKey
	        = OSSymbol::withCStringNoCopy("IOInterruptSpecifiers");

	gIOSupportedPropertiesKey = OSSymbol::withCStringNoCopy(kIOSupportedPropertiesKey);
	gIOUserServicePropertiesKey = OSSymbol::withCStringNoCopy(kIOUserServicePropertiesKey);

	gIOMapperIDKey = OSSymbol::withCStringNoCopy(kIOMapperIDKey);

	gIOKitDebugKey      = OSSymbol::withCStringNoCopy( kIOKitDebugKey );

	gIOCommandPoolSizeKey       = OSSymbol::withCStringNoCopy( kIOCommandPoolSizeKey );

	gIOGeneralInterest          = OSSymbol::withCStringNoCopy( kIOGeneralInterest );
	gIOBusyInterest             = OSSymbol::withCStringNoCopy( kIOBusyInterest );
	gIOAppPowerStateInterest    = OSSymbol::withCStringNoCopy( kIOAppPowerStateInterest );
	gIOPriorityPowerStateInterest       = OSSymbol::withCStringNoCopy( kIOPriorityPowerStateInterest );
	gIOConsoleSecurityInterest  = OSSymbol::withCStringNoCopy( kIOConsoleSecurityInterest );

	gIOBSDKey      = OSSymbol::withCStringNoCopy(kIOBSDKey);
	gIOBSDNameKey  = OSSymbol::withCStringNoCopy(kIOBSDNameKey);
	gIOBSDMajorKey = OSSymbol::withCStringNoCopy(kIOBSDMajorKey);
	gIOBSDMinorKey = OSSymbol::withCStringNoCopy(kIOBSDMinorKey);
	gIOBSDUnitKey  = OSSymbol::withCStringNoCopy(kIOBSDUnitKey);

	gNotifications              = OSDictionary::withCapacity( 1 );
	gIOPublishNotification      = OSSymbol::withCStringNoCopy(
		kIOPublishNotification );
	gIOFirstPublishNotification = OSSymbol::withCStringNoCopy(
		kIOFirstPublishNotification );
	gIOMatchedNotification      = OSSymbol::withCStringNoCopy(
		kIOMatchedNotification );
	gIOFirstMatchNotification   = OSSymbol::withCStringNoCopy(
		kIOFirstMatchNotification );
	gIOTerminatedNotification   = OSSymbol::withCStringNoCopy(
		kIOTerminatedNotification );
	gIOWillTerminateNotification = OSSymbol::withCStringNoCopy(
		kIOWillTerminateNotification );
	gIOServiceKey               = OSSymbol::withCStringNoCopy( kIOServiceClass);


	gIOConsoleLockedKey         = OSSymbol::withCStringNoCopy( kIOConsoleLockedKey);
	gIOConsoleUsersKey          = OSSymbol::withCStringNoCopy( kIOConsoleUsersKey);
	gIOConsoleSessionUIDKey     = OSSymbol::withCStringNoCopy( kIOConsoleSessionUIDKey);
	gIOConsoleSessionAuditIDKey = OSSymbol::withCStringNoCopy( kIOConsoleSessionAuditIDKey);

	gIOConsoleUsersSeedKey               = OSSymbol::withCStringNoCopy(kIOConsoleUsersSeedKey);
	gIOConsoleSessionOnConsoleKey        = OSSymbol::withCStringNoCopy(kIOConsoleSessionOnConsoleKey);
	gIOConsoleSessionLoginDoneKey        = OSSymbol::withCStringNoCopy(kIOConsoleSessionLoginDoneKey);
	gIOConsoleSessionSecureInputPIDKey   = OSSymbol::withCStringNoCopy(kIOConsoleSessionSecureInputPIDKey);
	gIOConsoleSessionScreenLockedTimeKey = OSSymbol::withCStringNoCopy(kIOConsoleSessionScreenLockedTimeKey);
	gIOConsoleSessionScreenIsLockedKey   = OSSymbol::withCStringNoCopy(kIOConsoleSessionScreenIsLockedKey);

	gIOConsoleUsersSeedValue           = OSData::withBytesNoCopy(&gIOConsoleUsersSeed, sizeof(gIOConsoleUsersSeed));

	gIOServiceDEXTEntitlementsKey           = OSSymbol::withCStringNoCopy( kIOServiceDEXTEntitlementsKey );
	gIODriverKitEntitlementKey             = OSSymbol::withCStringNoCopy( kIODriverKitEntitlementKey );
	gIODriverKitUserClientEntitlementsKey   = OSSymbol::withCStringNoCopy( kIODriverKitUserClientEntitlementsKey );
	gIODriverKitUserClientEntitlementAllowAnyKey   = OSSymbol::withCStringNoCopy( kIODriverKitUserClientEntitlementAllowAnyKey );
	gIOMatchDeferKey                        = OSSymbol::withCStringNoCopy( kIOMatchDeferKey );

	gIOPlatformFunctionHandlerSet               = OSSymbol::withCStringNoCopy(kIOPlatformFunctionHandlerSet);
#if defined(__i386__) || defined(__x86_64__)
	sCPULatencyFunctionName[kCpuDelayBusStall]  = OSSymbol::withCStringNoCopy(kIOPlatformFunctionHandlerMaxBusDelay);
	sCPULatencyFunctionName[kCpuDelayInterrupt] = OSSymbol::withCStringNoCopy(kIOPlatformFunctionHandlerMaxInterruptDelay);
	uint32_t  idx;
	for (idx = 0; idx < kCpuNumDelayTypes; idx++) {
		sCPULatencySet[idx]    = OSNumber::withNumber(-1U, 32);
		sCPULatencyHolder[idx] = OSNumber::withNumber(0ULL, 64);
		assert(sCPULatencySet[idx] && sCPULatencyHolder[idx]);
	}
	gIOCreateEFIDevicePathSymbol = OSSymbol::withCString("CreateEFIDevicePath");
#endif
	gNotificationLock           = IORecursiveLockAlloc();

	gAKSGetKey                   = OSSymbol::withCStringNoCopy(AKS_PLATFORM_FUNCTION_GETKEY);

	assert( gIOServicePlane && gIODeviceMemoryKey
	    && gIOInterruptControllersKey && gIOInterruptSpecifiersKey
	    && gIOResourcesKey && gNotifications && gNotificationLock
	    && gIOProviderClassKey && gIONameMatchKey && gIONameMatchedKey
	    && gIOMatchCategoryKey && gIODefaultMatchCategoryKey
	    && gIOPublishNotification && gIOMatchedNotification
	    && gIOTerminatedNotification && gIOServiceKey
	    && gIOConsoleUsersKey && gIOConsoleSessionUIDKey
	    && gIOConsoleSessionOnConsoleKey && gIOConsoleSessionSecureInputPIDKey
	    && gIOConsoleUsersSeedKey && gIOConsoleUsersSeedValue);

	gJobsLock   = IOLockAlloc();
	gJobs       = OSOrderedSet::withCapacity( 10 );

	gIOServiceBusyLock = IOLockAlloc();

	gIOConsoleUsersLock = IOLockAlloc();

	err = semaphore_create(kernel_task, &gJobsSemaphore, SYNC_POLICY_FIFO, 0);

	gIOConsoleLockCallout = thread_call_allocate(&IOService::consoleLockTimer, NULL);

	IORegistryEntry::getRegistryRoot()->setProperty(gIOConsoleLockedKey, kOSBooleanTrue);

	assert( gIOServiceBusyLock && gJobs && gJobsLock && gIOConsoleUsersLock
	    && gIOConsoleLockCallout && (err == KERN_SUCCESS));

	gIOResources = IOResources::resources();
	gIOUserResources = IOUserResources::resources();
	assert( gIOResources && gIOUserResources );

	gIOServiceNullNotifier = OSTypeAlloc(_IOServiceNullNotifier);
	assert(gIOServiceNullNotifier);

	gArbitrationLockQueueLock = IOLockAlloc();
	queue_init(&gArbitrationLockQueueActive);
	queue_init(&gArbitrationLockQueueWaiting);
	queue_init(&gArbitrationLockQueueFree);

	assert( gArbitrationLockQueueLock );

	gIOTerminatePhase2List = OSArray::withCapacity( 2 );
	gIOStopList            = OSArray::withCapacity( 16 );
	gIOStopProviderList    = OSArray::withCapacity( 16 );
	gIOFinalizeList        = OSArray::withCapacity( 16 );
#if !NO_KEXTD
	gIOMatchDeferList      = OSArray::withCapacity( 16 );
#endif
	assert( gIOTerminatePhase2List && gIOStopList && gIOStopProviderList && gIOFinalizeList );

	// worker thread that is responsible for terminating / cleaning up threads
	kernel_thread_start(&terminateThread, NULL, &gIOTerminateWorkerThread);
	assert(gIOTerminateWorkerThread);
	thread_set_thread_name(gIOTerminateWorkerThread, "IOServiceTerminateThread");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(__i386__) || defined(__x86_64__)
extern "C" {
const char *getCpuDelayBusStallHolderName(void);
const char *
getCpuDelayBusStallHolderName(void)
{
	return sCPULatencyHolderName[kCpuDelayBusStall];
}

const char *getCpuInterruptDelayHolderName(void);
const char *
getCpuInterruptDelayHolderName(void)
{
	return sCPULatencyHolderName[kCpuDelayInterrupt];
}
}
#endif

#if IOMATCHDEBUG
static UInt64
getDebugFlags( OSDictionary * props )
{
	OSNumber *  debugProp;
	UInt64      debugFlags;

	debugProp = OSDynamicCast( OSNumber,
	    props->getObject( gIOKitDebugKey ));
	if (debugProp) {
		debugFlags = debugProp->unsigned64BitValue();
	} else {
		debugFlags = gIOKitDebug;
	}

	return debugFlags;
}

static UInt64
getDebugFlags( IOService * inst )
{
	OSObject *  prop;
	OSNumber *  debugProp;
	UInt64      debugFlags;

	prop = inst->copyProperty(gIOKitDebugKey);
	debugProp = OSDynamicCast(OSNumber, prop);
	if (debugProp) {
		debugFlags = debugProp->unsigned64BitValue();
	} else {
		debugFlags = gIOKitDebug;
	}

	OSSafeReleaseNULL(prop);

	return debugFlags;
}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Probe a matched service and return an instance to be started.
// The default score is from the property table, & may be altered
// during probe to change the start order.

IOService *
IOService::probe(   IOService * provider,
    SInt32    * score )
{
	return this;
}

bool
IOService::start( IOService * provider )
{
	return true;
}

void
IOService::stop( IOService * provider )
{
	if (reserved->uvars && reserved->uvars->started && reserved->uvars->userServer) {
		reserved->uvars->userServer->serviceStop(this, provider);
	}
}

bool
IOService::init( OSDictionary * dictionary )
{
	bool ret;

	ret = super::init(dictionary);
	if (!ret) {
		return false;
	}
	if (reserved) {
		return true;
	}

	reserved = IONew(ExpansionData, 1);
	if (!reserved) {
		return false;
	}
	bzero(reserved, sizeof(*reserved));

	/*
	 * TODO: Improve on this.  Previous efforts to more lazily allocate this
	 * lock based on the presence of specifiers ran into issues as some
	 * platforms set up the specifiers after IOService initialization.
	 *
	 * We may be able to get away with a global lock, as this should only be
	 * contended by IOReporting clients and driver start/stop (unless a
	 * driver wants to remove/add handlers in the course of normal operation,
	 * which should be unlikely).
	 */
	reserved->interruptStatisticsLock = IOLockAlloc();
	if (!reserved->interruptStatisticsLock) {
		return false;
	}

	return true;
}

bool
IOService::init( IORegistryEntry * from,
    const IORegistryPlane * inPlane )
{
	bool ret;

	ret = super::init(from, inPlane);
	if (!ret) {
		return false;
	}
	if (reserved) {
		return true;
	}

	reserved = IONew(ExpansionData, 1);
	if (!reserved) {
		return false;
	}
	bzero(reserved, sizeof(*reserved));

	/*
	 * TODO: Improve on this.  Previous efforts to more lazily allocate this
	 * lock based on the presence of specifiers ran into issues as some
	 * platforms set up the specifiers after IOService initialization.
	 *
	 * We may be able to get away with a global lock, as this should only be
	 * contended by IOReporting clients and driver start/stop (unless a
	 * driver wants to remove/add handlers in the course of normal operation,
	 * which should be unlikely).
	 */
	reserved->interruptStatisticsLock = IOLockAlloc();
	if (!reserved->interruptStatisticsLock) {
		return false;
	}

	return true;
}

void
IOService::free( void )
{
	int i = 0;
	requireMaxBusStall(0);
	requireMaxInterruptDelay(0);
	if (getPropertyTable()) {
		unregisterAllInterest();
	}
	PMfree();

	if (reserved) {
		if (reserved->interruptStatisticsArray) {
			for (i = 0; i < reserved->interruptStatisticsArrayCount; i++) {
				if (reserved->interruptStatisticsArray[i].reporter) {
					reserved->interruptStatisticsArray[i].reporter->release();
				}
			}

			IODelete(reserved->interruptStatisticsArray, IOInterruptAccountingReporter, reserved->interruptStatisticsArrayCount);
		}

		if (reserved->interruptStatisticsLock) {
			IOLockFree(reserved->interruptStatisticsLock);
		}
		if (reserved->uvars && reserved->uvars->userServer) {
			reserved->uvars->userServer->serviceFree(this);
		}
		IODelete(reserved, ExpansionData, 1);
	}

	if (_numInterruptSources && _interruptSources) {
		for (i = 0; i < _numInterruptSources; i++) {
			void * block = _interruptSourcesPrivate(this)[i].vectorBlock;
			if (block) {
				Block_release(block);
			}
		}
		IOFree(_interruptSources,
		    _numInterruptSources * sizeofAllIOInterruptSource);
		_interruptSources = NULL;
	}

	super::free();
}

/*
 * Attach in service plane
 */
bool
IOService::attach( IOService * provider )
{
	bool         ok;
	uint32_t     count;
	AbsoluteTime deadline;
	int          waitResult = THREAD_AWAKENED;
	bool         wait, computeDeadline = true;

	if (provider) {
		if (gIOKitDebug & kIOLogAttach) {
			LOG( "%s::attach(%s)\n", getName(),
			    provider->getName());
		}

		ok   = false;
		do{
			wait = false;
			provider->lockForArbitration();
			if (provider->__state[0] & kIOServiceInactiveState) {
				ok = false;
			} else {
				count = provider->getChildCount(gIOServicePlane);
				wait = (count > (kIOServiceBusyMax - 4));
				if (!wait) {
					ok = attachToParent(provider, gIOServicePlane);
				} else {
					IOLog("stalling for detach from %s\n", provider->getName());
					IOLockLock( gIOServiceBusyLock );
					provider->__state[1] |= kIOServiceWaitDetachState;
				}
			}
			provider->unlockForArbitration();
			if (wait) {
				if (computeDeadline) {
					clock_interval_to_deadline(15, kSecondScale, &deadline);
					computeDeadline = false;
				}
				assert_wait_deadline((event_t)&provider->__provider, THREAD_UNINT, deadline);
				IOLockUnlock( gIOServiceBusyLock );
				waitResult = thread_block(THREAD_CONTINUE_NULL);
				wait = (waitResult != THREAD_TIMED_OUT);
			}
		}while (wait);
	} else {
		gIOServiceRoot = this;
		ok = attachToParent( getRegistryRoot(), gIOServicePlane);
	}

	if (ok && !__provider) {
		(void) getProvider();
	}

	return ok;
}

IOService *
IOService::getServiceRoot( void )
{
	return gIOServiceRoot;
}

void
IOService::detach( IOService * provider )
{
	IOService * newProvider = NULL;
	SInt32      busy;
	bool        adjParent;

	if (gIOKitDebug & kIOLogAttach) {
		LOG("%s::detach(%s)\n", getName(), provider->getName());
	}

#if !NO_KEXTD
	IOLockLock(gJobsLock);
	if (gIOMatchDeferList) {
		auto idx = gIOMatchDeferList->getNextIndexOfObject(this, 0);
		if (-1U != idx) {
			gIOMatchDeferList->removeObject(idx);
		}
	}
	if (IOServicePH::fMatchingDelayed) {
		auto idx = IOServicePH::fMatchingDelayed->getNextIndexOfObject(this, 0);
		if (-1U != idx) {
			IOServicePH::fMatchingDelayed->removeObject(idx);
		}
	}
	IOLockUnlock(gJobsLock);
#endif /* NO_KEXTD */

	lockForArbitration();

	uint64_t regID1 = provider->getRegistryEntryID();
	uint64_t regID2 = getRegistryEntryID();
	IOServiceTrace(
		IOSERVICE_DETACH,
		(uintptr_t) regID1,
		(uintptr_t) (regID1 >> 32),
		(uintptr_t) regID2,
		(uintptr_t) (regID2 >> 32));

	adjParent = ((busy = (__state[1] & kIOServiceBusyStateMask))
	    && (provider == getProvider()));

	detachFromParent( provider, gIOServicePlane );

	if (busy) {
		newProvider = getProvider();
		if (busy && (__state[1] & kIOServiceTermPhase3State) && (NULL == newProvider)) {
			_adjustBusy( -busy );
		}
	}

	if (kIOServiceInactiveState & __state[0]) {
		getMetaClass()->removeInstance(this);
		IORemoveServicePlatformActions(this);
	}

	unlockForArbitration();

	if (newProvider && adjParent) {
		newProvider->lockForArbitration();
		newProvider->_adjustBusy(1);
		newProvider->unlockForArbitration();
	}

	// check for last client detach from a terminated service
	if (provider->lockForArbitration( true )) {
		if (kIOServiceStartState & __state[1]) {
			provider->scheduleTerminatePhase2();
		}
		if (adjParent) {
			provider->_adjustBusy( -1 );
		}
		if ((provider->__state[1] & kIOServiceTermPhase3State)
		    && (NULL == provider->getClient())) {
			provider->scheduleFinalize(false);
		}

		IOLockLock( gIOServiceBusyLock );
		if (kIOServiceWaitDetachState & provider->__state[1]) {
			provider->__state[1] &= ~kIOServiceWaitDetachState;
			thread_wakeup(&provider->__provider);
		}
		IOLockUnlock( gIOServiceBusyLock );

		provider->unlockForArbitration();
	}
}

/*
 * Register instance - publish it for matching
 */

void
IOService::registerService( IOOptionBits options )
{
	char *              pathBuf;
	const char *        path;
	char *              skip;
	int                 len;
	enum { kMaxPathLen  = 256 };
	enum { kMaxChars    = 63 };

	IORegistryEntry * parent = this;
	IORegistryEntry * root = getRegistryRoot();
	while (parent && (parent != root)) {
		parent = parent->getParentEntry( gIOServicePlane);
	}

	if (parent != root) {
		IOLog("%s: not registry member at registerService()\n", getName());
		return;
	}

	// Allow the Platform Expert to adjust this node.
	if (gIOPlatform && (!gIOPlatform->platformAdjustService(this))) {
		return;
	}

	IOInstallServicePlatformActions(this);

	if ((this != gIOResources)
	    && (kIOLogRegister & gIOKitDebug)) {
		pathBuf = (char *) IOMalloc( kMaxPathLen );

		IOLog( "Registering: " );

		len = kMaxPathLen;
		if (pathBuf && getPath( pathBuf, &len, gIOServicePlane)) {
			path = pathBuf;
			if (len > kMaxChars) {
				IOLog("..");
				len -= kMaxChars;
				path += len;
				if ((skip = strchr( path, '/'))) {
					path = skip;
				}
			}
		} else {
			path = getName();
		}

		IOLog( "%s\n", path );

		if (pathBuf) {
			IOFree( pathBuf, kMaxPathLen );
		}
	}

	startMatching( options );
}

void
IOService::startMatching( IOOptionBits options )
{
	IOService * provider;
	UInt32      prevBusy = 0;
	bool        needConfig;
	bool        needWake = false;
	bool        ok;
	bool        sync;
	bool        waitAgain;

	lockForArbitration();

	sync = (options & kIOServiceSynchronous)
	    || ((provider = getProvider())
	    && (provider->__state[1] & kIOServiceSynchronousState));

	if (options & kIOServiceAsynchronous) {
		sync = false;
	}

	needConfig =  (0 == (__state[1] & (kIOServiceNeedConfigState | kIOServiceConfigRunning)))
	    && (0 == (__state[0] & kIOServiceInactiveState));

	__state[1] |= kIOServiceNeedConfigState;

//    __state[0] &= ~kIOServiceInactiveState;

//    if( sync) LOG("OSKernelStackRemaining = %08x @ %s\n",
//			OSKernelStackRemaining(), getName());

	if (needConfig) {
		needWake = (0 != (kIOServiceSyncPubState & __state[1]));
	}

	if (sync) {
		__state[1] |= kIOServiceSynchronousState;
	} else {
		__state[1] &= ~kIOServiceSynchronousState;
	}

	if (needConfig) {
		prevBusy = _adjustBusy( 1 );
	}

	unlockForArbitration();

	if (needConfig) {
		if (needWake) {
			IOLockLock( gIOServiceBusyLock );
			thread_wakeup((event_t) this /*&__state[1]*/ );
			IOLockUnlock( gIOServiceBusyLock );
		} else if (!sync || (kIOServiceAsynchronous & options)) {
			ok = (NULL != _IOServiceJob::startJob( this, kMatchNubJob, options ));
		} else {
			do {
				if ((__state[1] & kIOServiceNeedConfigState)) {
					doServiceMatch( options );
				}

				lockForArbitration();
				IOLockLock( gIOServiceBusyLock );

				waitAgain = ((prevBusy < (__state[1] & kIOServiceBusyStateMask))
				    && (0 == (__state[0] & kIOServiceInactiveState)));

				if (waitAgain) {
					__state[1] |= kIOServiceSyncPubState | kIOServiceBusyWaiterState;
				} else {
					__state[1] &= ~kIOServiceSyncPubState;
				}

				unlockForArbitration();

				if (waitAgain) {
					assert_wait((event_t) this /*&__state[1]*/, THREAD_UNINT);
				}

				IOLockUnlock( gIOServiceBusyLock );
				if (waitAgain) {
					thread_block(THREAD_CONTINUE_NULL);
				}
			} while (waitAgain);
		}
	}
}


void
IOService::startDeferredMatches(void)
{
#if !NO_KEXTD
	OSArray * array;

	IOLockLock(gJobsLock);
	array = gIOMatchDeferList;
	gIOMatchDeferList = NULL;
	IOLockUnlock(gJobsLock);

	if (array) {
		IOLog("deferred rematching count %d\n", array->getCount());
		array->iterateObjects(^bool (OSObject * obj)
		{
			((IOService *)obj)->startMatching(kIOServiceAsynchronous);
			return false;
		});
		array->release();
	}
#endif /* !NO_KEXTD */
}

void
IOService::kextdLaunched(void)
{
#if !NO_KEXTD
	IOServiceTrace(IOSERVICE_KEXTD_READY, 0, 0, 0, 0);
	startDeferredMatches();
	getServiceRoot()->adjustBusy(-1);
	IOService::publishUserResource(gIOResourceIOKitKey);
#endif /* !NO_KEXTD */
}

IOReturn
IOService::catalogNewDrivers( OSOrderedSet * newTables )
{
	OSDictionary *      table;
	OSSet *             set;
	OSSet *             allSet = NULL;
	IOService *         service;
#if IOMATCHDEBUG
	SInt32              count = 0;
#endif

	newTables->retain();

	while ((table = (OSDictionary *) newTables->getFirstObject())) {
		LOCKWRITENOTIFY();
		set = (OSSet *) copyExistingServices( table,
		    kIOServiceRegisteredState,
		    kIOServiceExistingSet);
		UNLOCKNOTIFY();
		if (set) {
#if IOMATCHDEBUG
			count += set->getCount();
#endif
			if (allSet) {
				allSet->merge((const OSSet *) set);
				set->release();
			} else {
				allSet = set;
			}
		}

#if IOMATCHDEBUG
		if (getDebugFlags( table ) & kIOLogMatch) {
			LOG("Matching service count = %ld\n", (long)count);
		}
#endif
		newTables->removeObject(table);
	}

	if (allSet) {
		while ((service = (IOService *) allSet->getAnyObject())) {
			service->startMatching(kIOServiceAsynchronous);
			allSet->removeObject(service);
		}
		allSet->release();
	}

	newTables->release();

	return kIOReturnSuccess;
}

_IOServiceJob *
_IOServiceJob::startJob( IOService * nub, int type,
    IOOptionBits options )
{
	_IOServiceJob *     job;

	job = new _IOServiceJob;
	if (job && !job->init()) {
		job->release();
		job = NULL;
	}

	if (job) {
		job->type       = type;
		job->nub        = nub;
		job->options    = options;
		nub->retain();          // thread will release()
		pingConfig( job );
	}

	return job;
}

/*
 * Called on a registered service to see if it matches
 * a property table.
 */

bool
IOService::matchPropertyTable( OSDictionary * table, SInt32 * score )
{
	return matchPropertyTable(table);
}

bool
IOService::matchPropertyTable( OSDictionary * table )
{
	return true;
}

/*
 * Called on a matched service to allocate resources
 * before first driver is attached.
 */

IOReturn
IOService::getResources( void )
{
	return kIOReturnSuccess;
}

/*
 * Client/provider accessors
 */

IOService *
IOService::getProvider( void ) const
{
	IOService * self = (IOService *) this;
	IOService * parent;
	SInt32      generation;

	generation = getRegistryEntryGenerationCount();
	if (__providerGeneration == generation) {
		return __provider;
	}

	parent = (IOService *) getParentEntry( gIOServicePlane);
	if (parent == IORegistryEntry::getRegistryRoot()) {
		/* root is not an IOService */
		parent = NULL;
	}

	self->__provider = parent;
	OSMemoryBarrier();
	// save the count from before call to getParentEntry()
	self->__providerGeneration = generation;

	return parent;
}

IOWorkLoop *
IOService::getWorkLoop() const
{
	IOService *provider = getProvider();

	if (provider) {
		return provider->getWorkLoop();
	} else {
		return NULL;
	}
}

OSIterator *
IOService::getProviderIterator( void ) const
{
	return getParentIterator( gIOServicePlane);
}

IOService *
IOService::getClient( void ) const
{
	return (IOService *) getChildEntry( gIOServicePlane);
}

OSIterator *
IOService::getClientIterator( void ) const
{
	return getChildIterator( gIOServicePlane);
}

OSIterator *
_IOOpenServiceIterator::iterator( OSIterator * _iter,
    const IOService * client,
    const IOService * provider )
{
	_IOOpenServiceIterator * inst;

	if (!_iter) {
		return NULL;
	}

	inst = new _IOOpenServiceIterator;

	if (inst && !inst->init()) {
		inst->release();
		inst = NULL;
	}
	if (inst) {
		inst->iter = _iter;
		inst->client = client;
		inst->provider = provider;
	}

	return inst;
}

void
_IOOpenServiceIterator::free()
{
	iter->release();
	if (last) {
		last->unlockForArbitration();
	}
	OSIterator::free();
}

OSObject *
_IOOpenServiceIterator::getNextObject()
{
	IOService * next;

	if (last) {
		last->unlockForArbitration();
	}

	while ((next = (IOService *) iter->getNextObject())) {
		next->lockForArbitration();
		if ((client && (next->isOpen( client )))
		    || (provider && (provider->isOpen( next )))) {
			break;
		}
		next->unlockForArbitration();
	}

	last = next;

	return next;
}

bool
_IOOpenServiceIterator::isValid()
{
	return iter->isValid();
}

void
_IOOpenServiceIterator::reset()
{
	if (last) {
		last->unlockForArbitration();
		last = NULL;
	}
	iter->reset();
}

OSIterator *
IOService::getOpenProviderIterator( void ) const
{
	return _IOOpenServiceIterator::iterator( getProviderIterator(), this, NULL );
}

OSIterator *
IOService::getOpenClientIterator( void ) const
{
	return _IOOpenServiceIterator::iterator( getClientIterator(), NULL, this );
}


IOReturn
IOService::callPlatformFunction( const OSSymbol * functionName,
    bool waitForFunction,
    void *param1, void *param2,
    void *param3, void *param4 )
{
	IOReturn  result = kIOReturnUnsupported;
	IOService *provider;

	if (functionName == gIOPlatformQuiesceActionKey ||
	    functionName == gIOPlatformActiveActionKey) {
		/*
		 * Services which register for IOPlatformQuiesceAction / IOPlatformActiveAction
		 * must consume that event themselves, without passing it up to super/IOService.
		 */
		if (gEnforceQuiesceSafety) {
			panic("Class %s passed the quiesce/active action to IOService",
			    getMetaClass()->getClassName());
		}
	}

	if (gIOPlatformFunctionHandlerSet == functionName) {
#if defined(__i386__) || defined(__x86_64__)
		const OSSymbol * functionHandlerName = (const OSSymbol *) param1;
		IOService *      target              = (IOService *) param2;
		bool             enable              = (param3 != NULL);

		if (sCPULatencyFunctionName[kCpuDelayBusStall] == functionHandlerName) {
			result = setLatencyHandler(kCpuDelayBusStall, target, enable);
		} else if (sCPULatencyFunctionName[kCpuDelayInterrupt] == param1) {
			result = setLatencyHandler(kCpuDelayInterrupt, target, enable);
		}
#endif /* defined(__i386__) || defined(__x86_64__) */
	}

	if ((kIOReturnUnsupported == result) && (provider = getProvider())) {
		result = provider->callPlatformFunction(functionName, waitForFunction,
		    param1, param2, param3, param4);
	}

	return result;
}

IOReturn
IOService::callPlatformFunction( const char * functionName,
    bool waitForFunction,
    void *param1, void *param2,
    void *param3, void *param4 )
{
	IOReturn result = kIOReturnNoMemory;
	const OSSymbol *functionSymbol = OSSymbol::withCString(functionName);

	if (functionSymbol != NULL) {
		result = callPlatformFunction(functionSymbol, waitForFunction,
		    param1, param2, param3, param4);
		functionSymbol->release();
	}

	return result;
}


/*
 * Accessors for global services
 */

IOPlatformExpert *
IOService::getPlatform( void )
{
	return gIOPlatform;
}

class IOPMrootDomain *
	IOService::getPMRootDomain( void )
{
	return gIOPMRootDomain;
}

IOService *
IOService::getResourceService( void )
{
	return gIOResources;
}

void
IOService::setPlatform( IOPlatformExpert * platform)
{
	gIOPlatform = platform;
	gIOResources->attachToParent( gIOServiceRoot, gIOServicePlane );
	gIOUserResources->attachToParent( gIOServiceRoot, gIOServicePlane );

#if defined(__i386__) || defined(__x86_64__)

	static const char * keys[kCpuNumDelayTypes] = {
		kIOPlatformMaxBusDelay, kIOPlatformMaxInterruptDelay };
	const OSObject * objs[2];
	OSArray * array;
	uint32_t  idx;

	for (idx = 0; idx < kCpuNumDelayTypes; idx++) {
		objs[0] = sCPULatencySet[idx];
		objs[1] = sCPULatencyHolder[idx];
		array   = OSArray::withObjects(objs, 2);
		if (!array) {
			break;
		}
		platform->setProperty(keys[idx], array);
		array->release();
	}
#endif /* defined(__i386__) || defined(__x86_64__) */
}

void
IOService::setPMRootDomain( class IOPMrootDomain * rootDomain)
{
	gIOPMRootDomain = rootDomain;
	publishResource(gIOResourceIOKitKey);
	IOServicePH::init(rootDomain);
}

/*
 * Stacking change
 */

bool
IOService::lockForArbitration( bool isSuccessRequired )
{
	bool                          found;
	bool                          success;
	ArbitrationLockQueueElement * element;
	ArbitrationLockQueueElement * active;
	ArbitrationLockQueueElement * waiting;

	enum { kPutOnFreeQueue, kPutOnActiveQueue, kPutOnWaitingQueue } action;

	// lock global access
	IOTakeLock( gArbitrationLockQueueLock );

	// obtain an unused queue element
	if (!queue_empty( &gArbitrationLockQueueFree )) {
		queue_remove_first( &gArbitrationLockQueueFree,
		    element,
		    ArbitrationLockQueueElement *,
		    link );
	} else {
		element = IONew( ArbitrationLockQueueElement, 1 );
		assert( element );
	}

	// prepare the queue element
	element->thread   = IOThreadSelf();
	element->service  = this;
	element->count    = 1;
	element->required = isSuccessRequired;
	element->aborted  = false;

	// determine whether this object is already locked (ie. on active queue)
	found = false;
	queue_iterate( &gArbitrationLockQueueActive,
	    active,
	    ArbitrationLockQueueElement *,
	    link )
	{
		if (active->service == element->service) {
			found = true;
			break;
		}
	}

	if (found) { // this object is already locked
		// determine whether it is the same or a different thread trying to lock
		if (active->thread != element->thread) { // it is a different thread
			ArbitrationLockQueueElement * victim = NULL;

			// before placing this new thread on the waiting queue, we look for
			// a deadlock cycle...

			while (1) {
				// determine whether the active thread holding the object we
				// want is waiting for another object to be unlocked
				found = false;
				queue_iterate( &gArbitrationLockQueueWaiting,
				    waiting,
				    ArbitrationLockQueueElement *,
				    link )
				{
					if (waiting->thread == active->thread) {
						assert( false == waiting->aborted );
						found = true;
						break;
					}
				}

				if (found) { // yes, active thread waiting for another object
					// this may be a candidate for rejection if the required
					// flag is not set, should we detect a deadlock later on
					if (false == waiting->required) {
						victim = waiting;
					}

					// find the thread that is holding this other object, that
					// is blocking the active thread from proceeding (fun :-)
					found = false;
					queue_iterate( &gArbitrationLockQueueActive,
					    active, // (reuse active queue element)
					    ArbitrationLockQueueElement *,
					    link )
					{
						if (active->service == waiting->service) {
							found = true;
							break;
						}
					}

					// someone must be holding it or it wouldn't be waiting
					assert( found );

					if (active->thread == element->thread) {
						// doh, it's waiting for the thread that originated
						// this whole lock (ie. current thread) -> deadlock
						if (false == element->required) { // willing to fail?
							// the originating thread doesn't have the required
							// flag, so it can fail
							success = false; // (fail originating lock request)
							break; // (out of while)
						} else { // originating thread is not willing to fail
							// see if we came across a waiting thread that did
							// not have the 'required' flag set: we'll fail it
							if (victim) {
								// we do have a willing victim, fail it's lock
								victim->aborted = true;

								// take the victim off the waiting queue
								queue_remove( &gArbitrationLockQueueWaiting,
								    victim,
								    ArbitrationLockQueueElement *,
								    link );

								// wake the victim
								IOLockWakeup( gArbitrationLockQueueLock,
								    victim,
								    /* one thread */ true );

								// allow this thread to proceed (ie. wait)
								success = true; // (put request on wait queue)
								break; // (out of while)
							} else {
								// all the waiting threads we came across in
								// finding this loop had the 'required' flag
								// set, so we've got a deadlock we can't avoid
								panic("I/O Kit: Unrecoverable deadlock.");
							}
						}
					} else {
						// repeat while loop, redefining active thread to be the
						// thread holding "this other object" (see above), and
						// looking for threads waiting on it; note the active
						// variable points to "this other object" already... so
						// there nothing to do in this else clause.
					}
				} else { // no, active thread is not waiting for another object
					success = true; // (put request on wait queue)
					break; // (out of while)
				}
			} // while forever

			if (success) { // put the request on the waiting queue?
				kern_return_t wait_result;

				// place this thread on the waiting queue and put it to sleep;
				// we place it at the tail of the queue...
				queue_enter( &gArbitrationLockQueueWaiting,
				    element,
				    ArbitrationLockQueueElement *,
				    link );

				// declare that this thread will wait for a given event
restart_sleep:                  wait_result = assert_wait( element,
				    element->required ? THREAD_UNINT
				    : THREAD_INTERRUPTIBLE );

				// unlock global access
				IOUnlock( gArbitrationLockQueueLock );

				// put thread to sleep, waiting for our event to fire...
				if (wait_result == THREAD_WAITING) {
					wait_result = thread_block(THREAD_CONTINUE_NULL);
				}


				// ...and we've been woken up; we might be in one of two states:
				// (a) we've been aborted and our queue element is not on
				//     any of the three queues, but is floating around
				// (b) we're allowed to proceed with the lock and we have
				//     already been moved from the waiting queue to the
				//     active queue.
				// ...plus a 3rd state, should the thread have been interrupted:
				// (c) we're still on the waiting queue

				// determine whether we were interrupted out of our sleep
				if (THREAD_INTERRUPTED == wait_result) {
					// re-lock global access
					IOTakeLock( gArbitrationLockQueueLock );

					// determine whether we're still on the waiting queue
					found = false;
					queue_iterate( &gArbitrationLockQueueWaiting,
					    waiting, // (reuse waiting queue element)
					    ArbitrationLockQueueElement *,
					    link )
					{
						if (waiting == element) {
							found = true;
							break;
						}
					}

					if (found) { // yes, we're still on the waiting queue
						// determine whether we're willing to fail
						if (false == element->required) {
							// mark us as aborted
							element->aborted = true;

							// take us off the waiting queue
							queue_remove( &gArbitrationLockQueueWaiting,
							    element,
							    ArbitrationLockQueueElement *,
							    link );
						} else { // we are not willing to fail
							// ignore interruption, go back to sleep
							goto restart_sleep;
						}
					}

					// unlock global access
					IOUnlock( gArbitrationLockQueueLock );

					// proceed as though this were a normal wake up
					wait_result = THREAD_AWAKENED;
				}

				assert( THREAD_AWAKENED == wait_result );

				// determine whether we've been aborted while we were asleep
				if (element->aborted) {
					assert( false == element->required );

					// re-lock global access
					IOTakeLock( gArbitrationLockQueueLock );

					action = kPutOnFreeQueue;
					success = false;
				} else { // we weren't aborted, so we must be ready to go :-)
					// we've already been moved from waiting to active queue
					return true;
				}
			} else { // the lock request is to be failed
				// return unused queue element to queue
				action = kPutOnFreeQueue;
			}
		} else { // it is the same thread, recursive access is allowed
			// add one level of recursion
			active->count++;

			// return unused queue element to queue
			action = kPutOnFreeQueue;
			success = true;
		}
	} else { // this object is not already locked, so let this thread through
		action = kPutOnActiveQueue;
		success = true;
	}

	// put the new element on a queue
	if (kPutOnActiveQueue == action) {
		queue_enter( &gArbitrationLockQueueActive,
		    element,
		    ArbitrationLockQueueElement *,
		    link );
	} else if (kPutOnFreeQueue == action) {
		queue_enter( &gArbitrationLockQueueFree,
		    element,
		    ArbitrationLockQueueElement *,
		    link );
	} else {
		assert( 0 ); // kPutOnWaitingQueue never occurs, handled specially above
	}

	// unlock global access
	IOUnlock( gArbitrationLockQueueLock );

	return success;
}

void
IOService::unlockForArbitration( void )
{
	bool                          found;
	ArbitrationLockQueueElement * element;

	// lock global access
	IOTakeLock( gArbitrationLockQueueLock );

	// find the lock element for this object (ie. on active queue)
	found = false;
	queue_iterate( &gArbitrationLockQueueActive,
	    element,
	    ArbitrationLockQueueElement *,
	    link )
	{
		if (element->service == this) {
			found = true;
			break;
		}
	}

	assert( found );

	// determine whether the lock has been taken recursively
	if (element->count > 1) {
		// undo one level of recursion
		element->count--;
	} else {
		// remove it from the active queue
		queue_remove( &gArbitrationLockQueueActive,
		    element,
		    ArbitrationLockQueueElement *,
		    link );

		// put it on the free queue
		queue_enter( &gArbitrationLockQueueFree,
		    element,
		    ArbitrationLockQueueElement *,
		    link );

		// determine whether a thread is waiting for object (head to tail scan)
		found = false;
		queue_iterate( &gArbitrationLockQueueWaiting,
		    element,
		    ArbitrationLockQueueElement *,
		    link )
		{
			if (element->service == this) {
				found = true;
				break;
			}
		}

		if (found) { // we found an interested thread on waiting queue
			// remove it from the waiting queue
			queue_remove( &gArbitrationLockQueueWaiting,
			    element,
			    ArbitrationLockQueueElement *,
			    link );

			// put it on the active queue
			queue_enter( &gArbitrationLockQueueActive,
			    element,
			    ArbitrationLockQueueElement *,
			    link );

			// wake the waiting thread
			IOLockWakeup( gArbitrationLockQueueLock,
			    element,
			    /* one thread */ true );
		}
	}

	// unlock global access
	IOUnlock( gArbitrationLockQueueLock );
}

uint32_t
IOService::isLockedForArbitration(IOService * service)
{
#if DEBUG_NOTIFIER_LOCKED
	uint32_t                      count;
	ArbitrationLockQueueElement * active;

	// lock global access
	IOLockLock(gArbitrationLockQueueLock);

	// determine whether this object is already locked (ie. on active queue)
	count = 0;
	queue_iterate(&gArbitrationLockQueueActive,
	    active,
	    ArbitrationLockQueueElement *,
	    link)
	{
		if ((active->thread == IOThreadSelf())
		    && (!service || (active->service == service))) {
			count += 0x10000;
			count += active->count;
		}
	}

	IOLockUnlock(gArbitrationLockQueueLock);

	return count;

#else /* DEBUG_NOTIFIER_LOCKED */

	return 0;

#endif /* DEBUG_NOTIFIER_LOCKED */
}

void
IOService::applyToProviders( IOServiceApplierFunction applier,
    void * context )
{
	applyToParents((IORegistryEntryApplierFunction) applier,
	    context, gIOServicePlane );
}

void
IOService::applyToClients( IOServiceApplierFunction applier,
    void * context )
{
	applyToChildren((IORegistryEntryApplierFunction) applier,
	    context, gIOServicePlane );
}


/*
 * Client messages
 */


// send a message to a client or interested party of this service
IOReturn
IOService::messageClient( UInt32 type, OSObject * client,
    void * argument, vm_size_t argSize )
{
	IOReturn                            ret;
	IOService *                         service;
	_IOServiceInterestNotifier *        notify;

	if ((service = OSDynamicCast( IOService, client))) {
		ret = service->message( type, this, argument );
	} else if ((notify = OSDynamicCast( _IOServiceInterestNotifier, client))) {
		_IOServiceNotifierInvocation invocation;
		bool                     willNotify;

		invocation.thread = current_thread();

		LOCKWRITENOTIFY();
		willNotify = (0 != (kIOServiceNotifyEnable & notify->state));

		if (willNotify) {
			queue_enter( &notify->handlerInvocations, &invocation,
			    _IOServiceNotifierInvocation *, link );
		}
		UNLOCKNOTIFY();

		if (willNotify) {
			ret = (*notify->handler)( notify->target, notify->ref,
			    type, this, argument, argSize );

			LOCKWRITENOTIFY();
			queue_remove( &notify->handlerInvocations, &invocation,
			    _IOServiceNotifierInvocation *, link );
			if (kIOServiceNotifyWaiter & notify->state) {
				notify->state &= ~kIOServiceNotifyWaiter;
				WAKEUPNOTIFY( notify );
			}
			UNLOCKNOTIFY();
		} else {
			ret = kIOReturnSuccess;
		}
	} else {
		ret = kIOReturnBadArgument;
	}

	return ret;
}

static void
applyToInterestNotifiers(const IORegistryEntry *target,
    const OSSymbol * typeOfInterest,
    OSObjectApplierFunction applier,
    void * context )
{
	OSArray *  copyArray = NULL;
	OSObject * prop;

	LOCKREADNOTIFY();

	prop = target->copyProperty(typeOfInterest);
	IOCommand *notifyList = OSDynamicCast(IOCommand, prop);

	if (notifyList) {
		copyArray = OSArray::withCapacity(1);

		// iterate over queue, entry is set to each element in the list
		iterqueue(&notifyList->fCommandChain, entry) {
			_IOServiceInterestNotifier * notify;

			queue_element(entry, notify, _IOServiceInterestNotifier *, chain);
			copyArray->setObject(notify);
		}
	}
	UNLOCKNOTIFY();

	if (copyArray) {
		unsigned int    index;
		OSObject *      next;

		for (index = 0; (next = copyArray->getObject( index )); index++) {
			(*applier)(next, context);
		}
		copyArray->release();
	}

	OSSafeReleaseNULL(prop);
}

void
IOService::applyToInterested( const OSSymbol * typeOfInterest,
    OSObjectApplierFunction applier,
    void * context )
{
	if (gIOGeneralInterest == typeOfInterest) {
		applyToClients((IOServiceApplierFunction) applier, context );
	}
	applyToInterestNotifiers(this, typeOfInterest, applier, context);
}

struct MessageClientsContext {
	IOService * service;
	UInt32      type;
	void *      argument;
	vm_size_t   argSize;
	IOReturn    ret;
};

static void
messageClientsApplier( OSObject * object, void * ctx )
{
	IOReturn                ret;
	MessageClientsContext * context = (MessageClientsContext *) ctx;

	ret = context->service->messageClient( context->type,
	    object, context->argument, context->argSize );
	if (kIOReturnSuccess != ret) {
		context->ret = ret;
	}
}

// send a message to all clients
IOReturn
IOService::messageClients( UInt32 type,
    void * argument, vm_size_t argSize )
{
	MessageClientsContext       context;

	context.service     = this;
	context.type        = type;
	context.argument    = argument;
	context.argSize     = argSize;
	context.ret         = kIOReturnSuccess;

	applyToInterested( gIOGeneralInterest,
	    &messageClientsApplier, &context );

	return context.ret;
}

IOReturn
IOService::acknowledgeNotification( IONotificationRef notification,
    IOOptionBits response )
{
	return kIOReturnUnsupported;
}

IONotifier *
IOService::registerInterest( const OSSymbol * typeOfInterest,
    IOServiceInterestHandler handler, void * target, void * ref )
{
	_IOServiceInterestNotifier * notify = NULL;
	IOReturn rc = kIOReturnError;

	notify = new _IOServiceInterestNotifier;
	if (!notify) {
		return NULL;
	}

	if (notify->init()) {
		rc = registerInterestForNotifier(notify, typeOfInterest,
		    handler, target, ref);
	}

	if (rc != kIOReturnSuccess) {
		notify->release();
		notify = NULL;
	}

	return notify;
}



static IOReturn
IOServiceInterestHandlerToBlock( void * target __unused, void * refCon,
    UInt32 messageType, IOService * provider,
    void * messageArgument, vm_size_t argSize )
{
	return ((IOServiceInterestHandlerBlock) refCon)(messageType, provider, messageArgument, argSize);
}

IONotifier *
IOService::registerInterest(const OSSymbol * typeOfInterest,
    IOServiceInterestHandlerBlock handler)
{
	IONotifier * notify;
	void       * block;

	block = Block_copy(handler);
	if (!block) {
		return NULL;
	}

	notify = registerInterest(typeOfInterest, &IOServiceInterestHandlerToBlock, NULL, block);

	if (!notify) {
		Block_release(block);
	}

	return notify;
}

IOReturn
IOService::registerInterestForNotifier( IONotifier *svcNotify, const OSSymbol * typeOfInterest,
    IOServiceInterestHandler handler, void * target, void * ref )
{
	IOReturn rc = kIOReturnSuccess;
	_IOServiceInterestNotifier  *notify = NULL;

	if (!svcNotify || !(notify = OSDynamicCast(_IOServiceInterestNotifier, svcNotify))) {
		return kIOReturnBadArgument;
	}

	notify->handler = handler;
	notify->target = target;
	notify->ref = ref;

	if ((typeOfInterest != gIOGeneralInterest)
	    && (typeOfInterest != gIOBusyInterest)
	    && (typeOfInterest != gIOAppPowerStateInterest)
	    && (typeOfInterest != gIOConsoleSecurityInterest)
	    && (typeOfInterest != gIOPriorityPowerStateInterest)) {
		return kIOReturnBadArgument;
	}

	lockForArbitration();
	if (0 == (__state[0] & kIOServiceInactiveState)) {
		notify->state = kIOServiceNotifyEnable;

		////// queue

		LOCKWRITENOTIFY();

		// Get the head of the notifier linked list
		IOCommand * notifyList;
		OSObject  * obj = copyProperty( typeOfInterest );
		if (!(notifyList = OSDynamicCast(IOCommand, obj))) {
			notifyList = OSTypeAlloc(IOCommand);
			if (notifyList) {
				notifyList->init();
				bool ok = setProperty( typeOfInterest, notifyList);
				notifyList->release();
				if (!ok) {
					notifyList = NULL;
				}
			}
		}
		if (obj) {
			obj->release();
		}

		if (notifyList) {
			enqueue(&notifyList->fCommandChain, &notify->chain);
			notify->retain(); // ref'ed while in list
		}

		UNLOCKNOTIFY();
	} else {
		rc = kIOReturnNotReady;
	}
	unlockForArbitration();

	return rc;
}

static void
cleanInterestList( OSObject * head )
{
	IOCommand *notifyHead = OSDynamicCast(IOCommand, head);
	if (!notifyHead) {
		return;
	}

	LOCKWRITENOTIFY();
	while (queue_entry_t entry = dequeue(&notifyHead->fCommandChain)) {
		queue_next(entry) = queue_prev(entry) = NULL;

		_IOServiceInterestNotifier * notify;

		queue_element(entry, notify, _IOServiceInterestNotifier *, chain);
		notify->release();
	}
	UNLOCKNOTIFY();
}

void
IOService::unregisterAllInterest( void )
{
	OSObject * prop;

	prop = copyProperty(gIOGeneralInterest);
	cleanInterestList(prop);
	OSSafeReleaseNULL(prop);

	prop = copyProperty(gIOBusyInterest);
	cleanInterestList(prop);
	OSSafeReleaseNULL(prop);

	prop = copyProperty(gIOAppPowerStateInterest);
	cleanInterestList(prop);
	OSSafeReleaseNULL(prop);

	prop = copyProperty(gIOPriorityPowerStateInterest);
	cleanInterestList(prop);
	OSSafeReleaseNULL(prop);

	prop = copyProperty(gIOConsoleSecurityInterest);
	cleanInterestList(prop);
	OSSafeReleaseNULL(prop);
}

/*
 * _IOServiceInterestNotifier
 */

// wait for all threads, other than the current one,
//  to exit the handler

void
_IOServiceInterestNotifier::wait()
{
	_IOServiceNotifierInvocation * next;
	bool doWait;

	do {
		doWait = false;
		queue_iterate( &handlerInvocations, next,
		    _IOServiceNotifierInvocation *, link) {
			if (next->thread != current_thread()) {
				doWait = true;
				break;
			}
		}
		if (doWait) {
			state |= kIOServiceNotifyWaiter;
			SLEEPNOTIFY(this);
		}
	} while (doWait);
}

void
_IOServiceInterestNotifier::free()
{
	assert( queue_empty( &handlerInvocations ));

	if (handler == &IOServiceInterestHandlerToBlock) {
		Block_release(ref);
	}

	OSObject::free();
}

void
_IOServiceInterestNotifier::remove()
{
	LOCKWRITENOTIFY();

	if (queue_next( &chain )) {
		remqueue(&chain);
		queue_next( &chain) = queue_prev( &chain) = NULL;
		release();
	}

	state &= ~kIOServiceNotifyEnable;

	wait();

	UNLOCKNOTIFY();

	release();
}

bool
_IOServiceInterestNotifier::disable()
{
	bool        ret;

	LOCKWRITENOTIFY();

	ret = (0 != (kIOServiceNotifyEnable & state));
	state &= ~kIOServiceNotifyEnable;
	if (ret) {
		wait();
	}

	UNLOCKNOTIFY();

	return ret;
}

void
_IOServiceInterestNotifier::enable( bool was )
{
	LOCKWRITENOTIFY();
	if (was) {
		state |= kIOServiceNotifyEnable;
	} else {
		state &= ~kIOServiceNotifyEnable;
	}
	UNLOCKNOTIFY();
}

bool
_IOServiceInterestNotifier::init()
{
	queue_init( &handlerInvocations );
	return OSObject::init();
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Termination
 */

#define tailQ(o)                setObject(o)
#define headQ(o)                setObject(0, o)
#define TLOG(fmt, args...)      { if(kIOLogYield & gIOKitDebug) { IOLog("[%llx] ", thread_tid(current_thread())); IOLog(fmt, ## args); }}

static void
_workLoopAction( IOWorkLoop::Action action,
    IOService * service,
    void * p0 = NULL, void * p1 = NULL,
    void * p2 = NULL, void * p3 = NULL )
{
	IOWorkLoop * wl;

	if ((wl = service->getWorkLoop())) {
		wl->retain();
		wl->runAction( action, service, p0, p1, p2, p3 );
		wl->release();
	} else {
		(*action)( service, p0, p1, p2, p3 );
	}
}

bool
IOService::requestTerminate( IOService * provider, IOOptionBits options )
{
	bool ok;

	// if its our only provider
	ok = isParent( provider, gIOServicePlane, true);

	// -- compat
	if (ok) {
		provider->terminateClient( this, options | kIOServiceRecursing );
		ok = (0 != (kIOServiceInactiveState & __state[0]));
	}
	// --

	return ok;
}

bool
IOService::terminatePhase1( IOOptionBits options )
{
	IOService *  victim;
	IOService *  client;
	IOService *  rematchProvider;
	OSIterator * iter;
	OSArray *    makeInactive;
	OSArray *    waitingInactive;
	IOOptionBits callerOptions;
	int          waitResult = THREAD_AWAKENED;
	bool         wait;
	bool                 ok;
	bool                 didInactive;
	bool                 startPhase2 = false;

	TLOG("%s[0x%qx]::terminatePhase1(%08llx)\n", getName(), getRegistryEntryID(), (long long)options);

	callerOptions = options;
	rematchProvider = NULL;
	uint64_t regID = getRegistryEntryID();
	IOServiceTrace(
		IOSERVICE_TERMINATE_PHASE1,
		(uintptr_t) regID,
		(uintptr_t) (regID >> 32),
		(uintptr_t) this,
		(uintptr_t) options);

	// -- compat
	if (options & kIOServiceRecursing) {
		lockForArbitration();
		if (0 == (kIOServiceInactiveState & __state[0])) {
			__state[0] |= kIOServiceInactiveState;
			__state[1] |= kIOServiceRecursing | kIOServiceTermPhase1State;
		}
		unlockForArbitration();

		return true;
	}
	// --

	makeInactive    = OSArray::withCapacity( 16 );
	waitingInactive = OSArray::withCapacity( 16 );
	if (!makeInactive || !waitingInactive) {
		return false;
	}

	victim = this;
	victim->retain();

	while (victim) {
		didInactive = victim->lockForArbitration( true );
		if (didInactive) {
			uint64_t regID1 = victim->getRegistryEntryID();
			IOServiceTrace(IOSERVICE_TERM_SET_INACTIVE,
			    (uintptr_t) regID1,
			    (uintptr_t) (regID1 >> 32),
			    (uintptr_t) victim->__state[1],
			    (uintptr_t) 0);

			enum { kRP1 = kIOServiceRecursing | kIOServiceTermPhase1State };
			didInactive = (kRP1 == (victim->__state[1] & kRP1))
			    || (0 == (victim->__state[0] & kIOServiceInactiveState));

			if (!didInactive) {
				// a multiply attached IOService can be visited twice
				if (-1U == waitingInactive->getNextIndexOfObject(victim, 0)) {
					do{
						IOLockLock(gIOServiceBusyLock);
						wait = (victim->__state[1] & kIOServiceTermPhase1State);
						if (wait) {
							TLOG("%s[0x%qx]::waitPhase1(%s[0x%qx])\n",
							    getName(), getRegistryEntryID(), victim->getName(), victim->getRegistryEntryID());
							victim->__state[1] |= kIOServiceTerm1WaiterState;
							victim->unlockForArbitration();
							assert_wait((event_t)&victim->__state[1], THREAD_UNINT);
						}
						IOLockUnlock(gIOServiceBusyLock);
						if (wait) {
							waitResult = thread_block(THREAD_CONTINUE_NULL);
							TLOG("%s[0x%qx]::did waitPhase1(%s[0x%qx])\n",
							    getName(), getRegistryEntryID(), victim->getName(), victim->getRegistryEntryID());
							victim->lockForArbitration();
						}
					}while (wait && (waitResult != THREAD_TIMED_OUT));
				}
			} else {
				victim->__state[0] |= kIOServiceInactiveState;
				victim->__state[0] &= ~(kIOServiceRegisteredState | kIOServiceMatchedState
				    | kIOServiceFirstPublishState | kIOServiceFirstMatchState);
				victim->__state[1] &= ~kIOServiceRecursing;
				victim->__state[1] |= kIOServiceTermPhase1State;
				waitingInactive->headQ(victim);
				if (victim == this) {
					if (kIOServiceTerminateNeedWillTerminate & options) {
						victim->__state[1] |= kIOServiceNeedWillTerminate;
					}
				}
				victim->_adjustBusy( 1 );

				if ((options & kIOServiceTerminateWithRematch) && (victim == this)) {
					OSObject     * obj;
					OSObject     * rematchProps;
					OSNumber     * num;
					uint32_t       count;

					rematchProvider = getProvider();
					if (rematchProvider) {
						obj = rematchProvider->copyProperty(gIORematchCountKey);
						num = OSDynamicCast(OSNumber, obj);
						count = 0;
						if (num) {
							count = num->unsigned32BitValue();
							count++;
						}
						num = OSNumber::withNumber(count, 32);
						rematchProvider->setProperty(gIORematchCountKey, num);
						rematchProps = copyProperty(gIOMatchedPersonalityKey);
						rematchProvider->setProperty(gIORematchPersonalityKey, rematchProps);
						OSSafeReleaseNULL(num);
						OSSafeReleaseNULL(rematchProps);
						OSSafeReleaseNULL(obj);
					}
				}
			}
			victim->unlockForArbitration();
		}
		if (victim == this) {
			options &= ~kIOServiceTerminateWithRematch;
			startPhase2 = didInactive;
		}
		if (didInactive) {
			OSArray * notifiers;
			notifiers = victim->copyNotifiers(gIOTerminatedNotification, 0, 0xffffffff);
			victim->invokeNotifiers(&notifiers);

			IOUserClient::destroyUserReferences( victim );

			iter = victim->getClientIterator();
			if (iter) {
				while ((client = (IOService *) iter->getNextObject())) {
					TLOG("%s[0x%qx]::requestTerminate(%s[0x%qx], %08llx)\n",
					    client->getName(), client->getRegistryEntryID(),
					    victim->getName(), victim->getRegistryEntryID(), (long long)options);
					ok = client->requestTerminate( victim, options );
					TLOG("%s[0x%qx]::requestTerminate(%s[0x%qx], ok = %d)\n",
					    client->getName(), client->getRegistryEntryID(),
					    victim->getName(), victim->getRegistryEntryID(), ok);

					uint64_t regID1 = client->getRegistryEntryID();
					uint64_t regID2 = victim->getRegistryEntryID();
					IOServiceTrace(
						(ok ? IOSERVICE_TERMINATE_REQUEST_OK
						: IOSERVICE_TERMINATE_REQUEST_FAIL),
						(uintptr_t) regID1,
						(uintptr_t) (regID1 >> 32),
						(uintptr_t) regID2,
						(uintptr_t) (regID2 >> 32));

					if (ok) {
						makeInactive->setObject( client );
					}
				}
				iter->release();
			}
		}
		victim->release();
		victim = (IOService *) makeInactive->getObject(0);
		if (victim) {
			victim->retain();
			makeInactive->removeObject(0);
		}
	}
	makeInactive->release();

	while ((victim = (IOService *) waitingInactive->getObject(0))) {
		victim->retain();
		waitingInactive->removeObject(0);

		victim->lockForArbitration();
		victim->__state[1] &= ~kIOServiceTermPhase1State;
		if (kIOServiceTerm1WaiterState & victim->__state[1]) {
			victim->__state[1] &= ~kIOServiceTerm1WaiterState;
			TLOG("%s[0x%qx]::wakePhase1\n", victim->getName(), victim->getRegistryEntryID());
			IOLockLock( gIOServiceBusyLock );
			thread_wakeup((event_t) &victim->__state[1]);
			IOLockUnlock( gIOServiceBusyLock );
		}
		victim->unlockForArbitration();
		victim->release();
	}
	waitingInactive->release();

	if (startPhase2) {
		retain();
		lockForArbitration();
		scheduleTerminatePhase2(options);
		unlockForArbitration();
		release();
	}

	if (rematchProvider) {
		DKLOG(DKS " rematching after dext crash\n", DKN(rematchProvider));
		rematchProvider->registerService();
	}

	return true;
}

void
IOService::setTerminateDefer(IOService * provider, bool defer)
{
	lockForArbitration();
	if (defer) {
		__state[1] |= kIOServiceStartState;
	} else {
		__state[1] &= ~kIOServiceStartState;
	}
	unlockForArbitration();

	if (provider && !defer) {
		provider->lockForArbitration();
		provider->scheduleTerminatePhase2();
		provider->unlockForArbitration();
	}
}

// Must call this while holding gJobsLock
void
IOService::waitToBecomeTerminateThread(void)
{
	IOLockAssert(gJobsLock, kIOLockAssertOwned);
	bool wait;
	do {
		wait = (gIOTerminateThread != THREAD_NULL);
		if (wait) {
			IOLockSleep(gJobsLock, &gIOTerminateThread, THREAD_UNINT);
		}
	} while (wait);
	gIOTerminateThread = current_thread();
}

// call with lockForArbitration
void
IOService::scheduleTerminatePhase2( IOOptionBits options )
{
	AbsoluteTime        deadline;
	uint64_t            regID1;
	int                 waitResult = THREAD_AWAKENED;
	bool                wait = false, haveDeadline = false;

	if (!(__state[0] & kIOServiceInactiveState)) {
		return;
	}

	regID1 = getRegistryEntryID();
	IOServiceTrace(
		IOSERVICE_TERM_SCHED_PHASE2,
		(uintptr_t) regID1,
		(uintptr_t) (regID1 >> 32),
		(uintptr_t) __state[1],
		(uintptr_t) options);

	if (__state[1] & kIOServiceTermPhase1State) {
		return;
	}

	retain();
	unlockForArbitration();
	options |= kIOServiceRequired;
	IOLockLock( gJobsLock );

	if ((options & kIOServiceSynchronous)
	    && (current_thread() != gIOTerminateThread)) {
		waitToBecomeTerminateThread();
		gIOTerminatePhase2List->setObject( this );
		gIOTerminateWork++;

		do {
			while (gIOTerminateWork) {
				terminateWorker( options );
			}
			wait = (0 != (__state[1] & kIOServiceBusyStateMask));
			if (wait) {
				/* wait for the victim to go non-busy */
				if (!haveDeadline) {
					clock_interval_to_deadline( 15, kSecondScale, &deadline );
					haveDeadline = true;
				}
				/* let others do work while we wait */
				gIOTerminateThread = NULL;
				IOLockWakeup( gJobsLock, (event_t) &gIOTerminateThread, /* one-thread */ false);
				waitResult = IOLockSleepDeadline( gJobsLock, &gIOTerminateWork,
				    deadline, THREAD_UNINT );
				if (__improbable(waitResult == THREAD_TIMED_OUT)) {
					IOLog("%s[0x%qx]::terminate(kIOServiceSynchronous): THREAD_TIMED_OUT. "
					    "Attempting to auto-resolve your deadlock. PLEASE FIX!\n", getName(), getRegistryEntryID());
				}
				waitToBecomeTerminateThread();
			}
		} while (gIOTerminateWork || (wait && (waitResult != THREAD_TIMED_OUT)));

		gIOTerminateThread = NULL;
		IOLockWakeup( gJobsLock, (event_t) &gIOTerminateThread, /* one-thread */ false);
	} else {
		// ! kIOServiceSynchronous

		gIOTerminatePhase2List->setObject( this );
		if (0 == gIOTerminateWork++) {
			assert(gIOTerminateWorkerThread);
			IOLockWakeup(gJobsLock, (event_t)&gIOTerminateWork, /* one-thread */ false );
		}
	}

	IOLockUnlock( gJobsLock );
	lockForArbitration();
	release();
}

__attribute__((__noreturn__))
void
IOService::terminateThread( void * arg, wait_result_t waitResult )
{
	// IOLockSleep re-acquires the lock on wakeup, so we only need to do this once
	IOLockLock(gJobsLock);
	while (true) {
		if (gIOTerminateThread != gIOTerminateWorkerThread) {
			waitToBecomeTerminateThread();
		}

		while (gIOTerminateWork) {
			terminateWorker((uintptr_t)arg );
		}

		gIOTerminateThread = NULL;
		IOLockWakeup( gJobsLock, (event_t) &gIOTerminateThread, /* one-thread */ false);
		IOLockSleep(gJobsLock, &gIOTerminateWork, THREAD_UNINT);
	}
}

void
IOService::scheduleStop( IOService * provider )
{
	uint64_t regID1 = getRegistryEntryID();
	uint64_t regID2 = provider->getRegistryEntryID();

	TLOG("%s[0x%qx]::scheduleStop(%s[0x%qx])\n", getName(), regID1, provider->getName(), regID2);
	IOServiceTrace(
		IOSERVICE_TERMINATE_SCHEDULE_STOP,
		(uintptr_t) regID1,
		(uintptr_t) (regID1 >> 32),
		(uintptr_t) regID2,
		(uintptr_t) (regID2 >> 32));

	IOLockLock( gJobsLock );
	gIOStopList->tailQ( this );
	gIOStopProviderList->tailQ( provider );

	if (0 == gIOTerminateWork++) {
		assert(gIOTerminateWorkerThread);
		IOLockWakeup(gJobsLock, (event_t)&gIOTerminateWork, /* one-thread */ false );
	}

	IOLockUnlock( gJobsLock );
}

void
IOService::scheduleFinalize(bool now)
{
	uint64_t regID1 = getRegistryEntryID();

	TLOG("%s[0x%qx]::scheduleFinalize\n", getName(), regID1);
	IOServiceTrace(
		IOSERVICE_TERMINATE_SCHEDULE_FINALIZE,
		(uintptr_t) regID1,
		(uintptr_t) (regID1 >> 32),
		0, 0);

	if (now || IOUserClient::finalizeUserReferences(this)) {
		IOLockLock( gJobsLock );
		gIOFinalizeList->tailQ(this);
		if (0 == gIOTerminateWork++) {
			assert(gIOTerminateWorkerThread);
			IOLockWakeup(gJobsLock, (event_t)&gIOTerminateWork, /* one-thread */ false );
		}
		IOLockUnlock( gJobsLock );
	}
}

bool
IOService::willTerminate( IOService * provider, IOOptionBits options )
{
	if (reserved->uvars) {
		IOUserServer::serviceWillTerminate(this, provider, options);
	}
	return true;
}

bool
IOService::didTerminate( IOService * provider, IOOptionBits options, bool * defer )
{
	if (reserved->uvars) {
		IOUserServer::serviceDidTerminate(this, provider, options, defer);
	}

	if (false == *defer) {
		if (lockForArbitration( true )) {
			if (false == provider->handleIsOpen( this )) {
				scheduleStop( provider );
			}
			// -- compat
			else {
				message( kIOMessageServiceIsRequestingClose, provider, (void *)(uintptr_t) options );
				if (false == provider->handleIsOpen( this )) {
					scheduleStop( provider );
				}
			}
			// --
			unlockForArbitration();
		}
	}

	return true;
}

void
IOService::actionWillTerminate( IOService * victim, IOOptionBits options,
    OSArray * doPhase2List,
    bool user,
    void *unused3 __unused)
{
	OSIterator * iter;
	IOService *  client;
	bool         ok;
	uint64_t     regID1, regID2 = victim->getRegistryEntryID();

	iter = victim->getClientIterator();
	if (iter) {
		while ((client = (IOService *) iter->getNextObject())) {
			if (user != (NULL != client->reserved->uvars)) {
				continue;
			}
			regID1 = client->getRegistryEntryID();
			TLOG("%s[0x%qx]::willTerminate(%s[0x%qx], %08llx)\n",
			    client->getName(), regID1,
			    victim->getName(), regID2, (long long)options);
			IOServiceTrace(
				IOSERVICE_TERMINATE_WILL,
				(uintptr_t) regID1,
				(uintptr_t) (regID1 >> 32),
				(uintptr_t) regID2,
				(uintptr_t) (regID2 >> 32));

			ok = client->willTerminate( victim, options );
			doPhase2List->tailQ( client );
		}
		iter->release();
	}
}

void
IOService::actionDidTerminate( IOService * victim, IOOptionBits options,
    void *unused1 __unused, void *unused2 __unused,
    void *unused3 __unused )
{
	OSIterator * iter;
	IOService *  client;
	bool         defer;
	uint64_t     regID1, regID2 = victim->getRegistryEntryID();

	victim->messageClients( kIOMessageServiceIsTerminated, (void *)(uintptr_t) options );

	iter = victim->getClientIterator();
	if (iter) {
		while ((client = (IOService *) iter->getNextObject())) {
			regID1 = client->getRegistryEntryID();
			TLOG("%s[0x%qx]::didTerminate(%s[0x%qx], %08llx)\n",
			    client->getName(), regID1,
			    victim->getName(), regID2, (long long)options);
			defer = false;
			client->didTerminate( victim, options, &defer );

			IOServiceTrace(
				(defer ? IOSERVICE_TERMINATE_DID_DEFER
				: IOSERVICE_TERMINATE_DID),
				(uintptr_t) regID1,
				(uintptr_t) (regID1 >> 32),
				(uintptr_t) regID2,
				(uintptr_t) (regID2 >> 32));

			TLOG("%s[0x%qx]::didTerminate(%s[0x%qx], defer %d)\n",
			    client->getName(), regID1,
			    victim->getName(), regID2, defer);
		}
		iter->release();
	}
}


void
IOService::actionWillStop( IOService * victim, IOOptionBits options,
    void *unused1 __unused, void *unused2 __unused,
    void *unused3 __unused )
{
	OSIterator * iter;
	IOService *  provider;
	bool         ok;
	uint64_t     regID1, regID2 = victim->getRegistryEntryID();

	iter = victim->getProviderIterator();
	if (iter) {
		while ((provider = (IOService *) iter->getNextObject())) {
			regID1 = provider->getRegistryEntryID();
			TLOG("%s[0x%qx]::willTerminate(%s[0x%qx], %08llx)\n",
			    victim->getName(), regID2,
			    provider->getName(), regID1, (long long)options);
			IOServiceTrace(
				IOSERVICE_TERMINATE_WILL,
				(uintptr_t) regID2,
				(uintptr_t) (regID2 >> 32),
				(uintptr_t) regID1,
				(uintptr_t) (regID1 >> 32));

			ok = victim->willTerminate( provider, options );
		}
		iter->release();
	}
}

void
IOService::actionDidStop( IOService * victim, IOOptionBits options,
    void *unused1 __unused, void *unused2 __unused,
    void *unused3 __unused )
{
	OSIterator * iter;
	IOService *  provider;
	bool defer = false;
	uint64_t     regID1, regID2 = victim->getRegistryEntryID();

	iter = victim->getProviderIterator();
	if (iter) {
		while ((provider = (IOService *) iter->getNextObject())) {
			regID1 = provider->getRegistryEntryID();
			TLOG("%s[0x%qx]::didTerminate(%s[0x%qx], %08llx)\n",
			    victim->getName(), regID2,
			    provider->getName(), regID1, (long long)options);
			victim->didTerminate( provider, options, &defer );

			IOServiceTrace(
				(defer ? IOSERVICE_TERMINATE_DID_DEFER
				: IOSERVICE_TERMINATE_DID),
				(uintptr_t) regID2,
				(uintptr_t) (regID2 >> 32),
				(uintptr_t) regID1,
				(uintptr_t) (regID1 >> 32));

			TLOG("%s[0x%qx]::didTerminate(%s[0x%qx], defer %d)\n",
			    victim->getName(), regID2,
			    provider->getName(), regID1, defer);
		}
		iter->release();
	}
}


void
IOService::actionFinalize( IOService * victim, IOOptionBits options,
    void *unused1 __unused, void *unused2 __unused,
    void *unused3 __unused )
{
	uint64_t regID1 = victim->getRegistryEntryID();
	TLOG("%s[0x%qx]::finalize(%08llx)\n", victim->getName(), regID1, (long long)options);
	IOServiceTrace(
		IOSERVICE_TERMINATE_FINALIZE,
		(uintptr_t) regID1,
		(uintptr_t) (regID1 >> 32),
		0, 0);

	victim->finalize( options );
}

void
IOService::actionStop( IOService * provider, IOService * client,
    void *unused1 __unused, void *unused2 __unused,
    void *unused3 __unused )
{
	uint64_t regID1 = provider->getRegistryEntryID();
	uint64_t regID2 = client->getRegistryEntryID();

	TLOG("%s[0x%qx]::stop(%s[0x%qx])\n", client->getName(), regID2, provider->getName(), regID1);
	IOServiceTrace(
		IOSERVICE_TERMINATE_STOP,
		(uintptr_t) regID1,
		(uintptr_t) (regID1 >> 32),
		(uintptr_t) regID2,
		(uintptr_t) (regID2 >> 32));

	client->stop( provider );
	if (provider->isOpen( client )) {
		provider->close( client );
	}

	TLOG("%s[0x%qx]::detach(%s[0x%qx])\n", client->getName(), regID2, provider->getName(), regID1);
	client->detach( provider );
}

void
IOService::terminateWorker( IOOptionBits options )
{
	OSArray *           doPhase2List;
	OSArray *           didPhase2List;
	OSSet *             freeList;
	OSIterator *        iter;
	UInt32              workDone;
	IOService *         victim;
	IOService *         client;
	IOService *         provider;
	unsigned int        idx;
	bool                moreToDo;
	bool                doPhase2;
	bool                doPhase3;

	options |= kIOServiceRequired;

	doPhase2List  = OSArray::withCapacity( 16 );
	didPhase2List = OSArray::withCapacity( 16 );
	freeList      = OSSet::withCapacity( 16 );
	if ((NULL == doPhase2List) || (NULL == didPhase2List) || (NULL == freeList)) {
		return;
	}

	do {
		workDone = gIOTerminateWork;

		while ((victim = (IOService *) gIOTerminatePhase2List->getObject(0))) {
			victim->retain();
			gIOTerminatePhase2List->removeObject(0);
			IOLockUnlock( gJobsLock );

			uint64_t regID1 = victim->getRegistryEntryID();
			IOServiceTrace(
				IOSERVICE_TERM_START_PHASE2,
				(uintptr_t) regID1,
				(uintptr_t) (regID1 >> 32),
				(uintptr_t) 0,
				(uintptr_t) 0);

			while (victim) {
				doPhase2 = victim->lockForArbitration( true );
				if (doPhase2) {
					doPhase2 = (0 != (kIOServiceInactiveState & victim->__state[0]));
					if (doPhase2) {
						uint64_t regID1 = victim->getRegistryEntryID();
						IOServiceTrace(
							IOSERVICE_TERM_TRY_PHASE2,
							(uintptr_t) regID1,
							(uintptr_t) (regID1 >> 32),
							(uintptr_t) victim->__state[1],
							(uintptr_t) 0);

						doPhase2 = (0 == (victim->__state[1] &
						    (kIOServiceTermPhase1State
						    | kIOServiceTermPhase2State
						    | kIOServiceConfigState)));

						if (doPhase2 && (iter = victim->getClientIterator())) {
							while (doPhase2 && (client = (IOService *) iter->getNextObject())) {
								doPhase2 = (0 == (client->__state[1] & kIOServiceStartState));
								if (!doPhase2) {
									uint64_t regID1 = client->getRegistryEntryID();
									IOServiceTrace(
										IOSERVICE_TERM_UC_DEFER,
										(uintptr_t) regID1,
										(uintptr_t) (regID1 >> 32),
										(uintptr_t) client->__state[1],
										(uintptr_t) 0);
									TLOG("%s[0x%qx]::defer phase2(%s[0x%qx])\n",
									    victim->getName(), victim->getRegistryEntryID(),
									    client->getName(), client->getRegistryEntryID());
								}
							}
							iter->release();
						}
						if (doPhase2) {
							victim->__state[1] |= kIOServiceTermPhase2State;
						}
					}
					victim->unlockForArbitration();
				}
				if (doPhase2) {
					if (kIOServiceNeedWillTerminate & victim->__state[1]) {
						if (NULL == victim->reserved->uvars) {
							_workLoopAction((IOWorkLoop::Action) &actionWillStop,
							    victim, (void *)(uintptr_t) options);
						} else {
							actionWillStop(victim, options, NULL, NULL, NULL);
						}
					}

					OSArray * notifiers;
					notifiers = victim->copyNotifiers(gIOWillTerminateNotification, 0, 0xffffffff);
					victim->invokeNotifiers(&notifiers);

					_workLoopAction((IOWorkLoop::Action) &actionWillTerminate,
					    victim,
					    (void *)(uintptr_t) options,
					    (void *)(uintptr_t) doPhase2List,
					    (void *)(uintptr_t) false);

					actionWillTerminate(
						victim, options, doPhase2List, true, NULL);

					didPhase2List->headQ( victim );
				}
				victim->release();
				victim = (IOService *) doPhase2List->getObject(0);
				if (victim) {
					victim->retain();
					doPhase2List->removeObject(0);
				}
			}

			while ((victim = (IOService *) didPhase2List->getObject(0))) {
				bool scheduleFinalize = false;
				if (victim->lockForArbitration( true )) {
					victim->__state[1] |= kIOServiceTermPhase3State;
					scheduleFinalize = (NULL == victim->getClient());
					victim->unlockForArbitration();
				}
				_workLoopAction((IOWorkLoop::Action) &actionDidTerminate,
				    victim, (void *)(uintptr_t) options );
				if (kIOServiceNeedWillTerminate & victim->__state[1]) {
					_workLoopAction((IOWorkLoop::Action) &actionDidStop,
					    victim, (void *)(uintptr_t) options, NULL );
				}
				// no clients - will go to finalize
				if (scheduleFinalize) {
					victim->scheduleFinalize(false);
				}
				didPhase2List->removeObject(0);
			}
			IOLockLock( gJobsLock );
		}

		// phase 3
		do {
			doPhase3 = false;
			// finalize leaves
			while ((victim = (IOService *) gIOFinalizeList->getObject(0))) {
				bool sendFinal = false;
				IOLockUnlock( gJobsLock );
				if (victim->lockForArbitration(true)) {
					sendFinal = (0 == (victim->__state[1] & kIOServiceFinalized));
					if (sendFinal) {
						victim->__state[1] |= kIOServiceFinalized;
					}
					victim->unlockForArbitration();
				}
				if (sendFinal) {
					_workLoopAction((IOWorkLoop::Action) &actionFinalize,
					    victim, (void *)(uintptr_t) options );
				}
				IOLockLock( gJobsLock );
				// hold off free
				freeList->setObject( victim );
				// safe if finalize list is append only
				gIOFinalizeList->removeObject(0);
			}

			for (idx = 0;
			    (!doPhase3) && (client = (IOService *) gIOStopList->getObject(idx));) {
				provider = (IOService *) gIOStopProviderList->getObject(idx);
				assert( provider );

				uint64_t regID1 = provider->getRegistryEntryID();
				uint64_t regID2 = client->getRegistryEntryID();

				if (!provider->isChild( client, gIOServicePlane )) {
					// may be multiply queued - nop it
					TLOG("%s[0x%qx]::nop stop(%s[0x%qx])\n", client->getName(), regID2, provider->getName(), regID1);
					IOServiceTrace(
						IOSERVICE_TERMINATE_STOP_NOP,
						(uintptr_t) regID1,
						(uintptr_t) (regID1 >> 32),
						(uintptr_t) regID2,
						(uintptr_t) (regID2 >> 32));
				} else {
					// a terminated client is not ready for stop if it has clients, skip it
					bool deferStop = (0 != (kIOServiceInactiveState & client->__state[0]));
					IOLockUnlock( gJobsLock );
					if (deferStop && client->lockForArbitration(true)) {
						deferStop = (0 == (client->__state[1] & kIOServiceFinalized));
						//deferStop = (!deferStop && (0 != client->getClient()));
						//deferStop = (0 != client->getClient());
						client->unlockForArbitration();
						if (deferStop) {
							TLOG("%s[0x%qx]::defer stop()\n", client->getName(), regID2);
							IOServiceTrace(IOSERVICE_TERMINATE_STOP_DEFER,
							    (uintptr_t) regID1,
							    (uintptr_t) (regID1 >> 32),
							    (uintptr_t) regID2,
							    (uintptr_t) (regID2 >> 32));

							idx++;
							IOLockLock( gJobsLock );
							continue;
						}
					}
					_workLoopAction((IOWorkLoop::Action) &actionStop,
					    provider, (void *) client );
					IOLockLock( gJobsLock );
					// check the finalize list now
					doPhase3 = true;
				}
				// hold off free
				freeList->setObject( client );
				freeList->setObject( provider );

				// safe if stop list is append only
				gIOStopList->removeObject( idx );
				gIOStopProviderList->removeObject( idx );
				idx = 0;
			}
		} while (doPhase3);

		gIOTerminateWork -= workDone;
		moreToDo = (gIOTerminateWork != 0);

		if (!moreToDo) {
			TLOG("iokit terminate done, %d stops remain\n", gIOStopList->getCount());
			IOServiceTrace(
				IOSERVICE_TERMINATE_DONE,
				(uintptr_t) gIOStopList->getCount(), 0, 0, 0);
		}
	} while (moreToDo);

	IOLockUnlock( gJobsLock );

	freeList->release();
	doPhase2List->release();
	didPhase2List->release();

	IOLockLock( gJobsLock );
}

bool
IOService::finalize( IOOptionBits options )
{
	OSIterator *  iter;
	IOService *   provider;
	uint64_t      regID1, regID2 = getRegistryEntryID();

	iter = getProviderIterator();
	assert( iter );

	if (iter) {
		while ((provider = (IOService *) iter->getNextObject())) {
			// -- compat
			if (0 == (__state[1] & kIOServiceTermPhase3State)) {
				/* we come down here on programmatic terminate */

				regID1 = provider->getRegistryEntryID();
				TLOG("%s[0x%qx]::stop1(%s[0x%qx])\n", getName(), regID2, provider->getName(), regID1);
				IOServiceTrace(
					IOSERVICE_TERMINATE_STOP,
					(uintptr_t) regID1,
					(uintptr_t) (regID1 >> 32),
					(uintptr_t) regID2,
					(uintptr_t) (regID2 >> 32));

				stop( provider );
				if (provider->isOpen( this )) {
					provider->close( this );
				}
				detach( provider );
			} else {
				//--
				if (provider->lockForArbitration( true )) {
					if (0 == (provider->__state[1] & kIOServiceTermPhase3State)) {
						scheduleStop( provider );
					}
					provider->unlockForArbitration();
				}
			}
		}
		iter->release();
	}

	return true;
}

#undef tailQ
#undef headQ

/*
 * Terminate
 */

void
IOService::doServiceTerminate( IOOptionBits options )
{
}

// a method in case someone needs to override it
bool
IOService::terminateClient( IOService * client, IOOptionBits options )
{
	bool ok;

	if (client->isParent( this, gIOServicePlane, true)) {
		// we are the clients only provider
		ok = client->terminate( options );
	} else {
		ok = true;
	}

	return ok;
}

bool
IOService::terminate( IOOptionBits options )
{
	options |= kIOServiceTerminate;

	return terminatePhase1( options );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Open & close
 */

struct ServiceOpenMessageContext {
	IOService *  service;
	UInt32       type;
	IOService *  excludeClient;
	IOOptionBits options;
};

static void
serviceOpenMessageApplier( OSObject * object, void * ctx )
{
	ServiceOpenMessageContext * context = (ServiceOpenMessageContext *) ctx;

	if (object != context->excludeClient) {
		context->service->messageClient( context->type, object, (void *)(uintptr_t) context->options );
	}
}

bool
IOService::open(   IOService *     forClient,
    IOOptionBits    options,
    void *          arg )
{
	bool                        ok;
	ServiceOpenMessageContext   context;

	context.service             = this;
	context.type                = kIOMessageServiceIsAttemptingOpen;
	context.excludeClient       = forClient;
	context.options             = options;

	applyToInterested( gIOGeneralInterest,
	    &serviceOpenMessageApplier, &context );

	if (false == lockForArbitration(false)) {
		return false;
	}

	ok = (0 == (__state[0] & kIOServiceInactiveState));
	if (ok) {
		ok = handleOpen( forClient, options, arg );
	}

	if (ok && forClient && forClient->reserved->uvars && forClient->reserved->uvars->userServer) {
		forClient->reserved->uvars->userServer->serviceOpen(this, forClient);
	}

	unlockForArbitration();

	return ok;
}

void
IOService::close(  IOService *     forClient,
    IOOptionBits    options )
{
	bool                wasClosed;
	bool                last = false;

	lockForArbitration();

	wasClosed = handleIsOpen( forClient );
	if (wasClosed) {
		handleClose( forClient, options );
		last = (__state[1] & kIOServiceTermPhase3State);

		if (forClient && forClient->reserved->uvars && forClient->reserved->uvars->userServer) {
			forClient->reserved->uvars->userServer->serviceClose(this, forClient);
		}
	}

	unlockForArbitration();

	if (last) {
		forClient->scheduleStop( this );
	} else if (wasClosed) {
		ServiceOpenMessageContext context;

		context.service         = this;
		context.type            = kIOMessageServiceWasClosed;
		context.excludeClient   = forClient;
		context.options         = options;

		applyToInterested( gIOGeneralInterest,
		    &serviceOpenMessageApplier, &context );
	}
}

bool
IOService::isOpen( const IOService * forClient ) const
{
	IOService * self = (IOService *) this;
	bool ok;

	self->lockForArbitration();

	ok = handleIsOpen( forClient );

	self->unlockForArbitration();

	return ok;
}

bool
IOService::handleOpen(     IOService *     forClient,
    IOOptionBits    options,
    void *          arg )
{
	bool        ok;

	ok = (NULL == __owner);
	if (ok) {
		__owner = forClient;
	} else if (options & kIOServiceSeize) {
		ok = (kIOReturnSuccess == messageClient( kIOMessageServiceIsRequestingClose,
		    __owner, (void *)(uintptr_t) options ));
		if (ok && (NULL == __owner)) {
			__owner = forClient;
		} else {
			ok = false;
		}
	}
	return ok;
}

void
IOService::handleClose(    IOService *     forClient,
    IOOptionBits    options )
{
	if (__owner == forClient) {
		__owner = NULL;
	}
}

bool
IOService::handleIsOpen(   const IOService * forClient ) const
{
	if (forClient) {
		return __owner == forClient;
	} else {
		return __owner != forClient;
	}
}

/*
 * Probing & starting
 */
static SInt32
IONotifyOrdering( const OSMetaClassBase * inObj1, const OSMetaClassBase * inObj2, void * ref )
{
	const _IOServiceNotifier * obj1 = (const _IOServiceNotifier *) inObj1;
	const _IOServiceNotifier * obj2 = (const _IOServiceNotifier *) inObj2;
	SInt32             val1;
	SInt32             val2;

	val1 = 0;
	val2 = 0;

	if (obj1) {
		val1 = obj1->priority;
	}

	if (obj2) {
		val2 = obj2->priority;
	}

	return val1 - val2;
}

static SInt32
IOServiceObjectOrder( const OSObject * entry, void * ref)
{
	OSDictionary *      dict;
	IOService *         service;
	_IOServiceNotifier * notify;
	OSSymbol *          key = (OSSymbol *) ref;
	OSNumber *          offset;
	OSObject *          prop;
	SInt32              result;

	prop = NULL;
	result = kIODefaultProbeScore;
	if ((dict = OSDynamicCast( OSDictionary, entry))) {
		offset = OSDynamicCast(OSNumber, dict->getObject( key ));
	} else if ((notify = OSDynamicCast( _IOServiceNotifier, entry))) {
		return notify->priority;
	} else if ((service = OSDynamicCast( IOService, entry))) {
		prop = service->copyProperty(key);
		offset = OSDynamicCast(OSNumber, prop);
	} else {
		assert( false );
		offset = NULL;
	}

	if (offset) {
		result = offset->unsigned32BitValue();
	}

	OSSafeReleaseNULL(prop);

	return result;
}

SInt32
IOServiceOrdering( const OSMetaClassBase * inObj1, const OSMetaClassBase * inObj2, void * ref )
{
	const OSObject *    obj1 = (const OSObject *) inObj1;
	const OSObject *    obj2 = (const OSObject *) inObj2;
	SInt32               val1;
	SInt32               val2;

	val1 = 0;
	val2 = 0;

	if (obj1) {
		val1 = IOServiceObjectOrder( obj1, ref );
	}

	if (obj2) {
		val2 = IOServiceObjectOrder( obj2, ref );
	}

	return val1 - val2;
}

IOService *
IOService::copyClientWithCategory( const OSSymbol * category )
{
	IOService *         service = NULL;
	OSIterator *        iter;
	const OSSymbol *    nextCat;

	iter = getClientIterator();
	if (iter) {
		while ((service = (IOService *) iter->getNextObject())) {
			if (kIOServiceInactiveState & service->__state[0]) {
				continue;
			}
			nextCat = (const OSSymbol *) OSDynamicCast( OSSymbol,
			    service->getProperty( gIOMatchCategoryKey ));
			if (category == nextCat) {
				service->retain();
				break;
			}
		}
		iter->release();
	}
	return service;
}

IOService *
IOService::getClientWithCategory( const OSSymbol * category )
{
	IOService *
	    service = copyClientWithCategory(category);
	if (service) {
		service->release();
	}
	return service;
}

bool
IOService::invokeNotifier( _IOServiceNotifier * notify )
{
	_IOServiceNotifierInvocation invocation;
	bool                         willNotify;
	bool                         ret = true;
	invocation.thread = current_thread();

#if DEBUG_NOTIFIER_LOCKED
	uint32_t count;
	if ((count = isLockedForArbitration(0))) {
		IOLog("[%s, 0x%x]\n", notify->type->getCStringNoCopy(), count);
		panic("[%s, 0x%x]\n", notify->type->getCStringNoCopy(), count);
	}
#endif /* DEBUG_NOTIFIER_LOCKED */

	LOCKWRITENOTIFY();
	willNotify = (0 != (kIOServiceNotifyEnable & notify->state));

	if (willNotify) {
		queue_enter( &notify->handlerInvocations, &invocation,
		    _IOServiceNotifierInvocation *, link );
	}
	UNLOCKNOTIFY();

	if (willNotify) {
		ret = (*notify->handler)(notify->target, notify->ref, this, notify);

		LOCKWRITENOTIFY();
		queue_remove( &notify->handlerInvocations, &invocation,
		    _IOServiceNotifierInvocation *, link );
		if (kIOServiceNotifyWaiter & notify->state) {
			notify->state &= ~kIOServiceNotifyWaiter;
			WAKEUPNOTIFY( notify );
		}
		UNLOCKNOTIFY();
	}

	return ret;
}

bool
IOService::invokeNotifiers(OSArray * willSend[])
{
	OSArray *            array;
	_IOServiceNotifier * notify;
	bool                 ret = true;

	array = *willSend;
	if (!array) {
		return true;
	}
	*willSend = NULL;

	for (unsigned int idx = 0;
	    (notify = (_IOServiceNotifier *) array->getObject(idx));
	    idx++) {
		ret &= invokeNotifier(notify);
	}
	array->release();

	return ret;
}


/*
 * Alloc and probe matching classes,
 * called on the provider instance
 */

void
IOService::probeCandidates( OSOrderedSet * matches )
{
	OSDictionary        *       match = NULL;
	OSSymbol            *       symbol;
	IOService           *       inst;
	IOService           *       newInst;
	OSDictionary        *       props;
	SInt32                      score;
	OSNumber            *       newPri;
	OSOrderedSet        *       familyMatches = NULL;
	OSOrderedSet        *       startList;
	OSSet               *       kexts = NULL;
	OSObject            *       kextRef;

	OSDictionary        *       startDict = NULL;
	const OSSymbol      *       category;
	OSIterator          *       iter;
	_IOServiceNotifier  *       notify;
	OSObject            *       nextMatch = NULL;
	bool                        started;
	bool                        needReloc = false;
	bool                        matchDeferred = false;
#if IOMATCHDEBUG
	SInt64                      debugFlags;
#endif
	IOService           *       client = NULL;
	OSObject            *       prop1;
	OSObject            *       prop2;
	OSDictionary        *       rematchPersonality;
	OSNumber            *       num;
	uint32_t                    count;
	uint32_t                    dextCount;
	bool                        isDext;
	bool                        categoryConsumed;

	prop2 = NULL;
	count = 0;
	prop1 = copyProperty(gIORematchPersonalityKey);
	rematchPersonality = OSDynamicCast(OSDictionary, prop1);
	if (rematchPersonality) {
		prop2 = copyProperty(gIORematchCountKey);
		num   = OSDynamicCast(OSNumber, prop2);
		if (num) {
			count = num->unsigned32BitValue();
		}
		OSSafeReleaseNULL(prop2);
	}
	dextCount = 0;

	assert( matches );
	while (!needReloc
	    && (nextMatch = matches->getFirstObject())) {
		nextMatch->retain();
		matches->removeObject(nextMatch);

		if ((notify = OSDynamicCast( _IOServiceNotifier, nextMatch ))) {
			if (0 == (__state[0] & kIOServiceInactiveState)) {
				invokeNotifier( notify );
			}
			nextMatch->release();
			nextMatch = NULL;
			continue;
		} else if (!(match = OSDynamicCast( OSDictionary, nextMatch ))) {
			nextMatch->release();
			nextMatch = NULL;
			continue;
		}

		props = NULL;
#if IOMATCHDEBUG
		debugFlags = getDebugFlags( match );
#endif

		do {
			isDext = (NULL != match->getObject(gIOUserServerNameKey));
			if (isDext && !(kIODKEnable & gIODKDebug)) {
				continue;
			}

			category = OSDynamicCast( OSSymbol,
			    match->getObject( gIOMatchCategoryKey ));
			if (NULL == category) {
				category = gIODefaultMatchCategoryKey;
			}
			client = copyClientWithCategory(category);

			categoryConsumed = (client != NULL);
			if (categoryConsumed) {
#if IOMATCHDEBUG
				if ((debugFlags & kIOLogMatch) && (this != gIOResources)) {
					LOG("%s: match category %s exists\n", getName(),
					    category->getCStringNoCopy());
				}
#endif
				OSSafeReleaseNULL(client);
				if (!isDext) {
					break;
				}
			}

			// create a copy now in case its modified during matching
			props = OSDictionary::withDictionary(match, match->getCount());
			if (NULL == props) {
				break;
			}
			props->setCapacityIncrement(1);

			// check the nub matches
			if (false == matchPassive(props, kIOServiceChangesOK | kIOServiceClassDone)) {
				break;
			}
			if (isDext) {
				dextCount++;
				if (categoryConsumed) {
					break;
				}
			}

			if (rematchPersonality) {
				bool personalityMatch = match->isEqualTo(rematchPersonality);
				if (count > gIODextRelaunchMax) {
					personalityMatch = !personalityMatch;
				}
				if (!personalityMatch) {
					break;
				}
			}

			// Check to see if driver reloc has been loaded.
			needReloc = (false == gIOCatalogue->isModuleLoaded( match, &kextRef ));
			if (needReloc) {
#if IOMATCHDEBUG
				if (debugFlags & kIOLogCatalogue) {
					LOG("%s: stalling for module\n", getName());
				}
#endif
				// If reloc hasn't been loaded, exit;
				// reprobing will occur after reloc has been loaded.
				break;
			}
			if (kextRef) {
				if (NULL == kexts) {
					kexts = OSSet::withCapacity(1);
				}
				if (kexts) {
					kexts->setObject(kextRef);
					kextRef->release();
				}
			}
			if (isDext) {
				// copy saved for rematchng
				props->setObject(gIOMatchedPersonalityKey, match);
			}
			// reorder on family matchPropertyTable score.
			if (NULL == familyMatches) {
				familyMatches = OSOrderedSet::withCapacity( 1,
				    IOServiceOrdering, (void *) gIOProbeScoreKey );
			}
			if (familyMatches) {
				familyMatches->setObject( props );
			}
		} while (false);

		OSSafeReleaseNULL(nextMatch);
		OSSafeReleaseNULL(props);
	}
	matches->release();
	matches = NULL;

	if (familyMatches) {
		while (!needReloc
		    && (props = (OSDictionary *) familyMatches->getFirstObject())) {
			props->retain();
			familyMatches->removeObject( props );

			inst = NULL;
			newInst = NULL;
#if IOMATCHDEBUG
			debugFlags = getDebugFlags( props );
#endif
			do {
				symbol = OSDynamicCast( OSSymbol,
				    props->getObject( gIOClassKey));
				if (!symbol) {
					continue;
				}

				//IOLog("%s alloc (symbol %p props %p)\n", symbol->getCStringNoCopy(), IOSERVICE_OBFUSCATE(symbol), IOSERVICE_OBFUSCATE(props));

				// alloc the driver instance
				inst = (IOService *) OSMetaClass::allocClassWithName( symbol);

				if (!inst || !OSDynamicCast(IOService, inst)) {
					IOLog("Couldn't alloc class \"%s\"\n",
					    symbol->getCStringNoCopy());
					continue;
				}

				// init driver instance
				if (!(inst->init( props ))) {
#if IOMATCHDEBUG
					if (debugFlags & kIOLogStart) {
						IOLog("%s::init fails\n", symbol->getCStringNoCopy());
					}
#endif
					continue;
				}
				if (__state[1] & kIOServiceSynchronousState) {
					inst->__state[1] |= kIOServiceSynchronousState;
				}

				// give the driver the default match category if not specified
				category = OSDynamicCast( OSSymbol,
				    props->getObject( gIOMatchCategoryKey ));
				if (NULL == category) {
					category = gIODefaultMatchCategoryKey;
				}
				inst->setProperty( gIOMatchCategoryKey, (OSObject *) category );
				// attach driver instance
				if (!(inst->attach( this ))) {
					continue;
				}

				// pass in score from property table
				score = familyMatches->orderObject( props );

				// & probe the new driver instance
#if IOMATCHDEBUG
				if (debugFlags & kIOLogProbe) {
					LOG("%s::probe(%s)\n",
					    inst->getMetaClass()->getClassName(), getName());
				}
#endif

				newInst = inst->probe( this, &score );
				inst->detach( this );
				if (NULL == newInst) {
#if IOMATCHDEBUG
					if (debugFlags & kIOLogProbe) {
						IOLog("%s::probe fails\n", symbol->getCStringNoCopy());
					}
#endif
					continue;
				}

				// save the score
				newPri = OSNumber::withNumber( score, 32 );
				if (newPri) {
					newInst->setProperty( gIOProbeScoreKey, newPri );
					newPri->release();
				}

				// add to start list for the match category
				if (NULL == startDict) {
					startDict = OSDictionary::withCapacity( 1 );
				}
				assert( startDict );
				startList = (OSOrderedSet *)
				    startDict->getObject( category );
				if (NULL == startList) {
					startList = OSOrderedSet::withCapacity( 1,
					    IOServiceOrdering, (void *) gIOProbeScoreKey );
					if (startDict && startList) {
						startDict->setObject( category, startList );
						startList->release();
					}
				}
				assert( startList );
				if (startList) {
					startList->setObject( newInst );
				}
			} while (false);

			props->release();
			if (inst) {
				inst->release();
			}
		}
		familyMatches->release();
		familyMatches = NULL;
	}

	// start the best (until success) of each category

	iter = OSCollectionIterator::withCollection( startDict );
	if (iter) {
		while ((category = (const OSSymbol *) iter->getNextObject())) {
			startList = (OSOrderedSet *) startDict->getObject( category );
			assert( startList );
			if (!startList) {
				continue;
			}

			started = false;
			while (true // (!started)
			    && !matchDeferred
			    && (inst = (IOService *)startList->getFirstObject())) {
				inst->retain();
				startList->removeObject(inst);

#if IOMATCHDEBUG
				debugFlags = getDebugFlags( inst );

				if (debugFlags & kIOLogStart) {
					if (started) {
						LOG( "match category exists, skipping " );
					}
					LOG( "%s::start(%s) <%d>\n", inst->getName(),
					    getName(), inst->getRetainCount());
				}
#endif
				if (false == started) {
#if !NO_KEXTD
					IOLockLock(gJobsLock);
					matchDeferred = (gIOMatchDeferList
					    && (kOSBooleanTrue == inst->getProperty(gIOMatchDeferKey)));
					if (matchDeferred && (-1U == gIOMatchDeferList->getNextIndexOfObject(this, 0))) {
						gIOMatchDeferList->setObject(this);
					}
					IOLockUnlock(gJobsLock);
					if (matchDeferred) {
						symbol = OSDynamicCast(OSSymbol, inst->getProperty(gIOClassKey));
						IOLog("%s(0x%qx): matching deferred by %s\n",
						    getName(), getRegistryEntryID(),
						    symbol ? symbol->getCStringNoCopy() : "");
						// rematching will occur after kextd loads all plists
					}
#endif
					if (!matchDeferred) {
						started = startCandidate( inst );
#if IOMATCHDEBUG
						if ((debugFlags & kIOLogStart) && (false == started)) {
							LOG( "%s::start(%s) <%d> failed\n", inst->getName(), getName(),
							    inst->getRetainCount());
						}
#endif
					}
				}
				inst->release();
			}
		}
		iter->release();
	}

	OSSafeReleaseNULL(prop1);

	if (dextCount) {
		num = OSNumber::withNumber(dextCount, 32);
		setProperty(gIODEXTMatchCountKey, num);
		OSSafeReleaseNULL(num);
	} else if (rematchPersonality) {
		removeProperty(gIODEXTMatchCountKey);
	}

	// now that instances are created, drop the refs on any kexts allowing unload
	if (kexts) {
		OSKext::dropMatchingReferences(kexts);
		OSSafeReleaseNULL(kexts);
	}

	// adjust the busy count by +1 if matching is stalled for a module,
	// or -1 if a previously stalled matching is complete.
	lockForArbitration();
	SInt32 adjBusy = 0;
	uint64_t regID = getRegistryEntryID();

	if (needReloc) {
		adjBusy = (__state[1] & kIOServiceModuleStallState) ? 0 : 1;
		if (adjBusy) {
			IOServiceTrace(
				IOSERVICE_MODULESTALL,
				(uintptr_t) regID,
				(uintptr_t) (regID >> 32),
				(uintptr_t) this,
				0);

			__state[1] |= kIOServiceModuleStallState;
		}
	} else if (__state[1] & kIOServiceModuleStallState) {
		IOServiceTrace(
			IOSERVICE_MODULEUNSTALL,
			(uintptr_t) regID,
			(uintptr_t) (regID >> 32),
			(uintptr_t) this,
			0);

		__state[1] &= ~kIOServiceModuleStallState;
		adjBusy = -1;
	}
	if (adjBusy) {
		_adjustBusy( adjBusy );
	}
	unlockForArbitration();

	if (startDict) {
		startDict->release();
	}
}

/*
 * Wait for a IOUserServer to check in
 */

static
__attribute__((noinline, not_tail_called))
IOService *
__WAITING_FOR_USER_SERVER__(OSDictionary * matching)
{
	IOService * server;
	server = IOService::waitForMatchingService(matching, kIOUserServerCheckInTimeoutSecs * NSEC_PER_SEC);
	return server;
}

void
IOService::willShutdown()
{
	gKextdWillTerminate = true;
#if !NO_KEXTD
	getPlatform()->waitQuiet(30 * NSEC_PER_SEC);
#endif
	OSKext::willShutdown();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOServicePH::init(IOPMrootDomain * root)
{
	fUserServers     = OSArray::withCapacity(4);
	fMatchingWork    = OSArray::withCapacity(4);

	assert(fUserServers && fMatchingWork);

	fRootNotifier = root->registerInterest(
		gIOPriorityPowerStateInterest, &IOServicePH::systemPowerChange, NULL, NULL);

	assert(fRootNotifier);
}

void
IOServicePH::lock()
{
	IOLockLock(gJobsLock);
}

void
IOServicePH::unlock()
{
	IOLockUnlock(gJobsLock);
}

void
IOServicePH::serverAdd(IOUserServer * server)
{
	uint32_t idx;

	lock();
	idx = fUserServers->getNextIndexOfObject(server, 0);
	if (idx == -1U) {
		fUserServers->setObject(server);
	}
	unlock();
}

void
IOServicePH::serverRemove(IOUserServer * server)
{
	uint32_t idx;

	lock();
	idx = fUserServers->getNextIndexOfObject(server, 0);
	if (idx != -1U) {
		fUserServers->removeObject(idx);
	}
	unlock();
}

void
IOServicePH::serverAck(IOUserServer * server)
{
	uint32_t    idx;
	IOService * ackTo;
	uint32_t    ackToRef;

	ackTo = NULL;
	lock();
	if (server && fUserServersWait) {
		idx = fUserServersWait->getNextIndexOfObject(server, 0);
		if (idx != -1U) {
			fUserServersWait->removeObject(idx);
			if (0 == fUserServersWait->getCount()) {
				OSSafeReleaseNULL(fUserServersWait);
			}
		}
	}
	if (!fUserServersWait && !fMatchingWork->getCount()) {
		ackTo             = fSystemPowerAckTo;
		ackToRef          = fSystemPowerAckRef;
		fSystemPowerAckTo = NULL;
	}
	unlock();

	if (ackTo) {
		DKLOG("allowPowerChange\n");
		ackTo->allowPowerChange((uintptr_t) ackToRef);
	}
}

bool
IOServicePH::matchingStart(IOService * service)
{
	uint32_t idx;
	bool ok;

	lock();
	ok = !fSystemOff;
	if (ok) {
		idx = fMatchingWork->getNextIndexOfObject(service, 0);
		if (idx == -1U) {
			fMatchingWork->setObject(service);
		}
	} else {
		if (!fMatchingDelayed) {
			fMatchingDelayed = OSArray::withObjects((const OSObject **) &service, 1, 1);
		} else {
			idx = fMatchingDelayed->getNextIndexOfObject(service, 0);
			if (idx == -1U) {
				fMatchingDelayed->setObject(service);
			}
		}
	}
	unlock();

	return ok;
}

void
IOServicePH::matchingEnd(IOService * service)
{
	uint32_t idx;
	OSArray   * notifyServers;
	OSArray   * deferredMatches;

	notifyServers   = NULL;
	deferredMatches = NULL;

	lock();

	if (service) {
		idx = fMatchingWork->getNextIndexOfObject(service, 0);
		if (idx != -1U) {
			fMatchingWork->removeObject(idx);
		}
	}


	if ((fUserServerOff != fSystemOff) && fUserServers->getCount()) {
		if (fSystemOff) {
			if (0 == fMatchingWork->getCount()) {
				fUserServersWait = OSArray::withArray(fUserServers);
				notifyServers = OSArray::withArray(fUserServers);
				fUserServerOff = fSystemOff;
			}
		} else {
			notifyServers = OSArray::withArray(fUserServers);
			fUserServerOff = fSystemOff;
		}
	}

	if (!fSystemOff && fMatchingDelayed) {
		deferredMatches = fMatchingDelayed;
		fMatchingDelayed = NULL;
	}

	unlock();

	if (notifyServers) {
		notifyServers->iterateObjects(^bool (OSObject * obj) {
			IOUserServer * us;
			us = (typeof(us))obj;
			us->systemPower(fSystemOff);
			return false;
		});
		OSSafeReleaseNULL(notifyServers);
	}

	if (deferredMatches) {
		DKLOG("sleep deferred rematching count %d\n", deferredMatches->getCount());
		deferredMatches->iterateObjects(^bool (OSObject * obj)
		{
			((IOService *)obj)->startMatching(kIOServiceAsynchronous);
			return false;
		});
		deferredMatches->release();
	}

	serverAck(NULL);
}

IOReturn
IOServicePH::systemPowerChange(
	void * target,
	void * refCon,
	UInt32 messageType, IOService * service,
	void * messageArgument, vm_size_t argSize)
{
	IOReturn                               ret;
	IOUserServer                         * us;
	IOPMSystemCapabilityChangeParameters * params;

	us = NULL;

	switch (messageType) {
	case kIOMessageSystemCapabilityChange:

		params = (typeof params)messageArgument;

		if (kIODKLogPM & gIODKDebug) {
			IOLog("IOServicePH::kIOMessageSystemCapabilityChange: %s%s 0x%x->0x%x\n",
			    params->changeFlags & kIOPMSystemCapabilityWillChange ? "will" : "",
			    params->changeFlags & kIOPMSystemCapabilityDidChange ? "did" : "",
			    params->fromCapabilities,
			    params->toCapabilities);
		}

		if ((params->changeFlags & kIOPMSystemCapabilityWillChange) &&
		    (params->fromCapabilities & kIOPMSystemCapabilityCPU) &&
		    ((params->toCapabilities & kIOPMSystemCapabilityCPU) == 0)) {
			lock();
			fSystemOff         = true;
			fSystemPowerAckRef = params->notifyRef;
			fSystemPowerAckTo  = service;
			unlock();

			matchingEnd(NULL);

			params->maxWaitForReply = 60 * 1000 * 1000;
			ret = kIOReturnSuccess;
		} else if ((params->changeFlags & kIOPMSystemCapabilityWillChange) &&
		    ((params->fromCapabilities & kIOPMSystemCapabilityCPU) == 0) &&
		    (params->toCapabilities & kIOPMSystemCapabilityCPU)) {
			lock();
			fSystemOff = false;
			unlock();

			matchingEnd(NULL);

			params->maxWaitForReply = 0;
			ret                 = kIOReturnSuccess;
		} else {
			params->maxWaitForReply = 0;
			ret                 = kIOReturnSuccess;
		}
		break;

	default:
		ret = kIOReturnUnsupported;
		break;
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Start a previously attached & probed instance,
 * called on exporting object instance
 */

bool
IOService::startCandidate( IOService * service )
{
	bool                ok;
	OSObject          * obj;
	OSObject          * prop;
	IOUserServer      * userServer;
	bool                ph;

	userServer = NULL;
	obj = service->copyProperty(gIOUserServerNameKey);

	if (obj && (this == gIOResources)) {
		ok = false;
	} else {
		ok = service->attach( this );
	}
	if (!ok) {
		return false;
	}

	if ((this != gIOResources) && (this != gIOUserResources)) {
		// stall for any nub resources
		checkResources();
		// stall for any driver resources
		service->checkResources();
	}
	ph = false;
	{
		OSString       * bundleID;
		OSString       * serverName;
		OSString       * str;
		const OSSymbol * sym;
		OSDictionary   * matching;
		IOService      * server;
		OSNumber       * serverTag;
		uint64_t         entryID;

		if ((serverName = OSDynamicCast(OSString, obj))) {
			obj       = service->copyProperty(gIOModuleIdentifierKey);
			bundleID  = OSDynamicCast(OSString, obj);
			entryID   = service->getRegistryEntryID();
			serverTag = OSNumber::withNumber(entryID, 64);

			if (gKextdWillTerminate) {
				DKLOG("%s disabled in shutdown\n", serverName->getCStringNoCopy());
				service->detach(this);
				OSSafeReleaseNULL(obj);
				return false;
			}

			ph = IOServicePH::matchingStart(this);
			if (!ph) {
				DKLOG("%s deferred in sleep\n", serverName->getCStringNoCopy());
				service->detach(this);
				OSSafeReleaseNULL(obj);
				return false;
			}

			prop = service->copyProperty(gIOUserClassKey);
			str = OSDynamicCast(OSString, prop);
			if (str) {
				service->setName(str);
			}
			OSSafeReleaseNULL(prop);

			if (!(kIODKDisableDextLaunch & gIODKDebug)) {
				OSKext::requestDaemonLaunch(bundleID, serverName, serverTag);
			}
			sym = OSSymbol::withString(serverName);
			matching = serviceMatching(gIOUserServerClassKey);
			propertyMatching(gIOUserServerNameKey, sym, matching);
			if (!(kIODKDisableDextTag & gIODKDebug)) {
				propertyMatching(gIOUserServerTagKey, serverTag, matching);
			}

			server = __WAITING_FOR_USER_SERVER__(matching);
			matching->release();
			OSSafeReleaseNULL(serverTag);
			OSSafeReleaseNULL(serverName);

			userServer = OSDynamicCast(IOUserServer, server);
			if (!userServer) {
				service->detach(this);
				IOServicePH::matchingEnd(this);
				DKLOG(DKS " user server timeout\n", DKN(service));
				return false;
			}

			if (!(kIODKDisableCDHashChecking & gIODKDebug)) {
				if (!userServer->serviceMatchesCDHash(service)) {
					service->detach(this);
					IOServicePH::matchingEnd(this);
					userServer->exit("CDHash check failed");
					userServer->release();
					return false;
				}
			}
			OSKext *kext = OSKext::lookupKextWithIdentifier(bundleID);
			if (!kext) {
				const char *name = bundleID->getCStringNoCopy();
				IOLog("%s Could not find OSKext for %s\n", __func__, name);
				goto skip_log;
			}

			/*
			 * Used for logging
			 */
			userServer->setTaskLoadTag(kext);
			userServer->setDriverKitUUID(kext);
			OSKext::OSKextLogDriverKitInfoLoad(kext);
skip_log:
			OSSafeReleaseNULL(bundleID);
			OSSafeReleaseNULL(kext);

			if (!(kIODKDisableEntitlementChecking & gIODKDebug)) {
				if (!userServer->checkEntitlements(this, service)) {
					service->detach(this);
					IOServicePH::matchingEnd(this);
					userServer->exit("Entitlements check failed");
					userServer->release();
					return false;
				}
			}

			userServer->serviceAttach(service, this);
		}
	}

	AbsoluteTime startTime;
	AbsoluteTime endTime;
	UInt64       nano;

	if (kIOLogStart & gIOKitDebug) {
		clock_get_uptime(&startTime);
	}

	ok = service->start(this);

	if (kIOLogStart & gIOKitDebug) {
		clock_get_uptime(&endTime);

		if (CMP_ABSOLUTETIME(&endTime, &startTime) > 0) {
			SUB_ABSOLUTETIME(&endTime, &startTime);
			absolutetime_to_nanoseconds(endTime, &nano);
			if (nano > 500000000ULL) {
				IOLog("%s::start took %ld ms\n", service->getName(), (long)(UInt32)(nano / 1000000ULL));
			}
		}
	}
	if (userServer) {
		userServer->serviceStarted(service, this, ok);
		userServer->release();
	}
	if (!ok) {
		service->detach( this );
	}

	if (ph) {
		IOServicePH::matchingEnd(this);
	}

	return ok;
}

void
IOService::publishResource( const char * key, OSObject * value )
{
	const OSSymbol *    sym;

	if ((sym = OSSymbol::withCString( key))) {
		publishResource( sym, value);
		sym->release();
	}
}

void
IOService::publishResource( const OSSymbol * key, OSObject * value )
{
	if (NULL == value) {
		value = (OSObject *) gIOServiceKey;
	}

	gIOResources->setProperty( key, value);

	if (IORecursiveLockHaveLock( gNotificationLock)) {
		return;
	}

	gIOResourceGenerationCount++;
	gIOResources->registerService();
}

void
IOService::publishUserResource( const OSSymbol * key, OSObject * value )
{
	if (NULL == value) {
		value = (OSObject *) gIOServiceKey;
	}

	gIOUserResources->setProperty( key, value);

	if (IORecursiveLockHaveLock( gNotificationLock)) {
		return;
	}

	gIOResourceGenerationCount++;
	gIOUserResources->registerService();
}

bool
IOService::addNeededResource( const char * key )
{
	OSObject *  resourcesProp;
	OSSet *     set;
	OSString *  newKey;
	bool ret;

	resourcesProp = copyProperty( gIOResourceMatchKey );
	if (!resourcesProp) {
		return false;
	}

	newKey = OSString::withCString( key );
	if (!newKey) {
		resourcesProp->release();
		return false;
	}

	set = OSDynamicCast( OSSet, resourcesProp );
	if (!set) {
		set = OSSet::withCapacity( 1 );
		if (set) {
			set->setObject( resourcesProp );
		}
	} else {
		set->retain();
	}

	set->setObject( newKey );
	newKey->release();
	ret = setProperty( gIOResourceMatchKey, set );
	set->release();
	resourcesProp->release();

	return ret;
}

bool
IOService::checkResource( OSObject * matching )
{
	OSString *          str;
	OSDictionary *      table;

	if ((str = OSDynamicCast( OSString, matching ))) {
		if (gIOResources->getProperty( str )) {
			return true;
		}
	}

	if (str) {
		table = resourceMatching( str );
	} else if ((table = OSDynamicCast( OSDictionary, matching ))) {
		table->retain();
	} else {
		IOLog("%s: Can't match using: %s\n", getName(),
		    matching->getMetaClass()->getClassName());
		/* false would stall forever */
		return true;
	}

	if (gIOKitDebug & kIOLogConfig) {
		LOG("config(%p): stalling %s\n", IOSERVICE_OBFUSCATE(IOThreadSelf()), getName());
	}

	waitForService( table );

	if (gIOKitDebug & kIOLogConfig) {
		LOG("config(%p): waking\n", IOSERVICE_OBFUSCATE(IOThreadSelf()));
	}

	return true;
}

bool
IOService::checkResources( void )
{
	OSObject *          resourcesProp;
	OSSet *             set;
	OSIterator *        iter;
	bool                ok;

	resourcesProp = copyProperty( gIOResourceMatchKey );
	if (NULL == resourcesProp) {
		return true;
	}

	if ((set = OSDynamicCast( OSSet, resourcesProp ))) {
		iter = OSCollectionIterator::withCollection( set );
		ok = (NULL != iter);
		while (ok && (resourcesProp = iter->getNextObject())) {
			ok = checkResource( resourcesProp );
		}
		if (iter) {
			iter->release();
		}
	} else {
		ok = checkResource( resourcesProp );
	}

	OSSafeReleaseNULL(resourcesProp);

	return ok;
}


void
_IOConfigThread::configThread( int configThreadId )
{
	_IOConfigThread *   inst;

	do {
		if (!(inst = new _IOConfigThread)) {
			continue;
		}
		if (!inst->init()) {
			continue;
		}
		thread_t thread;
		if (KERN_SUCCESS != kernel_thread_start(&_IOConfigThread::main, inst, &thread)) {
			continue;
		}

		char threadName[MAXTHREADNAMESIZE];
		snprintf(threadName, sizeof(threadName), "IOConfigThread_%d", configThreadId);
		thread_set_thread_name(thread, threadName);
		thread_deallocate(thread);

		return;
	} while (false);

	if (inst) {
		inst->release();
	}

	return;
}

void
IOService::doServiceMatch( IOOptionBits options )
{
	_IOServiceNotifier * notify;
	OSIterator *        iter;
	OSOrderedSet *      matches;
	OSArray *           resourceKeys = NULL;
	SInt32              catalogGeneration;
	bool                keepGuessing = true;
	bool                reRegistered = true;
	bool                didRegister;
	OSArray *           notifiers[2] = {NULL};

//    job->nub->deliverNotification( gIOPublishNotification,
//                              kIOServiceRegisteredState, 0xffffffff );

	while (keepGuessing) {
		matches = gIOCatalogue->findDrivers( this, &catalogGeneration );
		// the matches list should always be created by findDrivers()
		if (matches) {
			lockForArbitration();
			if (0 == (__state[0] & kIOServiceFirstPublishState)) {
				getMetaClass()->addInstance(this);
				notifiers[0] = copyNotifiers(gIOFirstPublishNotification,
				    kIOServiceFirstPublishState, 0xffffffff );
			}
			LOCKREADNOTIFY();
			__state[1] &= ~kIOServiceNeedConfigState;
			__state[1] |= kIOServiceConfigState | kIOServiceConfigRunning;
			didRegister = (0 == (kIOServiceRegisteredState & __state[0]));
			__state[0] |= kIOServiceRegisteredState;

			keepGuessing &= (0 == (__state[0] & kIOServiceInactiveState));
			if (reRegistered && keepGuessing) {
				iter = OSCollectionIterator::withCollection((OSOrderedSet *)
				    gNotifications->getObject( gIOPublishNotification ));
				if (iter) {
					while ((notify = (_IOServiceNotifier *)
					    iter->getNextObject())) {
						if (matchPassive(notify->matching, 0)
						    && (kIOServiceNotifyEnable & notify->state)) {
							matches->setObject( notify );
						}
					}
					iter->release();
				}
			}

			UNLOCKNOTIFY();
			unlockForArbitration();
			invokeNotifiers(&notifiers[0]);

			if (keepGuessing && matches->getCount() && (kIOReturnSuccess == getResources())) {
				if ((this == gIOResources) || (this == gIOUserResources)) {
					if (resourceKeys) {
						resourceKeys->release();
					}
					resourceKeys = copyPropertyKeys();
				}
				probeCandidates( matches );
			} else {
				matches->release();
			}
		}

		lockForArbitration();
		reRegistered = (0 != (__state[1] & kIOServiceNeedConfigState));
		keepGuessing =
		    (reRegistered || (catalogGeneration !=
		    gIOCatalogue->getGenerationCount()))
		    && (0 == (__state[0] & kIOServiceInactiveState));

		if (keepGuessing) {
			unlockForArbitration();
		}
	}

	if ((0 == (__state[0] & kIOServiceInactiveState))
	    && (0 == (__state[1] & kIOServiceModuleStallState))) {
		if (resourceKeys) {
			setProperty(gIOResourceMatchedKey, resourceKeys);
		}

		notifiers[0] = copyNotifiers(gIOMatchedNotification,
		    kIOServiceMatchedState, 0xffffffff);
		if (0 == (__state[0] & kIOServiceFirstMatchState)) {
			notifiers[1] = copyNotifiers(gIOFirstMatchNotification,
			    kIOServiceFirstMatchState, 0xffffffff);
		}
	}

	__state[1] &= ~kIOServiceConfigRunning;
	unlockForArbitration();

	if (resourceKeys) {
		resourceKeys->release();
	}

	invokeNotifiers(&notifiers[0]);
	invokeNotifiers(&notifiers[1]);

	lockForArbitration();
	__state[1] &= ~kIOServiceConfigState;
	scheduleTerminatePhase2();

	_adjustBusy( -1 );
	unlockForArbitration();
}

UInt32
IOService::_adjustBusy( SInt32 delta )
{
	IOService * next;
	UInt32      count;
	UInt32      result;
	bool        wasQuiet, nowQuiet, needWake;

	next = this;
	result = __state[1] & kIOServiceBusyStateMask;

	if (delta) {
		do {
			if (next != this) {
				next->lockForArbitration();
			}
			count = next->__state[1] & kIOServiceBusyStateMask;
			wasQuiet = (0 == count);
			if (((delta < 0) && wasQuiet) || ((delta > 0) && (kIOServiceBusyMax == count))) {
				OSReportWithBacktrace("%s: bad busy count (%d,%d)\n", next->getName(), count, delta);
			} else {
				count += delta;
			}
			next->__state[1] = (next->__state[1] & ~kIOServiceBusyStateMask) | count;
			nowQuiet = (0 == count);
			needWake = (0 != (kIOServiceBusyWaiterState & next->__state[1]));

			if (needWake) {
				next->__state[1] &= ~kIOServiceBusyWaiterState;
				IOLockLock( gIOServiceBusyLock );
				thread_wakeup((event_t) next);
				IOLockUnlock( gIOServiceBusyLock );
			}
			if (next != this) {
				next->unlockForArbitration();
			}

			if ((wasQuiet || nowQuiet)) {
				uint64_t regID = next->getRegistryEntryID();
				IOServiceTrace(
					((wasQuiet /*nowBusy*/) ? IOSERVICE_BUSY : IOSERVICE_NONBUSY),
					(uintptr_t) regID,
					(uintptr_t) (regID >> 32),
					(uintptr_t) next,
					0);

				if (wasQuiet) {
					next->__timeBusy = mach_absolute_time();
				} else {
					next->__accumBusy += mach_absolute_time() - next->__timeBusy;
					next->__timeBusy = 0;
				}

				MessageClientsContext context;

				context.service  = next;
				context.type     = kIOMessageServiceBusyStateChange;
				context.argument = (void *) wasQuiet; /*nowBusy*/
				context.argSize  = 0;

				applyToInterestNotifiers( next, gIOBusyInterest,
				    &messageClientsApplier, &context );

#if !NO_KEXTD
				if (nowQuiet && (next == gIOServiceRoot)) {
					OSKext::considerUnloads();
					IOServiceTrace(IOSERVICE_REGISTRY_QUIET, 0, 0, 0, 0);
				}
#endif
			}

			delta = nowQuiet ? -1 : +1;
		} while ((wasQuiet || nowQuiet) && (next = next->getProvider()));
	}

	return result;
}

void
IOService::adjustBusy( SInt32 delta )
{
	lockForArbitration();
	_adjustBusy( delta );
	unlockForArbitration();
}

uint64_t
IOService::getAccumulatedBusyTime( void )
{
	uint64_t accumBusy = __accumBusy;
	uint64_t timeBusy = __timeBusy;
	uint64_t nano;

	do{
		accumBusy = __accumBusy;
		timeBusy  = __timeBusy;
		if (timeBusy) {
			accumBusy += mach_absolute_time() - timeBusy;
		}
	}while (timeBusy != __timeBusy);

	absolutetime_to_nanoseconds(*(AbsoluteTime *)&accumBusy, &nano);

	return nano;
}

UInt32
IOService::getBusyState( void )
{
	return __state[1] & kIOServiceBusyStateMask;
}

IOReturn
IOService::waitForState( UInt32 mask, UInt32 value,
    mach_timespec_t * timeout )
{
	panic("waitForState");
	return kIOReturnUnsupported;
}

IOReturn
IOService::waitForState( UInt32 mask, UInt32 value,
    uint64_t timeout )
{
	bool            wait;
	int             waitResult = THREAD_AWAKENED;
	bool            computeDeadline = true;
	AbsoluteTime    abstime;

	do {
		lockForArbitration();
		IOLockLock( gIOServiceBusyLock );
		wait = (value != (__state[1] & mask));
		if (wait) {
			__state[1] |= kIOServiceBusyWaiterState;
			unlockForArbitration();
			if (timeout != UINT64_MAX) {
				if (computeDeadline) {
					AbsoluteTime  nsinterval;
					nanoseconds_to_absolutetime(timeout, &nsinterval );
					clock_absolutetime_interval_to_deadline(nsinterval, &abstime);
					computeDeadline = false;
				}
				assert_wait_deadline((event_t)this, THREAD_UNINT, __OSAbsoluteTime(abstime));
			} else {
				assert_wait((event_t)this, THREAD_UNINT );
			}
		} else {
			unlockForArbitration();
		}
		IOLockUnlock( gIOServiceBusyLock );
		if (wait) {
			waitResult = thread_block(THREAD_CONTINUE_NULL);
		}
	} while (wait && (waitResult != THREAD_TIMED_OUT));

	if (waitResult == THREAD_TIMED_OUT) {
		return kIOReturnTimeout;
	} else {
		return kIOReturnSuccess;
	}
}

IOReturn
IOService::waitQuiet( uint64_t timeout )
{
	IOReturn ret;
	uint32_t loops;
	char *   string = NULL;
	char *   panicString = NULL;
	size_t   len;
	size_t   panicStringLen;
	uint64_t time;
	uint64_t nano;
	bool     kextdWait;
	bool     dopanic;

#if KASAN
	/*
	 * On kasan kernels, everything takes longer, so double the number of
	 * timeout extensions. This should help with issues like 41259215
	 * where WindowServer was timing out waiting for kextd to get all the
	 * kasan kexts loaded and started.
	 */
	enum { kTimeoutExtensions = 8 };
#else
	enum { kTimeoutExtensions = 4 };
#endif

	time = mach_absolute_time();
	kextdWait = false;
	for (loops = 0; loops < kTimeoutExtensions; loops++) {
		ret = waitForState( kIOServiceBusyStateMask, 0, timeout );

		if (loops && (kIOReturnSuccess == ret)) {
			time = mach_absolute_time() - time;
			absolutetime_to_nanoseconds(*(AbsoluteTime *)&time, &nano);
			IOLog("busy extended ok[%d], (%llds, %llds)\n",
			    loops, timeout / 1000000000ULL, nano / 1000000000ULL);
			break;
		} else if (kIOReturnTimeout != ret) {
			break;
		} else if (timeout < (4100ull * NSEC_PER_SEC)) {
			break;
		}

		{
			IORegistryIterator * iter;
			OSOrderedSet       * set;
			OSOrderedSet       * leaves;
			IOService          * next;
			IOService          * nextParent;
			char               * s;
			size_t               l;

			len = 256;
			panicStringLen = 256;
			if (!string) {
				string      = IONew(char, len);
			}
			if (!panicString) {
				panicString = IONew(char, panicStringLen);
			}
			set = NULL;
			kextdWait = OSKext::isWaitingKextd();
			iter = IORegistryIterator::iterateOver(this, gIOServicePlane, kIORegistryIterateRecursively);
			leaves = OSOrderedSet::withCapacity(4);
			if (iter) {
				set = iter->iterateAll();
			}
			if (string && panicString && leaves && set) {
				string[0] = panicString[0] = 0;
				set->setObject(this);
				while ((next = (IOService *) set->getLastObject())) {
					if (next->getBusyState()) {
						if (kIOServiceModuleStallState & next->__state[1]) {
							kextdWait = true;
						}
						leaves->setObject(next);
						nextParent = next;
						while ((nextParent = nextParent->getProvider())) {
							set->removeObject(nextParent);
							leaves->removeObject(nextParent);
						}
					}
					set->removeObject(next);
				}
				s = string;
				while ((next = (IOService *) leaves->getLastObject())) {
					l = snprintf(s, len, "%s'%s'", ((s == string) ? "" : ", "), next->getName());
					if (l >= len) {
						break;
					}
					s += l;
					len -= l;
					leaves->removeObject(next);
				}
			}
			OSSafeReleaseNULL(leaves);
			OSSafeReleaseNULL(set);
			OSSafeReleaseNULL(iter);
		}

		dopanic = ((loops >= (kTimeoutExtensions - 1)) && (kIOWaitQuietPanics & gIOKitDebug));
		snprintf(panicString, panicStringLen,
		    "%s[%d], (%llds): %s",
		    kextdWait ? "kextd stall" : "busy timeout",
		    loops, timeout / 1000000000ULL,
		    string ? string : "");
		IOLog("%s\n", panicString);
		if (dopanic) {
			panic("%s", panicString);
		} else if (!loops) {
			getPMRootDomain()->startSpinDump(1);
		}
	}

	if (string) {
		IODelete(string, char, 256);
	}
	if (panicString) {
		IODelete(panicString, char, panicStringLen);
	}

	return ret;
}

IOReturn
IOService::waitQuiet( mach_timespec_t * timeout )
{
	uint64_t    timeoutNS;

	if (timeout) {
		timeoutNS = timeout->tv_sec;
		timeoutNS *= kSecondScale;
		timeoutNS += timeout->tv_nsec;
	} else {
		timeoutNS = UINT64_MAX;
	}

	return waitQuiet(timeoutNS);
}

bool
IOService::serializeProperties( OSSerialize * s ) const
{
#if 0
	((IOService *)this)->setProperty(((IOService *)this)->__state,
	    sizeof(__state), "__state");
#endif
	return super::serializeProperties(s);
}


void
_IOConfigThread::main(void * arg, wait_result_t result)
{
	_IOConfigThread * self = (_IOConfigThread *) arg;
	_IOServiceJob * job;
	IOService   *   nub;
	bool            alive = true;
	kern_return_t   kr;
	thread_precedence_policy_data_t precedence = { -1 };

	kr = thread_policy_set(current_thread(),
	    THREAD_PRECEDENCE_POLICY,
	    (thread_policy_t) &precedence,
	    THREAD_PRECEDENCE_POLICY_COUNT);
	if (KERN_SUCCESS != kr) {
		IOLog("thread_policy_set(%d)\n", kr);
	}

	do {
//	randomDelay();

		semaphore_wait( gJobsSemaphore );

		IOTakeLock( gJobsLock );
		job = (_IOServiceJob *) gJobs->getFirstObject();
		job->retain();
		gJobs->removeObject(job);
		if (job) {
			gOutstandingJobs--;
//	    gNumConfigThreads--;	// we're out of service
			gNumWaitingThreads--; // we're out of service
		}
		IOUnlock( gJobsLock );

		if (job) {
			nub = job->nub;

			if (gIOKitDebug & kIOLogConfig) {
				LOG("config(%p): starting on %s, %d\n",
				    IOSERVICE_OBFUSCATE(IOThreadSelf()), job->nub->getName(), job->type);
			}

			switch (job->type) {
			case kMatchNubJob:
				nub->doServiceMatch( job->options );
				break;

			default:
				LOG("config(%p): strange type (%d)\n",
				    IOSERVICE_OBFUSCATE(IOThreadSelf()), job->type );
				break;
			}

			nub->release();
			job->release();

			IOTakeLock( gJobsLock );
			alive = (gOutstandingJobs > gNumWaitingThreads);
			if (alive) {
				gNumWaitingThreads++; // back in service
			}
//		gNumConfigThreads++;
			else {
				if (0 == --gNumConfigThreads) {
//                    IOLog("MATCH IDLE\n");
					IOLockWakeup( gJobsLock, (event_t) &gNumConfigThreads, /* one-thread */ false );
				}
			}
			IOUnlock( gJobsLock );
		}
	} while (alive);

	if (gIOKitDebug & kIOLogConfig) {
		LOG("config(%p): terminating\n", IOSERVICE_OBFUSCATE(IOThreadSelf()));
	}

	self->release();
}

IOReturn
IOService::waitMatchIdle( UInt32 msToWait )
{
	bool            wait;
	int             waitResult = THREAD_AWAKENED;
	bool            computeDeadline = true;
	AbsoluteTime    deadline;

	IOLockLock( gJobsLock );
	do {
		wait = (0 != gNumConfigThreads);
		if (wait) {
			if (msToWait) {
				if (computeDeadline) {
					clock_interval_to_deadline(
						msToWait, kMillisecondScale, &deadline );
					computeDeadline = false;
				}
				waitResult = IOLockSleepDeadline( gJobsLock, &gNumConfigThreads,
				    deadline, THREAD_UNINT );
			} else {
				waitResult = IOLockSleep( gJobsLock, &gNumConfigThreads,
				    THREAD_UNINT );
			}
		}
	} while (wait && (waitResult != THREAD_TIMED_OUT));
	IOLockUnlock( gJobsLock );

	if (waitResult == THREAD_TIMED_OUT) {
		return kIOReturnTimeout;
	} else {
		return kIOReturnSuccess;
	}
}

void
IOService::cpusRunning(void)
{
	gCPUsRunning = true;
}

void
_IOServiceJob::pingConfig( _IOServiceJob * job )
{
	int         count;
	bool        create;

	assert( job );

	IOTakeLock( gJobsLock );

	gOutstandingJobs++;
	gJobs->setLastObject( job );

	count = gNumWaitingThreads;
//    if( gNumConfigThreads) count++;// assume we're called from a config thread

	create = ((gOutstandingJobs > count)
	    && ((gNumConfigThreads < kMaxConfigThreads)
	    || (job->nub == gIOResources)
	    || !gCPUsRunning));
	if (create) {
		gNumConfigThreads++;
		gNumWaitingThreads++;
	}

	IOUnlock( gJobsLock );

	job->release();

	if (create) {
		if (gIOKitDebug & kIOLogConfig) {
			LOG("config(%d): creating\n", gNumConfigThreads - 1);
		}
		_IOConfigThread::configThread(gNumConfigThreads - 1);
	}

	semaphore_signal( gJobsSemaphore );
}

struct IOServiceMatchContext {
	OSDictionary * table;
	OSObject *     result;
	uint32_t       options;
	uint32_t       state;
	uint32_t       count;
	uint32_t       done;
};

bool
IOService::instanceMatch(const OSObject * entry, void * context)
{
	IOServiceMatchContext * ctx = (typeof(ctx))context;
	IOService *    service = (typeof(service))entry;
	OSDictionary * table   = ctx->table;
	uint32_t       options = ctx->options;
	uint32_t       state   = ctx->state;
	uint32_t       done;
	bool           match;

	done = 0;
	do{
		match = ((state == (state & service->__state[0]))
		    && (0 == (service->__state[0] & kIOServiceInactiveState)));
		if (!match) {
			break;
		}
		ctx->count += table->getCount();
		match = service->matchInternal(table, options, &done);
		ctx->done += done;
	}while (false);
	if (!match) {
		return false;
	}

	if ((kIONotifyOnce & options) && (ctx->done == ctx->count)) {
		service->retain();
		ctx->result = service;
		return true;
	} else if (!ctx->result) {
		ctx->result = OSSet::withObjects((const OSObject **) &service, 1, 1);
	} else {
		((OSSet *)ctx->result)->setObject(service);
	}
	return false;
}

// internal - call with gNotificationLock
OSObject *
IOService::copyExistingServices( OSDictionary * matching,
    IOOptionBits inState, IOOptionBits options )
{
	OSObject *   current = NULL;
	OSIterator * iter;
	IOService *  service;
	OSObject *   obj;
	OSString *   str;

	if (!matching) {
		return NULL;
	}

#if MATCH_DEBUG
	OSSerialize * s = OSSerialize::withCapacity(128);
	matching->serialize(s);
#endif

	if ((obj = matching->getObject(gIOProviderClassKey))
	    && gIOResourcesKey
	    && gIOResourcesKey->isEqualTo(obj)
	    && (service = gIOResources)) {
		if ((inState == (service->__state[0] & inState))
		    && (0 == (service->__state[0] & kIOServiceInactiveState))
		    && service->matchPassive(matching, options)) {
			if (options & kIONotifyOnce) {
				service->retain();
				current = service;
			} else {
				current = OSSet::withObjects((const OSObject **) &service, 1, 1 );
			}
		}
	} else {
		IOServiceMatchContext ctx;
		ctx.table   = matching;
		ctx.state   = inState;
		ctx.count   = 0;
		ctx.done    = 0;
		ctx.options = options;
		ctx.result  = NULL;

		if ((str = OSDynamicCast(OSString, obj))) {
			const OSSymbol * sym = OSSymbol::withString(str);
			OSMetaClass::applyToInstancesOfClassName(sym, instanceMatch, &ctx);
			sym->release();
		} else {
			IOService::gMetaClass.applyToInstances(instanceMatch, &ctx);
		}


		current = ctx.result;

		options |= kIOServiceInternalDone | kIOServiceClassDone;
		if (current && (ctx.done != ctx.count)) {
			OSSet *
			    source = OSDynamicCast(OSSet, current);
			current = NULL;
			while ((service = (IOService *) source->getAnyObject())) {
				if (service->matchPassive(matching, options)) {
					if (options & kIONotifyOnce) {
						service->retain();
						current = service;
						break;
					}
					if (current) {
						((OSSet *)current)->setObject( service );
					} else {
						current = OSSet::withObjects(
							(const OSObject **) &service, 1, 1 );
					}
				}
				source->removeObject(service);
			}
			source->release();
		}
	}

#if MATCH_DEBUG
	{
		OSObject * _current = 0;

		iter = IORegistryIterator::iterateOver( gIOServicePlane,
		    kIORegistryIterateRecursively );
		if (iter) {
			do {
				iter->reset();
				while ((service = (IOService *) iter->getNextObject())) {
					if ((inState == (service->__state[0] & inState))
					    && (0 == (service->__state[0] & kIOServiceInactiveState))
					    && service->matchPassive(matching, 0)) {
						if (options & kIONotifyOnce) {
							service->retain();
							_current = service;
							break;
						}
						if (_current) {
							((OSSet *)_current)->setObject( service );
						} else {
							_current = OSSet::withObjects(
								(const OSObject **) &service, 1, 1 );
						}
					}
				}
			} while (!service && !iter->isValid());
			iter->release();
		}

		if (((current != 0) != (_current != 0))
		    || (current && _current && !current->isEqualTo(_current))) {
			OSSerialize * s1 = OSSerialize::withCapacity(128);
			OSSerialize * s2 = OSSerialize::withCapacity(128);
			current->serialize(s1);
			_current->serialize(s2);
			kprintf("**mismatch** %p %p\n%s\n%s\n%s\n", IOSERVICE_OBFUSCATE(current),
			    IOSERVICE_OBFUSCATE(_current), s->text(), s1->text(), s2->text());
			s1->release();
			s2->release();
		}

		if (_current) {
			_current->release();
		}
	}

	s->release();
#endif

	if (current && (0 == (options & (kIONotifyOnce | kIOServiceExistingSet)))) {
		iter = OSCollectionIterator::withCollection((OSSet *)current );
		current->release();
		current = iter;
	}

	return current;
}

// public version
OSIterator *
IOService::getMatchingServices( OSDictionary * matching )
{
	OSIterator *        iter;

	// is a lock even needed?
	LOCKWRITENOTIFY();

	iter = (OSIterator *) copyExistingServices( matching,
	    kIOServiceMatchedState );

	UNLOCKNOTIFY();

	return iter;
}

IOService *
IOService::copyMatchingService( OSDictionary * matching )
{
	IOService * service;

	// is a lock even needed?
	LOCKWRITENOTIFY();

	service = (IOService *) copyExistingServices( matching,
	    kIOServiceMatchedState, kIONotifyOnce );

	UNLOCKNOTIFY();

	return service;
}

struct _IOServiceMatchingNotificationHandlerRef {
	IOServiceNotificationHandler handler;
	void * ref;
};

static bool
_IOServiceMatchingNotificationHandler( void * target, void * refCon,
    IOService * newService,
    IONotifier * notifier )
{
	return (*((_IOServiceNotifier *) notifier)->compatHandler)(target, refCon, newService);
}

// internal - call with gNotificationLock
IONotifier *
IOService::setNotification(
	const OSSymbol * type, OSDictionary * matching,
	IOServiceMatchingNotificationHandler handler, void * target, void * ref,
	SInt32 priority )
{
	_IOServiceNotifier * notify = NULL;
	OSOrderedSet *      set;

	if (!matching) {
		return NULL;
	}

	notify = new _IOServiceNotifier;
	if (notify && !notify->init()) {
		notify->release();
		notify = NULL;
	}

	if (notify) {
		notify->handler = handler;
		notify->target = target;
		notify->type = type;
		notify->matching = matching;
		matching->retain();
		if (handler == &_IOServiceMatchingNotificationHandler) {
			notify->compatHandler = ((_IOServiceMatchingNotificationHandlerRef *)ref)->handler;
			notify->ref = ((_IOServiceMatchingNotificationHandlerRef *)ref)->ref;
		} else {
			notify->ref = ref;
		}
		notify->priority = priority;
		notify->state = kIOServiceNotifyEnable;
		queue_init( &notify->handlerInvocations );

		////// queue

		if (NULL == (set = (OSOrderedSet *) gNotifications->getObject( type ))) {
			set = OSOrderedSet::withCapacity( 1,
			    IONotifyOrdering, NULL );
			if (set) {
				gNotifications->setObject( type, set );
				set->release();
			}
		}
		notify->whence = set;
		if (set) {
			set->setObject( notify );
		}
	}

	return notify;
}

// internal - call with gNotificationLock
IONotifier *
IOService::doInstallNotification(
	const OSSymbol * type, OSDictionary * matching,
	IOServiceMatchingNotificationHandler handler,
	void * target, void * ref,
	SInt32 priority, OSIterator ** existing )
{
	OSIterator *        exist;
	IONotifier *        notify;
	IOOptionBits        inState;

	if (!matching) {
		return NULL;
	}

	if (type == gIOPublishNotification) {
		inState = kIOServiceRegisteredState;
	} else if (type == gIOFirstPublishNotification) {
		inState = kIOServiceFirstPublishState;
	} else if (type == gIOMatchedNotification) {
		inState = kIOServiceMatchedState;
	} else if (type == gIOFirstMatchNotification) {
		inState = kIOServiceFirstMatchState;
	} else if ((type == gIOTerminatedNotification) || (type == gIOWillTerminateNotification)) {
		inState = 0;
	} else {
		return NULL;
	}

	notify = setNotification( type, matching, handler, target, ref, priority );

	if (inState) {
		// get the current set
		exist = (OSIterator *) copyExistingServices( matching, inState );
	} else {
		exist = NULL;
	}

	*existing = exist;

	return notify;
}

#if !defined(__LP64__)
IONotifier *
IOService::installNotification(const OSSymbol * type, OSDictionary * matching,
    IOServiceNotificationHandler handler,
    void * target, void * refCon,
    SInt32 priority, OSIterator ** existing )
{
	IONotifier * result;
	_IOServiceMatchingNotificationHandlerRef ref;
	ref.handler = handler;
	ref.ref     = refCon;

	result = (_IOServiceNotifier *) installNotification( type, matching,
	    &_IOServiceMatchingNotificationHandler,
	    target, &ref, priority, existing );
	if (result) {
		matching->release();
	}

	return result;
}
#endif /* !defined(__LP64__) */


IONotifier *
IOService::installNotification(
	const OSSymbol * type, OSDictionary * matching,
	IOServiceMatchingNotificationHandler handler,
	void * target, void * ref,
	SInt32 priority, OSIterator ** existing )
{
	IONotifier * notify;

	LOCKWRITENOTIFY();

	notify = doInstallNotification( type, matching, handler, target, ref,
	    priority, existing );

	// in case handler remove()s
	if (notify) {
		notify->retain();
	}

	UNLOCKNOTIFY();

	return notify;
}

IONotifier *
IOService::addNotification(
	const OSSymbol * type, OSDictionary * matching,
	IOServiceNotificationHandler handler,
	void * target, void * refCon,
	SInt32 priority )
{
	IONotifier * result;
	_IOServiceMatchingNotificationHandlerRef ref;

	ref.handler = handler;
	ref.ref     = refCon;

	result = addMatchingNotification(type, matching, &_IOServiceMatchingNotificationHandler,
	    target, &ref, priority);

	if (result) {
		matching->release();
	}

	return result;
}

IONotifier *
IOService::addMatchingNotification(
	const OSSymbol * type, OSDictionary * matching,
	IOServiceMatchingNotificationHandler handler,
	void * target, void * ref,
	SInt32 priority )
{
	OSIterator *                existing = NULL;
	IONotifier *                ret;
	_IOServiceNotifier *        notify;
	IOService *                 next;

	ret = notify = (_IOServiceNotifier *) installNotification( type, matching,
	    handler, target, ref, priority, &existing );
	if (!ret) {
		return NULL;
	}

	// send notifications for existing set
	if (existing) {
		while ((next = (IOService *) existing->getNextObject())) {
			if (0 == (next->__state[0] & kIOServiceInactiveState)) {
				next->invokeNotifier( notify );
			}
		}
		existing->release();
	}

	LOCKWRITENOTIFY();
	bool removed = (NULL == notify->whence);
	notify->release();
	if (removed) {
		ret = gIOServiceNullNotifier;
	}
	UNLOCKNOTIFY();

	return ret;
}

static bool
IOServiceMatchingNotificationHandlerToBlock( void * target __unused, void * refCon,
    IOService * newService,
    IONotifier * notifier )
{
	return ((IOServiceMatchingNotificationHandlerBlock) refCon)(newService, notifier);
}

IONotifier *
IOService::addMatchingNotification(
	const OSSymbol * type, OSDictionary * matching,
	SInt32 priority,
	IOServiceMatchingNotificationHandlerBlock handler)
{
	IONotifier * notify;
	void       * block;

	block = Block_copy(handler);
	if (!block) {
		return NULL;
	}

	notify = addMatchingNotification(type, matching,
	    &IOServiceMatchingNotificationHandlerToBlock, NULL, block, priority);

	if (!notify) {
		Block_release(block);
	}

	return notify;
}


bool
IOService::syncNotificationHandler(
	void * /* target */, void * ref,
	IOService * newService,
	IONotifier * notifier )
{
	LOCKWRITENOTIFY();
	if (!*((IOService **) ref)) {
		newService->retain();
		(*(IOService **) ref) = newService;
		WAKEUPNOTIFY(ref);
	}
	UNLOCKNOTIFY();

	return false;
}

IOService *
IOService::waitForMatchingService( OSDictionary * matching,
    uint64_t timeout)
{
	IONotifier *        notify = NULL;
	// priority doesn't help us much since we need a thread wakeup
	SInt32              priority = 0;
	IOService *         result;

	if (!matching) {
		return NULL;
	}

	result = NULL;

	LOCKWRITENOTIFY();
	do{
		result = (IOService *) copyExistingServices( matching,
		    kIOServiceMatchedState, kIONotifyOnce );
		if (result) {
			break;
		}
		notify = IOService::setNotification( gIOMatchedNotification, matching,
		    &IOService::syncNotificationHandler, (void *) NULL,
		    &result, priority );
		if (!notify) {
			break;
		}
		if (UINT64_MAX != timeout) {
			AbsoluteTime deadline;
			nanoseconds_to_absolutetime(timeout, &deadline);
			clock_absolutetime_interval_to_deadline(deadline, &deadline);
			SLEEPNOTIFYTO(&result, deadline);
		} else {
			SLEEPNOTIFY(&result);
		}
	}while (false);

	UNLOCKNOTIFY();

	if (notify) {
		notify->remove(); // dequeues
	}
	return result;
}

IOService *
IOService::waitForService( OSDictionary * matching,
    mach_timespec_t * timeout )
{
	IOService * result;
	uint64_t    timeoutNS;

	if (timeout) {
		timeoutNS = timeout->tv_sec;
		timeoutNS *= kSecondScale;
		timeoutNS += timeout->tv_nsec;
	} else {
		timeoutNS = UINT64_MAX;
	}

	result = waitForMatchingService(matching, timeoutNS);

	matching->release();
	if (result) {
		result->release();
	}

	return result;
}

__dead2
void
IOService::deliverNotification( const OSSymbol * type,
    IOOptionBits orNewState, IOOptionBits andNewState )
{
	panic("deliverNotification");
}

OSArray *
IOService::copyNotifiers(const OSSymbol * type,
    IOOptionBits orNewState, IOOptionBits andNewState )
{
	_IOServiceNotifier * notify;
	OSIterator *         iter;
	OSArray *            willSend = NULL;

	lockForArbitration();

	if ((0 == (__state[0] & kIOServiceInactiveState))
	    || (type == gIOTerminatedNotification)
	    || (type == gIOWillTerminateNotification)) {
		LOCKREADNOTIFY();

		iter = OSCollectionIterator::withCollection((OSOrderedSet *)
		    gNotifications->getObject( type ));

		if (iter) {
			while ((notify = (_IOServiceNotifier *) iter->getNextObject())) {
				if (matchPassive(notify->matching, 0)
				    && (kIOServiceNotifyEnable & notify->state)) {
					if (NULL == willSend) {
						willSend = OSArray::withCapacity(8);
					}
					if (willSend) {
						willSend->setObject( notify );
					}
				}
			}
			iter->release();
		}
		__state[0] = (__state[0] | orNewState) & andNewState;
		UNLOCKNOTIFY();
	}

	unlockForArbitration();

	return willSend;
}

IOOptionBits
IOService::getState( void ) const
{
	return __state[0];
}

/*
 * Helpers to make matching objects for simple cases
 */

OSDictionary *
IOService::serviceMatching( const OSString * name,
    OSDictionary * table )
{
	const OSString *    str;

	str = OSSymbol::withString(name);
	if (!str) {
		return NULL;
	}

	if (!table) {
		table = OSDictionary::withCapacity( 2 );
	}
	if (table) {
		table->setObject(gIOProviderClassKey, (OSObject *)str );
	}
	str->release();

	return table;
}

OSDictionary *
IOService::serviceMatching( const char * name,
    OSDictionary * table )
{
	const OSString *    str;

	str = OSSymbol::withCString( name );
	if (!str) {
		return NULL;
	}

	table = serviceMatching( str, table );
	str->release();
	return table;
}

OSDictionary *
IOService::nameMatching( const OSString * name,
    OSDictionary * table )
{
	if (!table) {
		table = OSDictionary::withCapacity( 2 );
	}
	if (table) {
		table->setObject( gIONameMatchKey, (OSObject *)name );
	}

	return table;
}

OSDictionary *
IOService::nameMatching( const char * name,
    OSDictionary * table )
{
	const OSString *    str;

	str = OSSymbol::withCString( name );
	if (!str) {
		return NULL;
	}

	table = nameMatching( str, table );
	str->release();
	return table;
}

OSDictionary *
IOService::resourceMatching( const OSString * str,
    OSDictionary * table )
{
	table = serviceMatching( gIOResourcesKey, table );
	if (table) {
		table->setObject( gIOResourceMatchKey, (OSObject *) str );
	}

	return table;
}

OSDictionary *
IOService::resourceMatching( const char * name,
    OSDictionary * table )
{
	const OSSymbol *    str;

	str = OSSymbol::withCString( name );
	if (!str) {
		return NULL;
	}

	table = resourceMatching( str, table );
	str->release();

	return table;
}

OSDictionary *
IOService::propertyMatching( const OSSymbol * key, const OSObject * value,
    OSDictionary * table )
{
	OSDictionary * properties;

	properties = OSDictionary::withCapacity( 2 );
	if (!properties) {
		return NULL;
	}
	properties->setObject( key, value );

	if (!table) {
		table = OSDictionary::withCapacity( 2 );
	}
	if (table) {
		table->setObject( gIOPropertyMatchKey, properties );
	}

	properties->release();

	return table;
}

OSDictionary *
IOService::registryEntryIDMatching( uint64_t entryID,
    OSDictionary * table )
{
	OSNumber *     num;

	num = OSNumber::withNumber( entryID, 64 );
	if (!num) {
		return NULL;
	}

	if (!table) {
		table = OSDictionary::withCapacity( 2 );
	}
	if (table) {
		table->setObject( gIORegistryEntryIDKey, num );
	}

	if (num) {
		num->release();
	}

	return table;
}


/*
 * _IOServiceNotifier
 */

// wait for all threads, other than the current one,
//  to exit the handler

void
_IOServiceNotifier::wait()
{
	_IOServiceNotifierInvocation * next;
	bool doWait;

	do {
		doWait = false;
		queue_iterate( &handlerInvocations, next,
		    _IOServiceNotifierInvocation *, link) {
			if (next->thread != current_thread()) {
				doWait = true;
				break;
			}
		}
		if (doWait) {
			state |= kIOServiceNotifyWaiter;
			SLEEPNOTIFY(this);
		}
	} while (doWait);
}

void
_IOServiceNotifier::free()
{
	assert( queue_empty( &handlerInvocations ));

	if (handler == &IOServiceMatchingNotificationHandlerToBlock) {
		Block_release(ref);
	}

	OSObject::free();
}

void
_IOServiceNotifier::remove()
{
	LOCKWRITENOTIFY();

	if (whence) {
		whence->removeObject((OSObject *) this );
		whence = NULL;
	}
	if (matching) {
		matching->release();
		matching = NULL;
	}

	state &= ~kIOServiceNotifyEnable;

	wait();

	UNLOCKNOTIFY();

	release();
}

bool
_IOServiceNotifier::disable()
{
	bool        ret;

	LOCKWRITENOTIFY();

	ret = (0 != (kIOServiceNotifyEnable & state));
	state &= ~kIOServiceNotifyEnable;
	if (ret) {
		wait();
	}

	UNLOCKNOTIFY();

	return ret;
}

void
_IOServiceNotifier::enable( bool was )
{
	LOCKWRITENOTIFY();
	if (was) {
		state |= kIOServiceNotifyEnable;
	} else {
		state &= ~kIOServiceNotifyEnable;
	}
	UNLOCKNOTIFY();
}


/*
 * _IOServiceNullNotifier
 */

void
_IOServiceNullNotifier::taggedRetain(const void *tag) const
{
}
void
_IOServiceNullNotifier::taggedRelease(const void *tag, const int when) const
{
}
void
_IOServiceNullNotifier::free()
{
}
void
_IOServiceNullNotifier::wait()
{
}
void
_IOServiceNullNotifier::remove()
{
}
void
_IOServiceNullNotifier::enable(bool was)
{
}
bool
_IOServiceNullNotifier::disable()
{
	return false;
}

/*
 * IOResources
 */

IOService *
IOResources::resources( void )
{
	IOResources *       inst;

	inst = new IOResources;
	if (inst && !inst->init()) {
		inst->release();
		inst = NULL;
	}

	return inst;
}

bool
IOResources::init( OSDictionary * dictionary )
{
	// Do super init first
	if (!IOService::init()) {
		return false;
	}

	// Allow PAL layer to publish a value
	const char *property_name;
	int property_value;

	pal_get_resource_property( &property_name, &property_value );

	if (property_name) {
		OSNumber *num;
		const OSSymbol *        sym;

		if ((num = OSNumber::withNumber(property_value, 32)) != NULL) {
			if ((sym = OSSymbol::withCString( property_name)) != NULL) {
				this->setProperty( sym, num );
				sym->release();
			}
			num->release();
		}
	}

	return true;
}

IOReturn
IOResources::newUserClient(task_t owningTask, void * securityID,
    UInt32 type, OSDictionary * properties,
    IOUserClient ** handler)
{
	return kIOReturnUnsupported;
}

IOWorkLoop *
IOResources::getWorkLoop() const
{
	// If we are the resource root
	// then use the platform's workloop
	if (this == (IOResources *) gIOResources) {
		return getPlatform()->getWorkLoop();
	} else {
		return IOService::getWorkLoop();
	}
}

static bool
IOResourcesMatchPropertyTable(IOService * resources, OSDictionary * table)
{
	OSObject *          prop;
	OSString *          str;
	OSSet *             set;
	OSIterator *        iter;
	OSObject *          obj;
	OSArray *           keys;
	bool                ok = true;

	prop = table->getObject( gIOResourceMatchKey );
	str = OSDynamicCast( OSString, prop );
	if (str) {
		ok = (NULL != resources->getProperty( str ));
	} else if ((set = OSDynamicCast( OSSet, prop))) {
		iter = OSCollectionIterator::withCollection( set );
		ok = (iter != NULL);
		while (ok && (str = OSDynamicCast( OSString, iter->getNextObject()))) {
			ok = (NULL != resources->getProperty( str ));
		}

		if (iter) {
			iter->release();
		}
	} else if ((prop = table->getObject(gIOResourceMatchedKey))) {
		obj = resources->copyProperty(gIOResourceMatchedKey);
		keys = OSDynamicCast(OSArray, obj);
		ok = false;
		if (keys) {
			// assuming OSSymbol
			ok = ((-1U) != keys->getNextIndexOfObject(prop, 0));
		}
		OSSafeReleaseNULL(obj);
	}

	return ok;
}

bool
IOResources::matchPropertyTable( OSDictionary * table )
{
	return IOResourcesMatchPropertyTable(this, table);
}

/*
 * IOUserResources
 */

IOService *
IOUserResources::resources( void )
{
	IOUserResources *       inst;

	inst = OSTypeAlloc(IOUserResources);
	if (inst && !inst->init()) {
		inst->release();
		inst = NULL;
	}

	return inst;
}

bool
IOUserResources::init( OSDictionary * dictionary )
{
	// Do super init first
	if (!IOService::init()) {
		return false;
	}
	return true;
}

IOReturn
IOUserResources::newUserClient(task_t owningTask, void * securityID,
    UInt32 type, OSDictionary * properties,
    IOUserClient ** handler)
{
	return kIOReturnUnsupported;
}

IOWorkLoop *
IOUserResources::getWorkLoop() const
{
	return getPlatform()->getWorkLoop();
}

bool
IOUserResources::matchPropertyTable( OSDictionary * table )
{
	return IOResourcesMatchPropertyTable(this, table);
}

// --

void
IOService::consoleLockTimer(thread_call_param_t p0, thread_call_param_t p1)
{
	IOService::updateConsoleUsers(NULL, 0);
}

void
IOService::updateConsoleUsers(OSArray * consoleUsers, IOMessage systemMessage)
{
	IORegistryEntry * regEntry;
	OSObject *        locked = kOSBooleanFalse;
	uint32_t          idx;
	bool              publish;
	OSDictionary *    user;
	static IOMessage  sSystemPower;
	clock_sec_t       now = 0;
	clock_usec_t      microsecs;

	regEntry = IORegistryEntry::getRegistryRoot();

	if (!gIOChosenEntry) {
		gIOChosenEntry = IORegistryEntry::fromPath("/chosen", gIODTPlane);
	}

	IOLockLock(gIOConsoleUsersLock);

	if (systemMessage) {
		sSystemPower = systemMessage;
#if HIBERNATION
		if (kIOMessageSystemHasPoweredOn == systemMessage) {
			uint32_t lockState = IOHibernateWasScreenLocked();
			switch (lockState) {
			case 0:
				break;
			case kIOScreenLockLocked:
			case kIOScreenLockFileVaultDialog:
				gIOConsoleBooterLockState = kOSBooleanTrue;
				break;
			case kIOScreenLockNoLock:
				gIOConsoleBooterLockState = NULL;
				break;
			case kIOScreenLockUnlocked:
			default:
				gIOConsoleBooterLockState = kOSBooleanFalse;
				break;
			}
		}
#endif /* HIBERNATION */
	}

	if (consoleUsers) {
		OSNumber * num = NULL;
		bool       loginLocked = true;

		gIOConsoleLoggedIn = false;
		for (idx = 0;
		    (user = OSDynamicCast(OSDictionary, consoleUsers->getObject(idx)));
		    idx++) {
			gIOConsoleLoggedIn |= ((kOSBooleanTrue == user->getObject(gIOConsoleSessionOnConsoleKey))
			    && (kOSBooleanTrue == user->getObject(gIOConsoleSessionLoginDoneKey)));

			loginLocked &= (kOSBooleanTrue == user->getObject(gIOConsoleSessionScreenIsLockedKey));
			if (!num) {
				num = OSDynamicCast(OSNumber, user->getObject(gIOConsoleSessionScreenLockedTimeKey));
			}
		}
#if HIBERNATION
		if (!loginLocked) {
			gIOConsoleBooterLockState = NULL;
		}
		IOLog("IOConsoleUsers: time(%d) %ld->%d, lin %d, llk %d, \n",
		    (num != NULL), gIOConsoleLockTime, (num ? num->unsigned32BitValue() : 0),
		    gIOConsoleLoggedIn, loginLocked);
#endif /* HIBERNATION */
		gIOConsoleLockTime = num ? num->unsigned32BitValue() : 0;
	}

	if (!gIOConsoleLoggedIn
	    || (kIOMessageSystemWillSleep == sSystemPower)
	    || (kIOMessageSystemPagingOff == sSystemPower)) {
		locked = kOSBooleanTrue;
	}
#if HIBERNATION
	else if (gIOConsoleBooterLockState) {
		locked = gIOConsoleBooterLockState;
	}
#endif /* HIBERNATION */
	else if (gIOConsoleLockTime) {
		clock_get_calendar_microtime(&now, &microsecs);
		if (gIOConsoleLockTime > now) {
			AbsoluteTime deadline;
			clock_interval_to_deadline(gIOConsoleLockTime - now, kSecondScale, &deadline);
			thread_call_enter_delayed(gIOConsoleLockCallout, deadline);
		} else {
			locked = kOSBooleanTrue;
		}
	}

	publish = (consoleUsers || (locked != regEntry->getProperty(gIOConsoleLockedKey)));
	if (publish) {
		regEntry->setProperty(gIOConsoleLockedKey, locked);
		if (consoleUsers) {
			regEntry->setProperty(gIOConsoleUsersKey, consoleUsers);
		}
		OSIncrementAtomic( &gIOConsoleUsersSeed );
	}

#if HIBERNATION
	if (gIOChosenEntry) {
		if (locked == kOSBooleanTrue) {
			gIOScreenLockState = kIOScreenLockLocked;
		} else if (gIOConsoleLockTime) {
			gIOScreenLockState = kIOScreenLockUnlocked;
		} else {
			gIOScreenLockState = kIOScreenLockNoLock;
		}
		gIOChosenEntry->setProperty(kIOScreenLockStateKey, &gIOScreenLockState, sizeof(gIOScreenLockState));

		IOLog("IOConsoleUsers: gIOScreenLockState %d, hs %d, bs %d, now %ld, sm 0x%x\n",
		    gIOScreenLockState, gIOHibernateState, (gIOConsoleBooterLockState != NULL), now, systemMessage);
	}
#endif /* HIBERNATION */

	IOLockUnlock(gIOConsoleUsersLock);

	if (publish) {
		publishResource( gIOConsoleUsersSeedKey, gIOConsoleUsersSeedValue );

		MessageClientsContext context;

		context.service  = getServiceRoot();
		context.type     = kIOMessageConsoleSecurityChange;
		context.argument = (void *) regEntry;
		context.argSize  = 0;

		applyToInterestNotifiers(getServiceRoot(), gIOConsoleSecurityInterest,
		    &messageClientsApplier, &context );
	}
}

IOReturn
IOResources::setProperties( OSObject * properties )
{
	IOReturn                    err;
	const OSSymbol *            key;
	OSDictionary *              dict;
	OSCollectionIterator *      iter;

	err = IOUserClient::clientHasPrivilege(current_task(), kIOClientPrivilegeAdministrator);
	if (kIOReturnSuccess != err) {
		return err;
	}

	dict = OSDynamicCast(OSDictionary, properties);
	if (NULL == dict) {
		return kIOReturnBadArgument;
	}

	iter = OSCollectionIterator::withCollection( dict);
	if (NULL == iter) {
		return kIOReturnBadArgument;
	}

	while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
		if (gIOConsoleUsersKey == key) {
			do{
				OSArray * consoleUsers;
				consoleUsers = OSDynamicCast(OSArray, dict->getObject(key));
				if (!consoleUsers) {
					continue;
				}
				IOService::updateConsoleUsers(consoleUsers, 0);
			}while (false);
		}

		publishResource( key, dict->getObject(key));
	}

	iter->release();

	return kIOReturnSuccess;
}

/*
 * Helpers for matching dictionaries.
 * Keys existing in matching are checked in properties.
 * Keys may be a string or OSCollection of IOStrings
 */

bool
IOService::compareProperty( OSDictionary * matching,
    const char *   key )
{
	OSObject *  value;
	OSObject *  prop;
	bool        ok;

	value = matching->getObject( key );
	if (value) {
		prop = copyProperty(key);
		ok = value->isEqualTo(prop);
		if (prop) {
			prop->release();
		}
	} else {
		ok = true;
	}

	return ok;
}


bool
IOService::compareProperty( OSDictionary *   matching,
    const OSString * key )
{
	OSObject *  value;
	OSObject *  prop;
	bool        ok;

	value = matching->getObject( key );
	if (value) {
		prop = copyProperty(key);
		ok = value->isEqualTo(prop);
		if (prop) {
			prop->release();
		}
	} else {
		ok = true;
	}

	return ok;
}

bool
IOService::compareProperties( OSDictionary * matching,
    OSCollection * keys )
{
	OSCollectionIterator *      iter;
	const OSString *            key;
	bool                        ok = true;

	if (!matching || !keys) {
		return false;
	}

	iter = OSCollectionIterator::withCollection( keys );

	if (iter) {
		while (ok && (key = OSDynamicCast( OSString, iter->getNextObject()))) {
			ok = compareProperty( matching, key );
		}

		iter->release();
	}
	keys->release(); // !! consume a ref !!

	return ok;
}

/* Helper to add a location matching dict to the table */

OSDictionary *
IOService::addLocation( OSDictionary * table )
{
	OSDictionary *      dict;

	if (!table) {
		return NULL;
	}

	dict = OSDictionary::withCapacity( 1 );
	if (dict) {
		bool ok = table->setObject( gIOLocationMatchKey, dict );
		dict->release();
		if (!ok) {
			dict = NULL;
		}
	}

	return dict;
}

/*
 * Go looking for a provider to match a location dict.
 */

IOService *
IOService::matchLocation( IOService * /* client */ )
{
	IOService * parent;

	parent = getProvider();

	if (parent) {
		parent = parent->matchLocation( this );
	}

	return parent;
}

bool
IOService::matchInternal(OSDictionary * table, uint32_t options, uint32_t * did)
{
	OSString *          matched;
	OSObject *          obj;
	OSString *          str;
	IORegistryEntry *   entry;
	OSNumber *          num;
	bool                match = true;
	bool                changesOK = (0 != (kIOServiceChangesOK & options));
	uint32_t            count;
	uint32_t            done;

	do{
		count = table->getCount();
		done = 0;

		str = OSDynamicCast(OSString, table->getObject(gIOProviderClassKey));
		if (str) {
			done++;
			match = ((kIOServiceClassDone & options) || (NULL != metaCast(str)));
#if MATCH_DEBUG
			match = (0 != metaCast( str ));
			if ((kIOServiceClassDone & options) && !match) {
				panic("classDone");
			}
#endif
			if ((!match) || (done == count)) {
				break;
			}
		}

		obj = table->getObject( gIONameMatchKey );
		if (obj) {
			done++;
			match = compareNames( obj, changesOK ? &matched : NULL );
			if (!match) {
				break;
			}
			if (changesOK && matched) {
				// leave a hint as to which name matched
				table->setObject( gIONameMatchedKey, matched );
				matched->release();
			}
			if (done == count) {
				break;
			}
		}

		str = OSDynamicCast( OSString, table->getObject( gIOLocationMatchKey ));
		if (str) {
			const OSSymbol * sym;
			done++;
			match = false;
			sym = copyLocation();
			if (sym) {
				match = sym->isEqualTo( str );
				sym->release();
			}
			if ((!match) || (done == count)) {
				break;
			}
		}

		obj = table->getObject( gIOPropertyMatchKey );
		if (obj) {
			OSDictionary * dict;
			OSDictionary * nextDict;
			OSIterator *   iter;
			done++;
			match = false;
			dict = dictionaryWithProperties();
			if (dict) {
				nextDict = OSDynamicCast( OSDictionary, obj);
				if (nextDict) {
					iter = NULL;
				} else {
					iter = OSCollectionIterator::withCollection(
						OSDynamicCast(OSCollection, obj));
				}

				while (nextDict
				    || (iter && (NULL != (nextDict = OSDynamicCast(OSDictionary,
				    iter->getNextObject()))))) {
					match = dict->isEqualTo( nextDict, nextDict);
					if (match) {
						break;
					}
					nextDict = NULL;
				}
				dict->release();
				if (iter) {
					iter->release();
				}
			}
			if ((!match) || (done == count)) {
				break;
			}
		}

		obj = table->getObject( gIOPropertyExistsMatchKey );
		if (obj) {
			OSDictionary * dict;
			OSString     * nextKey;
			OSIterator *   iter;
			done++;
			match = false;
			dict = dictionaryWithProperties();
			if (dict) {
				nextKey = OSDynamicCast( OSString, obj);
				if (nextKey) {
					iter = NULL;
				} else {
					iter = OSCollectionIterator::withCollection(
						OSDynamicCast(OSCollection, obj));
				}

				while (nextKey
				    || (iter && (NULL != (nextKey = OSDynamicCast(OSString,
				    iter->getNextObject()))))) {
					match = (NULL != dict->getObject(nextKey));
					if (match) {
						break;
					}
					nextKey = NULL;
				}
				dict->release();
				if (iter) {
					iter->release();
				}
			}
			if ((!match) || (done == count)) {
				break;
			}
		}

		str = OSDynamicCast( OSString, table->getObject( gIOPathMatchKey ));
		if (str) {
			done++;
			entry = IORegistryEntry::fromPath( str->getCStringNoCopy());
			match = (this == entry);
			if (entry) {
				entry->release();
			}
			if ((!match) || (done == count)) {
				break;
			}
		}

		num = OSDynamicCast( OSNumber, table->getObject( gIORegistryEntryIDKey ));
		if (num) {
			done++;
			match = (getRegistryEntryID() == num->unsigned64BitValue());
			if ((!match) || (done == count)) {
				break;
			}
		}

		num = OSDynamicCast( OSNumber, table->getObject( gIOMatchedServiceCountKey ));
		if (num) {
			OSIterator *        iter;
			IOService *         service = NULL;
			UInt32              serviceCount = 0;

			done++;
			iter = getClientIterator();
			if (iter) {
				while ((service = (IOService *) iter->getNextObject())) {
					if (kIOServiceInactiveState & service->__state[0]) {
						continue;
					}
					if (NULL == service->getProperty( gIOMatchCategoryKey )) {
						continue;
					}
					++serviceCount;
				}
				iter->release();
			}
			match = (serviceCount == num->unsigned32BitValue());
			if ((!match) || (done == count)) {
				break;
			}
		}

#define propMatch(key)                                  \
	obj = table->getObject(key);                    \
	if (obj)                                        \
	{                                               \
	    OSObject * prop;                            \
	    done++;                                     \
	    prop = copyProperty(key);                   \
	    match = obj->isEqualTo(prop);               \
	    if (prop) prop->release();                  \
	    if ((!match) || (done == count)) break;     \
	}
		propMatch(gIOBSDNameKey)
		propMatch(gIOBSDMajorKey)
		propMatch(gIOBSDMinorKey)
		propMatch(gIOBSDUnitKey)
#undef propMatch
	}while (false);

	if (did) {
		*did = done;
	}
	return match;
}

bool
IOService::passiveMatch( OSDictionary * table, bool changesOK )
{
	return matchPassive(table, changesOK ? kIOServiceChangesOK : 0);
}

bool
IOService::matchPassive(OSDictionary * table, uint32_t options)
{
	IOService *         where;
	OSDictionary *      nextTable;
	SInt32              score;
	OSNumber *          newPri;
	bool                match = true;
	bool                matchParent = false;
	uint32_t            count;
	uint32_t            done;

	assert( table );

#if !CONFIG_EMBEDDED
	OSArray* aliasServiceRegIds = NULL;
	IOService* foundAlternateService = NULL;
#endif

#if MATCH_DEBUG
	OSDictionary * root = table;
#endif

	where = this;
	do{
		do{
			count = table->getCount();
			if (!(kIOServiceInternalDone & options)) {
				match = where->matchInternal(table, options, &done);
				// don't call family if we've done all the entries in the table
				if ((!match) || (done == count)) {
					break;
				}
			}

			// pass in score from property table
			score = IOServiceObjectOrder( table, (void *) gIOProbeScoreKey);

			// do family specific matching
			match = where->matchPropertyTable( table, &score );

			if (!match) {
#if IOMATCHDEBUG
				if (kIOLogMatch & getDebugFlags( table )) {
					LOG("%s: family specific matching fails\n", where->getName());
				}
#endif
				break;
			}

			if (kIOServiceChangesOK & options) {
				// save the score
				newPri = OSNumber::withNumber( score, 32 );
				if (newPri) {
					table->setObject( gIOProbeScoreKey, newPri );
					newPri->release();
				}
			}

			options = 0;
			matchParent = false;

			nextTable = OSDynamicCast(OSDictionary,
			    table->getObject( gIOParentMatchKey ));
			if (nextTable) {
				// look for a matching entry anywhere up to root
				match = false;
				matchParent = true;
				table = nextTable;
				break;
			}

			table = OSDynamicCast(OSDictionary,
			    table->getObject( gIOLocationMatchKey ));
			if (table) {
				// look for a matching entry at matchLocation()
				match = false;
				where = where->getProvider();
				if (where && (where = where->matchLocation(where))) {
					continue;
				}
			}
			break;
		}while (true);

		if (match == true) {
			break;
		}

		if (matchParent == true) {
#if !CONFIG_EMBEDDED
			// check if service has an alias to search its other "parents" if a parent match isn't found
			OSObject * prop = where->copyProperty(gIOServiceLegacyMatchingRegistryIDKey);
			OSNumber * alternateRegistryID = OSDynamicCast(OSNumber, prop);
			if (alternateRegistryID != NULL) {
				if (aliasServiceRegIds == NULL) {
					aliasServiceRegIds = OSArray::withCapacity(sizeof(alternateRegistryID));
				}
				aliasServiceRegIds->setObject(alternateRegistryID);
			}
			OSSafeReleaseNULL(prop);
#endif
		} else {
			break;
		}

		where = where->getProvider();
#if !CONFIG_EMBEDDED
		if (where == NULL) {
			// there were no matching parent services, check to see if there are aliased services that have a matching parent
			if (aliasServiceRegIds != NULL) {
				unsigned int numAliasedServices = aliasServiceRegIds->getCount();
				if (numAliasedServices != 0) {
					OSNumber* alternateRegistryID = OSDynamicCast(OSNumber, aliasServiceRegIds->getObject(numAliasedServices - 1));
					if (alternateRegistryID != NULL) {
						OSDictionary* alternateMatchingDict = IOService::registryEntryIDMatching(alternateRegistryID->unsigned64BitValue());
						aliasServiceRegIds->removeObject(numAliasedServices - 1);
						if (alternateMatchingDict != NULL) {
							OSSafeReleaseNULL(foundAlternateService);
							foundAlternateService = IOService::copyMatchingService(alternateMatchingDict);
							alternateMatchingDict->release();
							if (foundAlternateService != NULL) {
								where = foundAlternateService;
							}
						}
					}
				}
			}
		}
#endif
	}while (where != NULL);

#if !CONFIG_EMBEDDED
	OSSafeReleaseNULL(foundAlternateService);
	OSSafeReleaseNULL(aliasServiceRegIds);
#endif

#if MATCH_DEBUG
	if (where != this) {
		OSSerialize * s = OSSerialize::withCapacity(128);
		root->serialize(s);
		kprintf("parent match 0x%llx, %d,\n%s\n", getRegistryEntryID(), match, s->text());
		s->release();
	}
#endif

	return match;
}


IOReturn
IOService::newUserClient( task_t owningTask, void * securityID,
    UInt32 type, OSDictionary * properties,
    IOUserClient ** handler )
{
	const OSSymbol *userClientClass = NULL;
	IOUserClient *client;
	OSObject *prop;
	OSObject *temp;

	if (reserved && reserved->uvars && reserved->uvars->userServer) {
		return reserved->uvars->userServer->serviceNewUserClient(this, owningTask, securityID, type, properties, handler);
	}

	if (kIOReturnSuccess == newUserClient( owningTask, securityID, type, handler )) {
		return kIOReturnSuccess;
	}

	// First try my own properties for a user client class name
	prop = copyProperty(gIOUserClientClassKey);
	if (prop) {
		if (OSDynamicCast(OSSymbol, prop)) {
			userClientClass = (const OSSymbol *) prop;
		} else if (OSDynamicCast(OSString, prop)) {
			userClientClass = OSSymbol::withString((OSString *) prop);
			if (userClientClass) {
				setProperty(gIOUserClientClassKey,
				    (OSObject *) userClientClass);
			}
		}
	}

	// Didn't find one so lets just bomb out now without further ado.
	if (!userClientClass) {
		OSSafeReleaseNULL(prop);
		return kIOReturnUnsupported;
	}

	// This reference is consumed by the IOServiceOpen call
	temp = OSMetaClass::allocClassWithName(userClientClass);
	OSSafeReleaseNULL(prop);
	if (!temp) {
		return kIOReturnNoMemory;
	}

	if (OSDynamicCast(IOUserClient, temp)) {
		client = (IOUserClient *) temp;
	} else {
		temp->release();
		return kIOReturnUnsupported;
	}

	if (!client->initWithTask(owningTask, securityID, type, properties)) {
		client->release();
		return kIOReturnBadArgument;
	}

	if (!client->attach(this)) {
		client->release();
		return kIOReturnUnsupported;
	}

	if (!client->start(this)) {
		client->detach(this);
		client->release();
		return kIOReturnUnsupported;
	}

	*handler = client;
	return kIOReturnSuccess;
}

IOReturn
IOService::newUserClient( task_t owningTask, void * securityID,
    UInt32 type, IOUserClient ** handler )
{
	return kIOReturnUnsupported;
}

IOReturn
IOService::requestProbe( IOOptionBits options )
{
	return kIOReturnUnsupported;
}

/*
 * Convert an IOReturn to text. Subclasses which add additional
 * IOReturn's should override this method and call
 * super::stringFromReturn if the desired value is not found.
 */

const char *
IOService::stringFromReturn( IOReturn rtn )
{
	static const IONamedValue IOReturn_values[] = {
		{kIOReturnSuccess, "success"                           },
		{kIOReturnError, "general error"                     },
		{kIOReturnNoMemory, "memory allocation error"           },
		{kIOReturnNoResources, "resource shortage"                 },
		{kIOReturnIPCError, "Mach IPC failure"                  },
		{kIOReturnNoDevice, "no such device"                    },
		{kIOReturnNotPrivileged, "privilege violation"               },
		{kIOReturnBadArgument, "invalid argument"                  },
		{kIOReturnLockedRead, "device is read locked"             },
		{kIOReturnLockedWrite, "device is write locked"            },
		{kIOReturnExclusiveAccess, "device is exclusive access"        },
		{kIOReturnBadMessageID, "bad IPC message ID"                },
		{kIOReturnUnsupported, "unsupported function"              },
		{kIOReturnVMError, "virtual memory error"              },
		{kIOReturnInternalError, "internal driver error"             },
		{kIOReturnIOError, "I/O error"                         },
		{kIOReturnCannotLock, "cannot acquire lock"               },
		{kIOReturnNotOpen, "device is not open"                },
		{kIOReturnNotReadable, "device is not readable"            },
		{kIOReturnNotWritable, "device is not writeable"           },
		{kIOReturnNotAligned, "alignment error"                   },
		{kIOReturnBadMedia, "media error"                       },
		{kIOReturnStillOpen, "device is still open"              },
		{kIOReturnRLDError, "rld failure"                       },
		{kIOReturnDMAError, "DMA failure"                       },
		{kIOReturnBusy, "device is busy"                    },
		{kIOReturnTimeout, "I/O timeout"                       },
		{kIOReturnOffline, "device is offline"                 },
		{kIOReturnNotReady, "device is not ready"               },
		{kIOReturnNotAttached, "device/channel is not attached"    },
		{kIOReturnNoChannels, "no DMA channels available"         },
		{kIOReturnNoSpace, "no space for data"                 },
		{kIOReturnPortExists, "device port already exists"        },
		{kIOReturnCannotWire, "cannot wire physical memory"       },
		{kIOReturnNoInterrupt, "no interrupt attached"             },
		{kIOReturnNoFrames, "no DMA frames enqueued"            },
		{kIOReturnMessageTooLarge, "message is too large"              },
		{kIOReturnNotPermitted, "operation is not permitted"        },
		{kIOReturnNoPower, "device is without power"           },
		{kIOReturnNoMedia, "media is not present"              },
		{kIOReturnUnformattedMedia, "media is not formatted"            },
		{kIOReturnUnsupportedMode, "unsupported mode"                  },
		{kIOReturnUnderrun, "data underrun"                     },
		{kIOReturnOverrun, "data overrun"                      },
		{kIOReturnDeviceError, "device error"                      },
		{kIOReturnNoCompletion, "no completion routine"             },
		{kIOReturnAborted, "operation was aborted"             },
		{kIOReturnNoBandwidth, "bus bandwidth would be exceeded"   },
		{kIOReturnNotResponding, "device is not responding"          },
		{kIOReturnInvalid, "unanticipated driver error"        },
		{0, NULL                                }
	};

	return IOFindNameForValue(rtn, IOReturn_values);
}

/*
 * Convert an IOReturn to an errno.
 */
int
IOService::errnoFromReturn( IOReturn rtn )
{
	if (unix_err(err_get_code(rtn)) == rtn) {
		return err_get_code(rtn);
	}

	switch (rtn) {
	// (obvious match)
	case kIOReturnSuccess:
		return 0;
	case kIOReturnNoMemory:
		return ENOMEM;
	case kIOReturnNoDevice:
		return ENXIO;
	case kIOReturnVMError:
		return EFAULT;
	case kIOReturnNotPermitted:
		return EPERM;
	case kIOReturnNotPrivileged:
		return EACCES;
	case kIOReturnIOError:
		return EIO;
	case kIOReturnNotWritable:
		return EROFS;
	case kIOReturnBadArgument:
		return EINVAL;
	case kIOReturnUnsupported:
		return ENOTSUP;
	case kIOReturnBusy:
		return EBUSY;
	case kIOReturnNoPower:
		return EPWROFF;
	case kIOReturnDeviceError:
		return EDEVERR;
	case kIOReturnTimeout:
		return ETIMEDOUT;
	case kIOReturnMessageTooLarge:
		return EMSGSIZE;
	case kIOReturnNoSpace:
		return ENOSPC;
	case kIOReturnCannotLock:
		return ENOLCK;

	// (best match)
	case kIOReturnBadMessageID:
	case kIOReturnNoCompletion:
	case kIOReturnNotAligned:
		return EINVAL;
	case kIOReturnNotReady:
		return EBUSY;
	case kIOReturnRLDError:
		return EBADMACHO;
	case kIOReturnPortExists:
	case kIOReturnStillOpen:
		return EEXIST;
	case kIOReturnExclusiveAccess:
	case kIOReturnLockedRead:
	case kIOReturnLockedWrite:
	case kIOReturnNotOpen:
	case kIOReturnNotReadable:
		return EACCES;
	case kIOReturnCannotWire:
	case kIOReturnNoResources:
		return ENOMEM;
	case kIOReturnAborted:
	case kIOReturnOffline:
	case kIOReturnNotResponding:
		return EBUSY;
	case kIOReturnBadMedia:
	case kIOReturnNoMedia:
	case kIOReturnNotAttached:
	case kIOReturnUnformattedMedia:
		return ENXIO; // (media error)
	case kIOReturnDMAError:
	case kIOReturnOverrun:
	case kIOReturnUnderrun:
		return EIO; // (transfer error)
	case kIOReturnNoBandwidth:
	case kIOReturnNoChannels:
	case kIOReturnNoFrames:
	case kIOReturnNoInterrupt:
		return EIO; // (hardware error)
	case kIOReturnError:
	case kIOReturnInternalError:
	case kIOReturnInvalid:
		return EIO; // (generic error)
	case kIOReturnIPCError:
		return EIO; // (ipc error)
	default:
		return EIO; // (all other errors)
	}
}

IOReturn
IOService::message( UInt32 type, IOService * provider,
    void * argument )
{
	/*
	 * Generic entry point for calls from the provider.  A return value of
	 * kIOReturnSuccess indicates that the message was received, and where
	 * applicable, that it was successful.
	 */

	return kIOReturnUnsupported;
}

/*
 * Device memory
 */

IOItemCount
IOService::getDeviceMemoryCount( void )
{
	OSArray *           array;
	IOItemCount         count;

	array = OSDynamicCast( OSArray, getProperty( gIODeviceMemoryKey));
	if (array) {
		count = array->getCount();
	} else {
		count = 0;
	}

	return count;
}

IODeviceMemory *
IOService::getDeviceMemoryWithIndex( unsigned int index )
{
	OSArray *           array;
	IODeviceMemory *    range;

	array = OSDynamicCast( OSArray, getProperty( gIODeviceMemoryKey));
	if (array) {
		range = (IODeviceMemory *) array->getObject( index );
	} else {
		range = NULL;
	}

	return range;
}

IOMemoryMap *
IOService::mapDeviceMemoryWithIndex( unsigned int index,
    IOOptionBits options )
{
	IODeviceMemory *    range;
	IOMemoryMap *       map;

	range = getDeviceMemoryWithIndex( index );
	if (range) {
		map = range->map( options );
	} else {
		map = NULL;
	}

	return map;
}

OSArray *
IOService::getDeviceMemory( void )
{
	return OSDynamicCast( OSArray, getProperty( gIODeviceMemoryKey));
}


void
IOService::setDeviceMemory( OSArray * array )
{
	setProperty( gIODeviceMemoryKey, array);
}

/*
 * For machines where the transfers on an I/O bus can stall because
 * the CPU is in an idle mode, These APIs allow a driver to specify
 * the maximum bus stall that they can handle.  0 indicates no limit.
 */
void
IOService::
setCPUSnoopDelay(UInt32 __unused ns)
{
#if defined(__i386__) || defined(__x86_64__)
	ml_set_maxsnoop(ns);
#endif /* defined(__i386__) || defined(__x86_64__) */
}

UInt32
IOService::
getCPUSnoopDelay()
{
#if defined(__i386__) || defined(__x86_64__)
	return ml_get_maxsnoop();
#else
	return 0;
#endif /* defined(__i386__) || defined(__x86_64__) */
}

#if defined(__i386__) || defined(__x86_64__)
static void
requireMaxCpuDelay(IOService * service, UInt32 ns, UInt32 delayType)
{
	static const UInt kNoReplace = -1U; // Must be an illegal index
	UInt replace = kNoReplace;
	bool setCpuDelay = false;

	IORecursiveLockLock(sCpuDelayLock);

	UInt count = sCpuDelayData->getLength() / sizeof(CpuDelayEntry);
	CpuDelayEntry *entries = (CpuDelayEntry *) sCpuDelayData->getBytesNoCopy();
	IOService * holder = NULL;

	if (ns) {
		const CpuDelayEntry ne = {service, ns, delayType};
		holder = service;
		// Set maximum delay.
		for (UInt i = 0; i < count; i++) {
			IOService *thisService = entries[i].fService;
			bool sameType = (delayType == entries[i].fDelayType);
			if ((service == thisService) && sameType) {
				replace = i;
			} else if (!thisService) {
				if (kNoReplace == replace) {
					replace = i;
				}
			} else if (sameType) {
				const UInt32 thisMax = entries[i].fMaxDelay;
				if (thisMax < ns) {
					ns = thisMax;
					holder = thisService;
				}
			}
		}

		setCpuDelay = true;
		if (kNoReplace == replace) {
			sCpuDelayData->appendBytes(&ne, sizeof(ne));
		} else {
			entries[replace] = ne;
		}
	} else {
		ns = -1U; // Set to max unsigned, i.e. no restriction

		for (UInt i = 0; i < count; i++) {
			// Clear a maximum delay.
			IOService *thisService = entries[i].fService;
			if (thisService && (delayType == entries[i].fDelayType)) {
				UInt32 thisMax = entries[i].fMaxDelay;
				if (service == thisService) {
					replace = i;
				} else if (thisMax < ns) {
					ns = thisMax;
					holder = thisService;
				}
			}
		}

		// Check if entry found
		if (kNoReplace != replace) {
			entries[replace].fService = NULL; // Null the entry
			setCpuDelay = true;
		}
	}

	if (setCpuDelay) {
		if (holder && debug_boot_arg) {
			strlcpy(sCPULatencyHolderName[delayType], holder->getName(), sizeof(sCPULatencyHolderName[delayType]));
		}

		// Must be safe to call from locked context
		if (delayType == kCpuDelayBusStall) {
			ml_set_maxbusdelay(ns);
		} else if (delayType == kCpuDelayInterrupt) {
			ml_set_maxintdelay(ns);
		}
		sCPULatencyHolder[delayType]->setValue(holder ? holder->getRegistryEntryID() : 0);
		sCPULatencySet[delayType]->setValue(ns);

		OSArray * handlers = sCpuLatencyHandlers[delayType];
		IOService * target;
		if (handlers) {
			for (unsigned int idx = 0;
			    (target = (IOService *) handlers->getObject(idx));
			    idx++) {
				target->callPlatformFunction(sCPULatencyFunctionName[delayType], false,
				    (void *) (uintptr_t) ns, holder,
				    NULL, NULL);
			}
		}
	}

	IORecursiveLockUnlock(sCpuDelayLock);
}

static IOReturn
setLatencyHandler(UInt32 delayType, IOService * target, bool enable)
{
	IOReturn result = kIOReturnNotFound;
	OSArray * array;
	unsigned int idx;

	IORecursiveLockLock(sCpuDelayLock);

	do{
		if (enable && !sCpuLatencyHandlers[delayType]) {
			sCpuLatencyHandlers[delayType] = OSArray::withCapacity(4);
		}
		array = sCpuLatencyHandlers[delayType];
		if (!array) {
			break;
		}
		idx = array->getNextIndexOfObject(target, 0);
		if (!enable) {
			if (-1U != idx) {
				array->removeObject(idx);
				result = kIOReturnSuccess;
			}
		} else {
			if (-1U != idx) {
				result = kIOReturnExclusiveAccess;
				break;
			}
			array->setObject(target);

			UInt count = sCpuDelayData->getLength() / sizeof(CpuDelayEntry);
			CpuDelayEntry *entries = (CpuDelayEntry *) sCpuDelayData->getBytesNoCopy();
			UInt32 ns = -1U; // Set to max unsigned, i.e. no restriction
			IOService * holder = NULL;

			for (UInt i = 0; i < count; i++) {
				if (entries[i].fService
				    && (delayType == entries[i].fDelayType)
				    && (entries[i].fMaxDelay < ns)) {
					ns = entries[i].fMaxDelay;
					holder = entries[i].fService;
				}
			}
			target->callPlatformFunction(sCPULatencyFunctionName[delayType], false,
			    (void *) (uintptr_t) ns, holder,
			    NULL, NULL);
			result = kIOReturnSuccess;
		}
	}while (false);

	IORecursiveLockUnlock(sCpuDelayLock);

	return result;
}

#endif /* defined(__i386__) || defined(__x86_64__) */

void
IOService::
requireMaxBusStall(UInt32 __unused ns)
{
#if defined(__i386__) || defined(__x86_64__)
	requireMaxCpuDelay(this, ns, kCpuDelayBusStall);
#endif
}

void
IOService::
requireMaxInterruptDelay(uint32_t __unused ns)
{
#if defined(__i386__) || defined(__x86_64__)
	requireMaxCpuDelay(this, ns, kCpuDelayInterrupt);
#endif
}

/*
 * Device interrupts
 */

IOReturn
IOService::resolveInterrupt(IOService *nub, int source)
{
	IOInterruptController *interruptController;
	OSArray               *array;
	OSData                *data;
	OSSymbol              *interruptControllerName;
	long                  numSources;
	IOInterruptSource     *interruptSources;

	// Get the parents list from the nub.
	array = OSDynamicCast(OSArray, nub->getProperty(gIOInterruptControllersKey));
	if (array == NULL) {
		return kIOReturnNoResources;
	}

	// Allocate space for the IOInterruptSources if needed... then return early.
	if (nub->_interruptSources == NULL) {
		numSources = array->getCount();
		interruptSources = (IOInterruptSource *)IOMalloc(
			numSources * sizeofAllIOInterruptSource);
		if (interruptSources == NULL) {
			return kIOReturnNoMemory;
		}

		bzero(interruptSources, numSources * sizeofAllIOInterruptSource);

		nub->_numInterruptSources = numSources;
		nub->_interruptSources = interruptSources;
		return kIOReturnSuccess;
	}

	interruptControllerName = OSDynamicCast(OSSymbol, array->getObject(source));
	if (interruptControllerName == NULL) {
		return kIOReturnNoResources;
	}

	interruptController = getPlatform()->lookUpInterruptController(interruptControllerName);
	if (interruptController == NULL) {
		return kIOReturnNoResources;
	}

	// Get the interrupt numbers from the nub.
	array = OSDynamicCast(OSArray, nub->getProperty(gIOInterruptSpecifiersKey));
	if (array == NULL) {
		return kIOReturnNoResources;
	}
	data = OSDynamicCast(OSData, array->getObject(source));
	if (data == NULL) {
		return kIOReturnNoResources;
	}

	// Set the interruptController and interruptSource in the nub's table.
	interruptSources = nub->_interruptSources;
	interruptSources[source].interruptController = interruptController;
	interruptSources[source].vectorData = data;

	return kIOReturnSuccess;
}

IOReturn
IOService::lookupInterrupt(int source, bool resolve, IOInterruptController **interruptController)
{
	IOReturn ret;

	/* Make sure the _interruptSources are set */
	if (_interruptSources == NULL) {
		ret = resolveInterrupt(this, source);
		if (ret != kIOReturnSuccess) {
			return ret;
		}
	}

	/* Make sure the local source number is valid */
	if ((source < 0) || (source >= _numInterruptSources)) {
		return kIOReturnNoInterrupt;
	}

	/* Look up the contoller for the local source */
	*interruptController = _interruptSources[source].interruptController;

	if (*interruptController == NULL) {
		if (!resolve) {
			return kIOReturnNoInterrupt;
		}

		/* Try to resolve the interrupt */
		ret = resolveInterrupt(this, source);
		if (ret != kIOReturnSuccess) {
			return ret;
		}

		*interruptController = _interruptSources[source].interruptController;
	}

	return kIOReturnSuccess;
}

IOReturn
IOService::registerInterrupt(int source, OSObject *target,
    IOInterruptAction handler,
    void *refCon)
{
	IOInterruptController *interruptController;
	IOReturn              ret;

	ret = lookupInterrupt(source, true, &interruptController);
	if (ret != kIOReturnSuccess) {
		return ret;
	}

	/* Register the source */
	return interruptController->registerInterrupt(this, source, target,
	           (IOInterruptHandler)handler,
	           refCon);
}

static void
IOServiceInterruptActionToBlock( OSObject * target, void * refCon,
    IOService * nub, int source )
{
	((IOInterruptActionBlock)(refCon))(nub, source);
}

IOReturn
IOService::registerInterruptBlock(int source, OSObject *target,
    IOInterruptActionBlock handler)
{
	IOReturn ret;
	void   * block;

	block = Block_copy(handler);
	if (!block) {
		return kIOReturnNoMemory;
	}

	ret = registerInterrupt(source, target, &IOServiceInterruptActionToBlock, block);
	if (kIOReturnSuccess != ret) {
		Block_release(block);
		return ret;
	}
	_interruptSourcesPrivate(this)[source].vectorBlock = block;

	return ret;
}

IOReturn
IOService::unregisterInterrupt(int source)
{
	IOReturn              ret;
	IOInterruptController *interruptController;
	void                  *block;

	ret = lookupInterrupt(source, false, &interruptController);
	if (ret != kIOReturnSuccess) {
		return ret;
	}

	/* Unregister the source */
	block = _interruptSourcesPrivate(this)[source].vectorBlock;
	ret = interruptController->unregisterInterrupt(this, source);
	if ((kIOReturnSuccess == ret) && (block = _interruptSourcesPrivate(this)[source].vectorBlock)) {
		_interruptSourcesPrivate(this)[source].vectorBlock = NULL;
		Block_release(block);
	}

	return ret;
}

IOReturn
IOService::addInterruptStatistics(IOInterruptAccountingData * statistics, int source)
{
	IOReportLegend * legend = NULL;
	IOInterruptAccountingData * oldValue = NULL;
	IOInterruptAccountingReporter * newArray = NULL;
	char subgroupName[64];
	int newArraySize = 0;
	int i = 0;

	if (source < 0) {
		return kIOReturnBadArgument;
	}

	/*
	 * We support statistics on a maximum of 256 interrupts per nub; if a nub
	 * has more than 256 interrupt specifiers associated with it, and tries
	 * to register a high interrupt index with interrupt accounting, panic.
	 * Having more than 256 interrupts associated with a single nub is
	 * probably a sign that something fishy is going on.
	 */
	if (source > IA_INDEX_MAX) {
		panic("addInterruptStatistics called for an excessively large index (%d)", source);
	}

	/*
	 * TODO: This is ugly (wrapping a lock around an allocation).  I'm only
	 * leaving it as is because the likelihood of contention where we are
	 * actually growing the array is minimal (we would realistically need
	 * to be starting a driver for the first time, with an IOReporting
	 * client already in place).  Nonetheless, cleanup that can be done
	 * to adhere to best practices; it'll make the code more complicated,
	 * unfortunately.
	 */
	IOLockLock(reserved->interruptStatisticsLock);

	/*
	 * Lazily allocate the statistics array.
	 */
	if (!reserved->interruptStatisticsArray) {
		reserved->interruptStatisticsArray = IONew(IOInterruptAccountingReporter, 1);
		assert(reserved->interruptStatisticsArray);
		reserved->interruptStatisticsArrayCount = 1;
		bzero(reserved->interruptStatisticsArray, sizeof(*reserved->interruptStatisticsArray));
	}

	if (source >= reserved->interruptStatisticsArrayCount) {
		/*
		 * We're still within the range of supported indices, but we are out
		 * of space in the current array.  Do a nasty realloc (because
		 * IORealloc isn't a thing) here.  We'll double the size with each
		 * reallocation.
		 *
		 * Yes, the "next power of 2" could be more efficient; but this will
		 * be invoked incredibly rarely.  Who cares.
		 */
		newArraySize = (reserved->interruptStatisticsArrayCount << 1);

		while (newArraySize <= source) {
			newArraySize = (newArraySize << 1);
		}
		newArray = IONew(IOInterruptAccountingReporter, newArraySize);

		assert(newArray);

		/*
		 * TODO: This even zeroes the memory it is about to overwrite.
		 * Shameful; fix it.  Not particularly high impact, however.
		 */
		bzero(newArray, newArraySize * sizeof(*newArray));
		memcpy(newArray, reserved->interruptStatisticsArray, reserved->interruptStatisticsArrayCount * sizeof(*newArray));
		IODelete(reserved->interruptStatisticsArray, IOInterruptAccountingReporter, reserved->interruptStatisticsArrayCount);
		reserved->interruptStatisticsArray = newArray;
		reserved->interruptStatisticsArrayCount = newArraySize;
	}

	if (!reserved->interruptStatisticsArray[source].reporter) {
		/*
		 * We don't have a reporter associated with this index yet, so we
		 * need to create one.
		 */
		/*
		 * TODO: Some statistics do in fact have common units (time); should this be
		 * split into separate reporters to communicate this?
		 */
		reserved->interruptStatisticsArray[source].reporter = IOSimpleReporter::with(this, kIOReportCategoryPower, kIOReportUnitNone);

		/*
		 * Each statistic is given an identifier based on the interrupt index (which
		 * should be unique relative to any single nub) and the statistic involved.
		 * We should now have a sane (small and positive) index, so start
		 * constructing the channels for statistics.
		 */
		for (i = 0; i < IA_NUM_INTERRUPT_ACCOUNTING_STATISTICS; i++) {
			/*
			 * TODO: Currently, this does not add channels for disabled statistics.
			 * Will this be confusing for clients?  If so, we should just add the
			 * channels; we can avoid updating the channels even if they exist.
			 */
			if (IA_GET_STATISTIC_ENABLED(i)) {
				reserved->interruptStatisticsArray[source].reporter->addChannel(IA_GET_CHANNEL_ID(source, i), kInterruptAccountingStatisticNameArray[i]);
			}
		}

		/*
		 * We now need to add the legend for this reporter to the registry.
		 */
		OSObject * prop = copyProperty(kIOReportLegendKey);
		legend = IOReportLegend::with(OSDynamicCast(OSArray, prop));
		OSSafeReleaseNULL(prop);

		/*
		 * Note that while we compose the subgroup name, we do not need to
		 * manage its lifecycle (the reporter will handle this).
		 */
		snprintf(subgroupName, sizeof(subgroupName), "%s %d", getName(), source);
		subgroupName[sizeof(subgroupName) - 1] = 0;
		legend->addReporterLegend(reserved->interruptStatisticsArray[source].reporter, kInterruptAccountingGroupName, subgroupName);
		setProperty(kIOReportLegendKey, legend->getLegend());
		legend->release();

		/*
		 * TODO: Is this a good idea?  Probably not; my assumption is it opts
		 * all entities who register interrupts into public disclosure of all
		 * IOReporting channels.  Unfortunately, this appears to be as fine
		 * grain as it gets.
		 */
		setProperty(kIOReportLegendPublicKey, true);
	}

	/*
	 * Don't stomp existing entries.  If we are about to, panic; this
	 * probably means we failed to tear down our old interrupt source
	 * correctly.
	 */
	oldValue = reserved->interruptStatisticsArray[source].statistics;

	if (oldValue) {
		panic("addInterruptStatistics call for index %d would have clobbered existing statistics", source);
	}

	reserved->interruptStatisticsArray[source].statistics = statistics;

	/*
	 * Inherit the reporter values for each statistic.  The target may
	 * be torn down as part of the runtime of the service (especially
	 * for sleep/wake), so we inherit in order to avoid having values
	 * reset for no apparent reason.  Our statistics are ultimately
	 * tied to the index and the sevice, not to an individual target,
	 * so we should maintain them accordingly.
	 */
	interruptAccountingDataInheritChannels(reserved->interruptStatisticsArray[source].statistics, reserved->interruptStatisticsArray[source].reporter);

	IOLockUnlock(reserved->interruptStatisticsLock);

	return kIOReturnSuccess;
}

IOReturn
IOService::removeInterruptStatistics(int source)
{
	IOInterruptAccountingData * value = NULL;

	if (source < 0) {
		return kIOReturnBadArgument;
	}

	IOLockLock(reserved->interruptStatisticsLock);

	/*
	 * We dynamically grow the statistics array, so an excessively
	 * large index value has NEVER been registered.  This either
	 * means our cap on the array size is too small (unlikely), or
	 * that we have been passed a corrupt index (this must be passed
	 * the plain index into the interrupt specifier list).
	 */
	if (source >= reserved->interruptStatisticsArrayCount) {
		panic("removeInterruptStatistics called for index %d, which was never registered", source);
	}

	assert(reserved->interruptStatisticsArray);

	/*
	 * If there is no existing entry, we are most likely trying to
	 * free an interrupt owner twice, or we have corrupted the
	 * index value.
	 */
	value = reserved->interruptStatisticsArray[source].statistics;

	if (!value) {
		panic("removeInterruptStatistics called for empty index %d", source);
	}

	/*
	 * We update the statistics, so that any delta with the reporter
	 * state is not lost.
	 */
	interruptAccountingDataUpdateChannels(reserved->interruptStatisticsArray[source].statistics, reserved->interruptStatisticsArray[source].reporter);
	reserved->interruptStatisticsArray[source].statistics = NULL;
	IOLockUnlock(reserved->interruptStatisticsLock);

	return kIOReturnSuccess;
}

IOReturn
IOService::getInterruptType(int source, int *interruptType)
{
	IOInterruptController *interruptController;
	IOReturn              ret;

	ret = lookupInterrupt(source, true, &interruptController);
	if (ret != kIOReturnSuccess) {
		return ret;
	}

	/* Return the type */
	return interruptController->getInterruptType(this, source, interruptType);
}

IOReturn
IOService::enableInterrupt(int source)
{
	IOInterruptController *interruptController;
	IOReturn              ret;

	ret = lookupInterrupt(source, false, &interruptController);
	if (ret != kIOReturnSuccess) {
		return ret;
	}

	/* Enable the source */
	return interruptController->enableInterrupt(this, source);
}

IOReturn
IOService::disableInterrupt(int source)
{
	IOInterruptController *interruptController;
	IOReturn              ret;

	ret = lookupInterrupt(source, false, &interruptController);
	if (ret != kIOReturnSuccess) {
		return ret;
	}

	/* Disable the source */
	return interruptController->disableInterrupt(this, source);
}

IOReturn
IOService::causeInterrupt(int source)
{
	IOInterruptController *interruptController;
	IOReturn              ret;

	ret = lookupInterrupt(source, false, &interruptController);
	if (ret != kIOReturnSuccess) {
		return ret;
	}

	/* Cause an interrupt for the source */
	return interruptController->causeInterrupt(this, source);
}

IOReturn
IOService::configureReport(IOReportChannelList    *channelList,
    IOReportConfigureAction action,
    void                   *result,
    void                   *destination)
{
	unsigned cnt;

	for (cnt = 0; cnt < channelList->nchannels; cnt++) {
		if (channelList->channels[cnt].channel_id == kPMPowerStatesChID) {
			if (pwrMgt) {
				configurePowerStatesReport(action, result);
			} else {
				return kIOReturnUnsupported;
			}
		} else if (channelList->channels[cnt].channel_id == kPMCurrStateChID) {
			if (pwrMgt) {
				configureSimplePowerReport(action, result);
			} else {
				return kIOReturnUnsupported;
			}
		}
	}

	IOLockLock(reserved->interruptStatisticsLock);

	/* The array count is signed (because the interrupt indices are signed), hence the cast */
	for (cnt = 0; cnt < (unsigned) reserved->interruptStatisticsArrayCount; cnt++) {
		if (reserved->interruptStatisticsArray[cnt].reporter) {
			/*
			 * If the reporter is currently associated with the statistics
			 * for an event source, we may need to update the reporter.
			 */
			if (reserved->interruptStatisticsArray[cnt].statistics) {
				interruptAccountingDataUpdateChannels(reserved->interruptStatisticsArray[cnt].statistics, reserved->interruptStatisticsArray[cnt].reporter);
			}

			reserved->interruptStatisticsArray[cnt].reporter->configureReport(channelList, action, result, destination);
		}
	}

	IOLockUnlock(reserved->interruptStatisticsLock);

	return kIOReturnSuccess;
}

IOReturn
IOService::updateReport(IOReportChannelList      *channelList,
    IOReportUpdateAction      action,
    void                     *result,
    void                     *destination)
{
	unsigned cnt;

	for (cnt = 0; cnt < channelList->nchannels; cnt++) {
		if (channelList->channels[cnt].channel_id == kPMPowerStatesChID) {
			if (pwrMgt) {
				updatePowerStatesReport(action, result, destination);
			} else {
				return kIOReturnUnsupported;
			}
		} else if (channelList->channels[cnt].channel_id == kPMCurrStateChID) {
			if (pwrMgt) {
				updateSimplePowerReport(action, result, destination);
			} else {
				return kIOReturnUnsupported;
			}
		}
	}

	IOLockLock(reserved->interruptStatisticsLock);

	/* The array count is signed (because the interrupt indices are signed), hence the cast */
	for (cnt = 0; cnt < (unsigned) reserved->interruptStatisticsArrayCount; cnt++) {
		if (reserved->interruptStatisticsArray[cnt].reporter) {
			/*
			 * If the reporter is currently associated with the statistics
			 * for an event source, we need to update the reporter.
			 */
			if (reserved->interruptStatisticsArray[cnt].statistics) {
				interruptAccountingDataUpdateChannels(reserved->interruptStatisticsArray[cnt].statistics, reserved->interruptStatisticsArray[cnt].reporter);
			}

			reserved->interruptStatisticsArray[cnt].reporter->updateReport(channelList, action, result, destination);
		}
	}

	IOLockUnlock(reserved->interruptStatisticsLock);

	return kIOReturnSuccess;
}

uint64_t
IOService::getAuthorizationID( void )
{
	return reserved->authorizationID;
}

IOReturn
IOService::setAuthorizationID( uint64_t authorizationID )
{
	OSObject * entitlement;
	IOReturn status;

	entitlement = IOUserClient::copyClientEntitlement( current_task(), "com.apple.private.iokit.IOServiceSetAuthorizationID" );

	if (entitlement) {
		if (entitlement == kOSBooleanTrue) {
			reserved->authorizationID = authorizationID;

			status = kIOReturnSuccess;
		} else {
			status = kIOReturnNotPrivileged;
		}

		entitlement->release();
	} else {
		status = kIOReturnNotPrivileged;
	}

	return status;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#if __LP64__
OSMetaClassDefineReservedUsed(IOService, 0);
OSMetaClassDefineReservedUsed(IOService, 1);
OSMetaClassDefineReservedUnused(IOService, 2);
OSMetaClassDefineReservedUnused(IOService, 3);
OSMetaClassDefineReservedUnused(IOService, 4);
OSMetaClassDefineReservedUnused(IOService, 5);
OSMetaClassDefineReservedUnused(IOService, 6);
OSMetaClassDefineReservedUnused(IOService, 7);
#else
OSMetaClassDefineReservedUsed(IOService, 0);
OSMetaClassDefineReservedUsed(IOService, 1);
OSMetaClassDefineReservedUsed(IOService, 2);
OSMetaClassDefineReservedUsed(IOService, 3);
OSMetaClassDefineReservedUsed(IOService, 4);
OSMetaClassDefineReservedUsed(IOService, 5);
OSMetaClassDefineReservedUsed(IOService, 6);
OSMetaClassDefineReservedUsed(IOService, 7);
#endif
OSMetaClassDefineReservedUnused(IOService, 8);
OSMetaClassDefineReservedUnused(IOService, 9);
OSMetaClassDefineReservedUnused(IOService, 10);
OSMetaClassDefineReservedUnused(IOService, 11);
OSMetaClassDefineReservedUnused(IOService, 12);
OSMetaClassDefineReservedUnused(IOService, 13);
OSMetaClassDefineReservedUnused(IOService, 14);
OSMetaClassDefineReservedUnused(IOService, 15);
OSMetaClassDefineReservedUnused(IOService, 16);
OSMetaClassDefineReservedUnused(IOService, 17);
OSMetaClassDefineReservedUnused(IOService, 18);
OSMetaClassDefineReservedUnused(IOService, 19);
OSMetaClassDefineReservedUnused(IOService, 20);
OSMetaClassDefineReservedUnused(IOService, 21);
OSMetaClassDefineReservedUnused(IOService, 22);
OSMetaClassDefineReservedUnused(IOService, 23);
OSMetaClassDefineReservedUnused(IOService, 24);
OSMetaClassDefineReservedUnused(IOService, 25);
OSMetaClassDefineReservedUnused(IOService, 26);
OSMetaClassDefineReservedUnused(IOService, 27);
OSMetaClassDefineReservedUnused(IOService, 28);
OSMetaClassDefineReservedUnused(IOService, 29);
OSMetaClassDefineReservedUnused(IOService, 30);
OSMetaClassDefineReservedUnused(IOService, 31);
OSMetaClassDefineReservedUnused(IOService, 32);
OSMetaClassDefineReservedUnused(IOService, 33);
OSMetaClassDefineReservedUnused(IOService, 34);
OSMetaClassDefineReservedUnused(IOService, 35);
OSMetaClassDefineReservedUnused(IOService, 36);
OSMetaClassDefineReservedUnused(IOService, 37);
OSMetaClassDefineReservedUnused(IOService, 38);
OSMetaClassDefineReservedUnused(IOService, 39);
OSMetaClassDefineReservedUnused(IOService, 40);
OSMetaClassDefineReservedUnused(IOService, 41);
OSMetaClassDefineReservedUnused(IOService, 42);
OSMetaClassDefineReservedUnused(IOService, 43);
OSMetaClassDefineReservedUnused(IOService, 44);
OSMetaClassDefineReservedUnused(IOService, 45);
OSMetaClassDefineReservedUnused(IOService, 46);
OSMetaClassDefineReservedUnused(IOService, 47);
