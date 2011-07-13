/*
 * Copyright (c) 1998-2009 Apple Inc. All rights reserved.
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
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOCommand.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterrupts.h>
#include <IOKit/IOInterruptController.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimeStamp.h>
#include <mach/sync_policy.h>
#include <IOKit/assert.h>
#include <sys/errno.h>

#include <machine/pal_routines.h>

#define LOG kprintf
//#define LOG IOLog

#include "IOServicePrivate.h"
#include "IOKitKernelInternal.h"

// take lockForArbitration before LOCKNOTIFY

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IORegistryEntry

OSDefineMetaClassAndStructors(IOService, IORegistryEntry)

OSDefineMetaClassAndStructors(_IOServiceNotifier, IONotifier)

OSDefineMetaClassAndStructors(_IOServiceInterestNotifier, IONotifier)

OSDefineMetaClassAndStructors(_IOConfigThread, OSObject)

OSDefineMetaClassAndStructors(_IOServiceJob, OSObject)

OSDefineMetaClassAndStructors(IOResources, IOService)

OSDefineMetaClassAndStructors(_IOOpenServiceIterator, OSIterator)

OSDefineMetaClassAndAbstractStructors(IONotifier, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOPlatformExpert *	gIOPlatform;
static class IOPMrootDomain *	gIOPMRootDomain;
const IORegistryPlane *		gIOServicePlane;
const IORegistryPlane *		gIOPowerPlane;
const OSSymbol *		gIODeviceMemoryKey;
const OSSymbol *		gIOInterruptControllersKey;
const OSSymbol *		gIOInterruptSpecifiersKey;

const OSSymbol *		gIOResourcesKey;
const OSSymbol *		gIOResourceMatchKey;
const OSSymbol *		gIOProviderClassKey;
const OSSymbol * 		gIONameMatchKey;
const OSSymbol *		gIONameMatchedKey;
const OSSymbol *		gIOPropertyMatchKey;
const OSSymbol *		gIOLocationMatchKey;
const OSSymbol *		gIOParentMatchKey;
const OSSymbol *		gIOPathMatchKey;
const OSSymbol *		gIOMatchCategoryKey;
const OSSymbol *		gIODefaultMatchCategoryKey;
const OSSymbol *		gIOMatchedServiceCountKey;

const OSSymbol *		gIOMapperIDKey;
const OSSymbol *		gIOUserClientClassKey;
const OSSymbol *		gIOKitDebugKey;

const OSSymbol *		gIOCommandPoolSizeKey;

const OSSymbol *		gIOConsoleLockedKey;
const OSSymbol *		gIOConsoleUsersKey;
const OSSymbol *		gIOConsoleSessionUIDKey;
const OSSymbol *		gIOConsoleSessionAuditIDKey;
const OSSymbol *		gIOConsoleUsersSeedKey;
const OSSymbol *		gIOConsoleSessionOnConsoleKey;
const OSSymbol *		gIOConsoleSessionSecureInputPIDKey;
const OSSymbol *		gIOConsoleSessionScreenLockedTimeKey;

static clock_sec_t		gIOConsoleLockTime;

static int			gIOResourceGenerationCount;

const OSSymbol *		gIOServiceKey;
const OSSymbol *		gIOPublishNotification;
const OSSymbol *		gIOFirstPublishNotification;
const OSSymbol *		gIOMatchedNotification;
const OSSymbol *		gIOFirstMatchNotification;
const OSSymbol *		gIOTerminatedNotification;

const OSSymbol *		gIOGeneralInterest;
const OSSymbol *		gIOBusyInterest;
const OSSymbol *		gIOAppPowerStateInterest;
const OSSymbol *		gIOPriorityPowerStateInterest;
const OSSymbol *		gIOConsoleSecurityInterest;

static OSDictionary * 		gNotifications;
static IORecursiveLock *	gNotificationLock;

static IOService *		gIOResources;
static IOService * 		gIOServiceRoot;

static OSOrderedSet *		gJobs;
static semaphore_port_t		gJobsSemaphore;
static IOLock *			gJobsLock;
static int			gOutstandingJobs;
static int			gNumConfigThreads;
static int			gNumWaitingThreads;
static IOLock *			gIOServiceBusyLock;

static thread_t			gIOTerminateThread;
static UInt32			gIOTerminateWork;
static OSArray *		gIOTerminatePhase2List;
static OSArray *		gIOStopList;
static OSArray *		gIOStopProviderList;
static OSArray *		gIOFinalizeList;

static SInt32			gIOConsoleUsersSeed;
static OSData *			gIOConsoleUsersSeedValue;

extern const OSSymbol *		gIODTPHandleKey;

const OSSymbol *		gIOPlatformSleepActionKey;
const OSSymbol *		gIOPlatformWakeActionKey;
const OSSymbol *		gIOPlatformQuiesceActionKey;
const OSSymbol *		gIOPlatformActiveActionKey;

const OSSymbol *		gIOPlatformFunctionHandlerSet;

static IOLock *			gIOConsoleUsersLock;
static thread_call_t		gIOConsoleLockCallout;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define LOCKREADNOTIFY()	\
    IORecursiveLockLock( gNotificationLock )
#define LOCKWRITENOTIFY()	\
    IORecursiveLockLock( gNotificationLock )
#define LOCKWRITE2READNOTIFY()
#define UNLOCKNOTIFY()		\
    IORecursiveLockUnlock( gNotificationLock )
#define SLEEPNOTIFY(event) \
    IORecursiveLockSleep( gNotificationLock, (void *)(event), THREAD_UNINT )
#define SLEEPNOTIFYTO(event, deadline) \
    IORecursiveLockSleepDeadline( gNotificationLock, (void *)(event), deadline, THREAD_UNINT )
#define WAKEUPNOTIFY(event) \
	IORecursiveLockWakeup( gNotificationLock, (void *)(event), /* wake one */ false )

#define randomDelay()	\
        int del = read_processor_clock();				\
        del = (((int)IOThreadSelf()) ^ del ^ (del >> 10)) & 0x3ff;	\
        IOSleep( del );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define queue_element(entry, element, type, field) do {	\
	vm_address_t __ele = (vm_address_t) (entry);	\
	__ele -= -4 + ((size_t)(&((type) 4)->field));	\
	(element) = (type) __ele;			\
    } while(0)

#define iterqueue(que, elt)				\
	for (queue_entry_t elt = queue_first(que);	\
	     !queue_end(que, elt);			\
	     elt = queue_next(elt))

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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

bool IOService::isInactive( void ) const
    { return( 0 != (kIOServiceInactiveState & getState())); }


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(__i386__) || defined(__x86_64__)

// Only used by the intel implementation of
//     IOService::requireMaxBusStall(UInt32 ns)
//     IOService::requireMaxInterruptDelay(uint32_t ns)
struct CpuDelayEntry
{
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

static void
requireMaxCpuDelay(IOService * service, UInt32 ns, UInt32 delayType);
static IOReturn
setLatencyHandler(UInt32 delayType, IOService * target, bool enable);

#endif /* defined(__i386__) || defined(__x86_64__) */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOService::initialize( void )
{
    kern_return_t	err;

    gIOServicePlane	= IORegistryEntry::makePlane( kIOServicePlane );
    gIOPowerPlane 	= IORegistryEntry::makePlane( kIOPowerPlane );

    gIOProviderClassKey = OSSymbol::withCStringNoCopy( kIOProviderClassKey );
    gIONameMatchKey	= OSSymbol::withCStringNoCopy( kIONameMatchKey );
    gIONameMatchedKey	= OSSymbol::withCStringNoCopy( kIONameMatchedKey );
    gIOPropertyMatchKey	= OSSymbol::withCStringNoCopy( kIOPropertyMatchKey );
    gIOPathMatchKey 	= OSSymbol::withCStringNoCopy( kIOPathMatchKey );
    gIOLocationMatchKey	= OSSymbol::withCStringNoCopy( kIOLocationMatchKey );
    gIOParentMatchKey	= OSSymbol::withCStringNoCopy( kIOParentMatchKey );

    gIOMatchCategoryKey	= OSSymbol::withCStringNoCopy( kIOMatchCategoryKey );
    gIODefaultMatchCategoryKey	= OSSymbol::withCStringNoCopy( 
					kIODefaultMatchCategoryKey );
    gIOMatchedServiceCountKey	= OSSymbol::withCStringNoCopy( 
					kIOMatchedServiceCountKey );

    gIOUserClientClassKey = OSSymbol::withCStringNoCopy( kIOUserClientClassKey );

    gIOResourcesKey	= OSSymbol::withCStringNoCopy( kIOResourcesClass );
    gIOResourceMatchKey	= OSSymbol::withCStringNoCopy( kIOResourceMatchKey );

    gIODeviceMemoryKey	= OSSymbol::withCStringNoCopy( "IODeviceMemory" );
    gIOInterruptControllersKey
	= OSSymbol::withCStringNoCopy("IOInterruptControllers");
    gIOInterruptSpecifiersKey
	= OSSymbol::withCStringNoCopy("IOInterruptSpecifiers");

    gIOMapperIDKey = OSSymbol::withCStringNoCopy(kIOMapperIDKey);

    gIOKitDebugKey	= OSSymbol::withCStringNoCopy( kIOKitDebugKey );

    gIOCommandPoolSizeKey	= OSSymbol::withCStringNoCopy( kIOCommandPoolSizeKey );

    gIOGeneralInterest 		= OSSymbol::withCStringNoCopy( kIOGeneralInterest );
    gIOBusyInterest   		= OSSymbol::withCStringNoCopy( kIOBusyInterest );
    gIOAppPowerStateInterest   	= OSSymbol::withCStringNoCopy( kIOAppPowerStateInterest );
    gIOPriorityPowerStateInterest   	= OSSymbol::withCStringNoCopy( kIOPriorityPowerStateInterest );
    gIOConsoleSecurityInterest 	= OSSymbol::withCStringNoCopy( kIOConsoleSecurityInterest );

    gNotifications		= OSDictionary::withCapacity( 1 );
    gIOPublishNotification	= OSSymbol::withCStringNoCopy(
						 kIOPublishNotification );
    gIOFirstPublishNotification	= OSSymbol::withCStringNoCopy(
                                                 kIOFirstPublishNotification );
    gIOMatchedNotification	= OSSymbol::withCStringNoCopy(
						 kIOMatchedNotification );
    gIOFirstMatchNotification	= OSSymbol::withCStringNoCopy(
						 kIOFirstMatchNotification );
    gIOTerminatedNotification	= OSSymbol::withCStringNoCopy(
						 kIOTerminatedNotification );
    gIOServiceKey		= OSSymbol::withCStringNoCopy( kIOServiceClass);

    gIOConsoleLockedKey		= OSSymbol::withCStringNoCopy( kIOConsoleLockedKey);
    gIOConsoleUsersKey		= OSSymbol::withCStringNoCopy( kIOConsoleUsersKey);
    gIOConsoleSessionUIDKey	= OSSymbol::withCStringNoCopy( kIOConsoleSessionUIDKey);
    gIOConsoleSessionAuditIDKey	= OSSymbol::withCStringNoCopy( kIOConsoleSessionAuditIDKey);

    gIOConsoleUsersSeedKey	         = OSSymbol::withCStringNoCopy(kIOConsoleUsersSeedKey);
    gIOConsoleSessionOnConsoleKey        = OSSymbol::withCStringNoCopy(kIOConsoleSessionOnConsoleKey);
    gIOConsoleSessionSecureInputPIDKey   = OSSymbol::withCStringNoCopy(kIOConsoleSessionSecureInputPIDKey);
    gIOConsoleSessionScreenLockedTimeKey = OSSymbol::withCStringNoCopy(kIOConsoleSessionScreenLockedTimeKey);

    gIOConsoleUsersSeedValue	       = OSData::withBytesNoCopy(&gIOConsoleUsersSeed, sizeof(gIOConsoleUsersSeed));
	
    gIOPlatformSleepActionKey	= OSSymbol::withCStringNoCopy(kIOPlatformSleepActionKey);
    gIOPlatformWakeActionKey	= OSSymbol::withCStringNoCopy(kIOPlatformWakeActionKey);
    gIOPlatformQuiesceActionKey	= OSSymbol::withCStringNoCopy(kIOPlatformQuiesceActionKey);
    gIOPlatformActiveActionKey	= OSSymbol::withCStringNoCopy(kIOPlatformActiveActionKey);

    gIOPlatformFunctionHandlerSet		= OSSymbol::withCStringNoCopy(kIOPlatformFunctionHandlerSet);
#if defined(__i386__) || defined(__x86_64__)
    sCPULatencyFunctionName[kCpuDelayBusStall]	= OSSymbol::withCStringNoCopy(kIOPlatformFunctionHandlerMaxBusDelay);
    sCPULatencyFunctionName[kCpuDelayInterrupt]	= OSSymbol::withCStringNoCopy(kIOPlatformFunctionHandlerMaxInterruptDelay);
#endif
    gNotificationLock	 	= IORecursiveLockAlloc();

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

    gJobsLock	= IOLockAlloc();
    gJobs 	= OSOrderedSet::withCapacity( 10 );

    gIOServiceBusyLock = IOLockAlloc();

    gIOConsoleUsersLock = IOLockAlloc();

    err = semaphore_create(kernel_task, &gJobsSemaphore, SYNC_POLICY_FIFO, 0);

    gIOConsoleLockCallout = thread_call_allocate(&IOService::consoleLockTimer, NULL);

    assert( gIOServiceBusyLock && gJobs && gJobsLock && gIOConsoleUsersLock
    		&& gIOConsoleLockCallout && (err == KERN_SUCCESS) );

    gIOResources = IOResources::resources();
    assert( gIOResources );

    gArbitrationLockQueueLock = IOLockAlloc();
    queue_init(&gArbitrationLockQueueActive);
    queue_init(&gArbitrationLockQueueWaiting);
    queue_init(&gArbitrationLockQueueFree);

    assert( gArbitrationLockQueueLock );

    gIOTerminatePhase2List = OSArray::withCapacity( 2 );
    gIOStopList            = OSArray::withCapacity( 16 );
    gIOStopProviderList    = OSArray::withCapacity( 16 );
    gIOFinalizeList	   = OSArray::withCapacity( 16 );
    assert( gIOTerminatePhase2List && gIOStopList && gIOStopProviderList && gIOFinalizeList );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if IOMATCHDEBUG
static UInt64 getDebugFlags( OSDictionary * props )
{
    OSNumber *	debugProp;
    UInt64	debugFlags;

    debugProp = OSDynamicCast( OSNumber,
		props->getObject( gIOKitDebugKey ));
    if( debugProp)
	debugFlags = debugProp->unsigned64BitValue();
    else
	debugFlags = gIOKitDebug;

    return( debugFlags );
}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Probe a matched service and return an instance to be started.
// The default score is from the property table, & may be altered
// during probe to change the start order.

IOService * IOService::probe(	IOService * provider,
				SInt32	  * score )
{
    return( this );
}

bool IOService::start( IOService * provider )
{
    return( true );
}

void IOService::stop( IOService * provider )
{
}

void IOService::free( void )
{
    requireMaxBusStall(0);
    requireMaxInterruptDelay(0);
    if( getPropertyTable())
        unregisterAllInterest();
    PMfree();
    super::free();
}

/*
 * Attach in service plane
 */
bool IOService::attach( IOService * provider )
{
    bool	ok;

    if( provider) {

	if( gIOKitDebug & kIOLogAttach)
            LOG( "%s::attach(%s)\n", getName(),
                    provider->getName());

        provider->lockForArbitration();
        if( provider->__state[0] & kIOServiceInactiveState)
            ok = false;
        else
            ok = attachToParent( provider, gIOServicePlane);
        provider->unlockForArbitration();

    } else {
	gIOServiceRoot = this;
	ok = attachToParent( getRegistryRoot(), gIOServicePlane);
    }

    return( ok );
}

IOService * IOService::getServiceRoot( void )
{
    return( gIOServiceRoot );
}

void IOService::detach( IOService * provider )
{
    IOService * newProvider = 0;
    SInt32	busy;
    bool	adjParent;

    if( gIOKitDebug & kIOLogAttach)
        LOG("%s::detach(%s)\n", getName(), provider->getName());

    lockForArbitration();

    adjParent = ((busy = (__state[1] & kIOServiceBusyStateMask))
               && (provider == getProvider()));

    detachFromParent( provider, gIOServicePlane );

    if( busy) {
        newProvider = getProvider();
        if( busy && (__state[1] & kIOServiceTermPhase3State) && (0 == newProvider))
            _adjustBusy( -busy );
    }

    unlockForArbitration();

    if( newProvider) {
        newProvider->lockForArbitration();
        newProvider->_adjustBusy(1);
        newProvider->unlockForArbitration();
    }

    // check for last client detach from a terminated service
    if( provider->lockForArbitration( true )) {
        if( adjParent)
            provider->_adjustBusy( -1 );
        if( (provider->__state[1] & kIOServiceTermPhase3State)
         && (0 == provider->getClient())) {
            provider->scheduleFinalize();
        }
        provider->unlockForArbitration();
    }
}

/*
 * Register instance - publish it for matching
 */

void IOService::registerService( IOOptionBits options )
{
    char *		pathBuf;
    const char *	path;
    char *		skip;
    int			len;
    enum { kMaxPathLen	= 256 };
    enum { kMaxChars	= 63 };

    IORegistryEntry * parent = this;
    IORegistryEntry * root = getRegistryRoot();
    while( parent && (parent != root))
        parent = parent->getParentEntry( gIOServicePlane);

    if( parent != root) {
        IOLog("%s: not registry member at registerService()\n", getName());
        return;
    }

    // Allow the Platform Expert to adjust this node.
    if( gIOPlatform && (!gIOPlatform->platformAdjustService(this)))
	return;

    if( (this != gIOResources)
     && (kIOLogRegister & gIOKitDebug)) {

        pathBuf = (char *) IOMalloc( kMaxPathLen );

        IOLog( "Registering: " );

        len = kMaxPathLen;
        if( pathBuf && getPath( pathBuf, &len, gIOServicePlane)) {

            path = pathBuf;
            if( len > kMaxChars) {
                IOLog("..");
                len -= kMaxChars;
                path += len;
                if( (skip = strchr( path, '/')))
                    path = skip;
            }
        } else
            path = getName();

        IOLog( "%s\n", path );

	if( pathBuf)
	    IOFree( pathBuf, kMaxPathLen );
    }

    startMatching( options );
}

void IOService::startMatching( IOOptionBits options )
{
    IOService *	provider;
    UInt32	prevBusy = 0;
    bool	needConfig;
    bool	needWake = false;
    bool	ok;
    bool	sync;
    bool	waitAgain;

    lockForArbitration();

    sync = (options & kIOServiceSynchronous)
	|| ((provider = getProvider())
		&& (provider->__state[1] & kIOServiceSynchronousState));

	if ( options & kIOServiceAsynchronous )
		sync = false;

    needConfig =  (0 == (__state[1] & (kIOServiceNeedConfigState | kIOServiceConfigState)))
	       && (0 == (__state[0] & kIOServiceInactiveState));

    __state[1] |= kIOServiceNeedConfigState;

//    __state[0] &= ~kIOServiceInactiveState;

//    if( sync) LOG("OSKernelStackRemaining = %08x @ %s\n",
//			OSKernelStackRemaining(), getName());

    if( needConfig) {
        needWake = (0 != (kIOServiceSyncPubState & __state[1]));
    }

    if( sync)
	__state[1] |= kIOServiceSynchronousState;
    else
	__state[1] &= ~kIOServiceSynchronousState;

    unlockForArbitration();

    if( needConfig) {

	prevBusy = _adjustBusy( 1 );

        if( needWake) {
            IOLockLock( gIOServiceBusyLock );
            thread_wakeup( (event_t) this/*&__state[1]*/ );
            IOLockUnlock( gIOServiceBusyLock );

        } else if( !sync || (kIOServiceAsynchronous & options)) {

            ok = (0 != _IOServiceJob::startJob( this, kMatchNubJob, options ));
    
        } else do {

            if( (__state[1] & kIOServiceNeedConfigState))
                doServiceMatch( options );

            lockForArbitration();
            IOLockLock( gIOServiceBusyLock );

            waitAgain = (prevBusy < (__state[1] & kIOServiceBusyStateMask));
            if( waitAgain)
                __state[1] |= kIOServiceSyncPubState | kIOServiceBusyWaiterState;
            else
                __state[1] &= ~kIOServiceSyncPubState;

            unlockForArbitration();

            if( waitAgain)
                assert_wait( (event_t) this/*&__state[1]*/, THREAD_UNINT);

            IOLockUnlock( gIOServiceBusyLock );
            if( waitAgain)
                thread_block(THREAD_CONTINUE_NULL);

        } while( waitAgain );
    }
}

IOReturn IOService::catalogNewDrivers( OSOrderedSet * newTables )
{
    OSDictionary *	table;
    OSSet *	        set;
    OSSet *	        allSet = 0;
    IOService *		service;
#if IOMATCHDEBUG
    SInt32		count = 0;
#endif

    newTables->retain();
    
    while( (table = (OSDictionary *) newTables->getFirstObject())) {

	LOCKWRITENOTIFY();
        set = (OSSet *) copyExistingServices( table, 
						kIOServiceRegisteredState,
						kIOServiceExistingSet);
	UNLOCKNOTIFY();
	if( set) {

#if IOMATCHDEBUG
	    count += set->getCount();
#endif
	    if (allSet) {
		allSet->merge((const OSSet *) set);
		set->release();
	    }
	    else
		allSet = set;
	}

#if IOMATCHDEBUG
	if( getDebugFlags( table ) & kIOLogMatch)
	    LOG("Matching service count = %ld\n", (long)count);
#endif
	newTables->removeObject(table);
    }

    if (allSet) {
	while( (service = (IOService *) allSet->getAnyObject())) {
	    service->startMatching(kIOServiceAsynchronous);
	    allSet->removeObject(service);
	}
	allSet->release();
    }

    newTables->release();

    return( kIOReturnSuccess );
}

 _IOServiceJob * _IOServiceJob::startJob( IOService * nub, int type,
						IOOptionBits options )
{
    _IOServiceJob *	job;

    job = new _IOServiceJob;
    if( job && !job->init()) {
        job->release();
        job = 0;
    }

    if( job) {
        job->type	= type;
        job->nub	= nub;
	job->options	= options;
        nub->retain();			// thread will release()
        pingConfig( job );
    }

    return( job );
}

/*
 * Called on a registered service to see if it matches
 * a property table.
 */

bool IOService::matchPropertyTable( OSDictionary * table, SInt32 * score )
{
    return( matchPropertyTable(table) );
}

bool IOService::matchPropertyTable( OSDictionary * table )
{
    return( true );
}

/*
 * Called on a matched service to allocate resources
 * before first driver is attached.
 */

IOReturn IOService::getResources( void )
{
    return( kIOReturnSuccess);
}

/*
 * Client/provider accessors
 */

IOService * IOService::getProvider( void ) const
{
    IOService *	self = (IOService *) this;
    IOService *	parent;
    SInt32	generation;

    parent = __provider;
    generation = getGenerationCount();
    if( __providerGeneration == generation)
	return( parent );

    parent = (IOService *) getParentEntry( gIOServicePlane);
    if( parent == IORegistryEntry::getRegistryRoot())
	/* root is not an IOService */
	parent = 0;

    self->__provider = parent;
    // save the count before getParentEntry()
    self->__providerGeneration = generation;

    return( parent );
}

IOWorkLoop * IOService::getWorkLoop() const
{ 
    IOService *provider = getProvider();

    if (provider)
	return provider->getWorkLoop();
    else
	return 0;
}

OSIterator * IOService::getProviderIterator( void ) const
{
    return( getParentIterator( gIOServicePlane));
}

IOService * IOService::getClient( void ) const
{
    return( (IOService *) getChildEntry( gIOServicePlane));
}

OSIterator * IOService::getClientIterator( void ) const
{
    return( getChildIterator( gIOServicePlane));
}

OSIterator * _IOOpenServiceIterator::iterator( OSIterator * _iter,
						const IOService * client,
						const IOService * provider )
{
    _IOOpenServiceIterator * inst;

    if( !_iter)
	return( 0 );

    inst = new _IOOpenServiceIterator;

    if( inst && !inst->init()) {
	inst->release();
	inst = 0;
    }
    if( inst) {
	inst->iter = _iter;
	inst->client = client;
	inst->provider = provider;
    }

    return( inst );
}

void _IOOpenServiceIterator::free()
{
    iter->release();
    if( last)
	last->unlockForArbitration();
    OSIterator::free();
}

OSObject * _IOOpenServiceIterator::getNextObject()
{
    IOService * next;

    if( last)
	last->unlockForArbitration();

    while( (next = (IOService *) iter->getNextObject())) {

	next->lockForArbitration();
	if( (client && (next->isOpen( client )))
	 || (provider && (provider->isOpen( next ))) )
            break;
	next->unlockForArbitration();
    }

    last = next;

    return( next );
}

bool _IOOpenServiceIterator::isValid()
{
    return( iter->isValid() );
}

void _IOOpenServiceIterator::reset()
{
    if( last) {
	last->unlockForArbitration();
	last = 0;
    }
    iter->reset();
}

OSIterator * IOService::getOpenProviderIterator( void ) const
{
    return( _IOOpenServiceIterator::iterator( getProviderIterator(), this, 0 ));
}

OSIterator * IOService::getOpenClientIterator( void ) const
{
    return( _IOOpenServiceIterator::iterator( getClientIterator(), 0, this ));
}


IOReturn IOService::callPlatformFunction( const OSSymbol * functionName,
					  bool waitForFunction,
					  void *param1, void *param2,
					  void *param3, void *param4 )
{
  IOReturn  result = kIOReturnUnsupported;
  IOService *provider;

  if (gIOPlatformFunctionHandlerSet == functionName)
  {
#if defined(__i386__) || defined(__x86_64__)
    const OSSymbol * functionHandlerName = (const OSSymbol *) param1;
    IOService *	     target		 = (IOService *) param2;
    bool	     enable		 = (param3 != 0);

    if (sCPULatencyFunctionName[kCpuDelayBusStall] == functionHandlerName)
	result = setLatencyHandler(kCpuDelayBusStall, target, enable);
    else if (sCPULatencyFunctionName[kCpuDelayInterrupt] == param1)
	result = setLatencyHandler(kCpuDelayInterrupt, target, enable);
#endif /* defined(__i386__) || defined(__x86_64__) */
  }

  if ((kIOReturnUnsupported == result) && (provider = getProvider())) {
    result = provider->callPlatformFunction(functionName, waitForFunction,
					    param1, param2, param3, param4);
  }
  
  return result;
}

IOReturn IOService::callPlatformFunction( const char * functionName,
					  bool waitForFunction,
					  void *param1, void *param2,
					  void *param3, void *param4 )
{
  IOReturn result = kIOReturnNoMemory;
  const OSSymbol *functionSymbol = OSSymbol::withCString(functionName);
  
  if (functionSymbol != 0) {
    result = callPlatformFunction(functionSymbol, waitForFunction,
				  param1, param2, param3, param4);
    functionSymbol->release();
  }
  
  return result;
}


/*
 * Accessors for global services
 */

IOPlatformExpert * IOService::getPlatform( void )
{
    return( gIOPlatform);
}

class IOPMrootDomain * IOService::getPMRootDomain( void )
{
    return( gIOPMRootDomain);
}

IOService * IOService::getResourceService( void )
{
    return( gIOResources );
}

void IOService::setPlatform( IOPlatformExpert * platform)
{
    gIOPlatform = platform;
    gIOResources->attachToParent( gIOServiceRoot, gIOServicePlane );
}

void IOService::setPMRootDomain( class IOPMrootDomain * rootDomain)
{
    gIOPMRootDomain = rootDomain;
    publishResource("IOKit");
}

/*
 * Stacking change
 */

bool IOService::lockForArbitration( bool isSuccessRequired )
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
    if( !queue_empty( &gArbitrationLockQueueFree )) {
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
        if( active->service == element->service ) {
            found = true;
            break;
        }
    }

    if( found ) { // this object is already locked

        // determine whether it is the same or a different thread trying to lock
        if( active->thread != element->thread ) { // it is a different thread

            ArbitrationLockQueueElement * victim = 0;

            // before placing this new thread on the waiting queue, we look for
            // a deadlock cycle...

            while( 1 ) {
                // determine whether the active thread holding the object we
                // want is waiting for another object to be unlocked
                found = false;
                queue_iterate( &gArbitrationLockQueueWaiting,
                               waiting,
                               ArbitrationLockQueueElement *,
                               link )
                {
                    if( waiting->thread == active->thread ) {
                        assert( false == waiting->aborted );
                        found = true;
                        break;
                    }
                }

                if( found ) { // yes, active thread waiting for another object

                    // this may be a candidate for rejection if the required
                    // flag is not set, should we detect a deadlock later on
                    if( false == waiting->required )
                        victim = waiting;

                    // find the thread that is holding this other object, that
                    // is blocking the active thread from proceeding (fun :-)
                    found = false;
                    queue_iterate( &gArbitrationLockQueueActive,
                                   active,      // (reuse active queue element)
                                   ArbitrationLockQueueElement *,
                                   link )
                    {
                        if( active->service == waiting->service ) {
                            found = true;
                            break;
                        }
                    }

                    // someone must be holding it or it wouldn't be waiting
                    assert( found );

                    if( active->thread == element->thread ) {

                        // doh, it's waiting for the thread that originated
                        // this whole lock (ie. current thread) -> deadlock
                        if( false == element->required ) { // willing to fail?

                            // the originating thread doesn't have the required
                            // flag, so it can fail
                            success = false; // (fail originating lock request)
                            break; // (out of while)

                        } else { // originating thread is not willing to fail

                            // see if we came across a waiting thread that did
                            // not have the 'required' flag set: we'll fail it
                            if( victim ) {

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

            if( success ) { // put the request on the waiting queue?
                kern_return_t wait_result;

                // place this thread on the waiting queue and put it to sleep;
                // we place it at the tail of the queue...
                queue_enter( &gArbitrationLockQueueWaiting,
                             element,
                             ArbitrationLockQueueElement *,
                             link );

                // declare that this thread will wait for a given event
restart_sleep:  wait_result = assert_wait( element,
					   element->required ? THREAD_UNINT
					   : THREAD_INTERRUPTIBLE );

                // unlock global access
                IOUnlock( gArbitrationLockQueueLock );

                // put thread to sleep, waiting for our event to fire...
		if (wait_result == THREAD_WAITING)
		    wait_result = thread_block(THREAD_CONTINUE_NULL);


                // ...and we've been woken up; we might be in one of two states:
                // (a) we've been aborted and our queue element is not on
                //     any of the three queues, but is floating around
                // (b) we're allowed to proceed with the lock and we have
                //     already been moved from the waiting queue to the
                //     active queue.
                // ...plus a 3rd state, should the thread have been interrupted:
                // (c) we're still on the waiting queue

                // determine whether we were interrupted out of our sleep
                if( THREAD_INTERRUPTED == wait_result ) {

                    // re-lock global access
                    IOTakeLock( gArbitrationLockQueueLock );

                    // determine whether we're still on the waiting queue
                    found = false;
                    queue_iterate( &gArbitrationLockQueueWaiting,
                                   waiting,     // (reuse waiting queue element)
                                   ArbitrationLockQueueElement *,
                                   link )
                    {
                        if( waiting == element ) {
                            found = true;
                            break;
                        }
                    }

                    if( found ) { // yes, we're still on the waiting queue

                        // determine whether we're willing to fail
                        if( false == element->required ) {

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
                if( element->aborted ) {
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
    if( kPutOnActiveQueue == action ) {
        queue_enter( &gArbitrationLockQueueActive,
                     element,
                     ArbitrationLockQueueElement *,
                     link );
    } else if( kPutOnFreeQueue == action ) {
        queue_enter( &gArbitrationLockQueueFree,
                     element,
                     ArbitrationLockQueueElement *,
                     link );
    } else {
        assert( 0 ); // kPutOnWaitingQueue never occurs, handled specially above
    }

    // unlock global access
    IOUnlock( gArbitrationLockQueueLock );

    return( success );
}

void IOService::unlockForArbitration( void )
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
        if( element->service == this ) {
            found = true;
            break;
        }
    }

    assert( found );

    // determine whether the lock has been taken recursively
    if( element->count > 1 ) {
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
            if( element->service == this ) {
                found = true;
                break;
            }
        }

        if ( found ) { // we found an interested thread on waiting queue

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

void IOService::applyToProviders( IOServiceApplierFunction applier,
                                  void * context )
{
    applyToParents( (IORegistryEntryApplierFunction) applier,
                    context, gIOServicePlane );
}

void IOService::applyToClients( IOServiceApplierFunction applier,
                                void * context )
{
    applyToChildren( (IORegistryEntryApplierFunction) applier,
                     context, gIOServicePlane );
}


/*
 * Client messages
 */


// send a message to a client or interested party of this service
IOReturn IOService::messageClient( UInt32 type, OSObject * client,
                                   void * argument, vm_size_t argSize )
{
    IOReturn 				ret;
    IOService * 			service;
    _IOServiceInterestNotifier *	notify;

    if( (service = OSDynamicCast( IOService, client)))
        ret = service->message( type, this, argument );
    
    else if( (notify = OSDynamicCast( _IOServiceInterestNotifier, client))) {

        _IOServiceNotifierInvocation invocation;
        bool			 willNotify;
    
        invocation.thread = current_thread();
    
        LOCKWRITENOTIFY();
        willNotify = (0 != (kIOServiceNotifyEnable & notify->state));
    
        if( willNotify) {
            queue_enter( &notify->handlerInvocations, &invocation,
                            _IOServiceNotifierInvocation *, link );
        }
        UNLOCKNOTIFY();
    
        if( willNotify) {

            ret = (*notify->handler)( notify->target, notify->ref,
                                          type, this, argument, argSize );
    
            LOCKWRITENOTIFY();
            queue_remove( &notify->handlerInvocations, &invocation,
                            _IOServiceNotifierInvocation *, link );
            if( kIOServiceNotifyWaiter & notify->state) {
                notify->state &= ~kIOServiceNotifyWaiter;
                WAKEUPNOTIFY( notify );
            }
            UNLOCKNOTIFY();

        } else
            ret = kIOReturnSuccess;

    } else
        ret = kIOReturnBadArgument;

    return( ret );
}

static void
applyToInterestNotifiers(const IORegistryEntry *target,
			 const OSSymbol * typeOfInterest,
			 OSObjectApplierFunction applier,
			 void * context )
{
    OSArray *		copyArray = 0;

    LOCKREADNOTIFY();

    IOCommand *notifyList =
	OSDynamicCast( IOCommand, target->getProperty( typeOfInterest ));

    if( notifyList) {
        copyArray = OSArray::withCapacity(1);

	// iterate over queue, entry is set to each element in the list
	iterqueue(&notifyList->fCommandChain, entry) {
	    _IOServiceInterestNotifier * notify;

	    queue_element(entry, notify, _IOServiceInterestNotifier *, chain);
	    copyArray->setObject(notify);
	}
    }
    UNLOCKNOTIFY();

    if( copyArray) {
	unsigned int	index;
	OSObject *	next;

	for( index = 0; (next = copyArray->getObject( index )); index++)
	    (*applier)(next, context);
	copyArray->release();
    }
}

void IOService::applyToInterested( const OSSymbol * typeOfInterest,
                                   OSObjectApplierFunction applier,
                                   void * context )
{
    if (gIOGeneralInterest == typeOfInterest)
	applyToClients( (IOServiceApplierFunction) applier, context );
    applyToInterestNotifiers(this, typeOfInterest, applier, context);
}

struct MessageClientsContext {
    IOService *	service;
    UInt32	type;
    void *	argument;
    vm_size_t	argSize;
    IOReturn	ret;
};

static void messageClientsApplier( OSObject * object, void * ctx )
{
    IOReturn		    ret;
    MessageClientsContext * context = (MessageClientsContext *) ctx;

    ret = context->service->messageClient( context->type,
                                           object, context->argument, context->argSize );    
    if( kIOReturnSuccess != ret)
        context->ret = ret;
}

// send a message to all clients
IOReturn IOService::messageClients( UInt32 type,
                                    void * argument, vm_size_t argSize )
{
    MessageClientsContext	context;

    context.service	= this;
    context.type	= type;
    context.argument	= argument;
    context.argSize	= argSize;
    context.ret		= kIOReturnSuccess;

    applyToInterested( gIOGeneralInterest,
                       &messageClientsApplier, &context );

    return( context.ret );
}

IOReturn IOService::acknowledgeNotification( IONotificationRef notification,
                                              IOOptionBits response )
{
    return( kIOReturnUnsupported );
}

IONotifier * IOService::registerInterest( const OSSymbol * typeOfInterest,
                  IOServiceInterestHandler handler, void * target, void * ref )
{
    _IOServiceInterestNotifier * notify = 0;

    if( (typeOfInterest != gIOGeneralInterest)
     && (typeOfInterest != gIOBusyInterest)
     && (typeOfInterest != gIOAppPowerStateInterest)
     && (typeOfInterest != gIOConsoleSecurityInterest)
     && (typeOfInterest != gIOPriorityPowerStateInterest))
        return( 0 );

    lockForArbitration();
    if( 0 == (__state[0] & kIOServiceInactiveState)) {

        notify = new _IOServiceInterestNotifier;
        if( notify && !notify->init()) {
            notify->release();
            notify = 0;
        }

        if( notify) {
            notify->handler = handler;
            notify->target = target;
            notify->ref = ref;
            notify->state = kIOServiceNotifyEnable;
            queue_init( &notify->handlerInvocations );

            ////// queue

            LOCKWRITENOTIFY();

	    // Get the head of the notifier linked list
	    IOCommand *notifyList = (IOCommand *) getProperty( typeOfInterest );
	    if (!notifyList || !OSDynamicCast(IOCommand, notifyList)) {
		notifyList = OSTypeAlloc(IOCommand);
		if (notifyList) {
		    notifyList->init();
		    setProperty( typeOfInterest, notifyList);
		    notifyList->release();
		}
	    }

	    if (notifyList) {
		enqueue(&notifyList->fCommandChain, &notify->chain);
		notify->retain();	// ref'ed while in list
	    }

            UNLOCKNOTIFY();
        }
    }
    unlockForArbitration();

    return( notify );
}

static void cleanInterestList( OSObject * head )
{
    IOCommand *notifyHead = OSDynamicCast(IOCommand, head);
    if (!notifyHead)
	return;

    LOCKWRITENOTIFY();
    while ( queue_entry_t entry = dequeue(&notifyHead->fCommandChain) ) {
	queue_next(entry) = queue_prev(entry) = 0;

	_IOServiceInterestNotifier * notify;

	queue_element(entry, notify, _IOServiceInterestNotifier *, chain);
	notify->release();
    }
    UNLOCKNOTIFY();
}

void IOService::unregisterAllInterest( void )
{
    cleanInterestList( getProperty( gIOGeneralInterest ));
    cleanInterestList( getProperty( gIOBusyInterest ));
    cleanInterestList( getProperty( gIOAppPowerStateInterest ));
    cleanInterestList( getProperty( gIOPriorityPowerStateInterest ));
    cleanInterestList( getProperty( gIOConsoleSecurityInterest ));
}

/*
 * _IOServiceInterestNotifier
 */

// wait for all threads, other than the current one,
//  to exit the handler

void _IOServiceInterestNotifier::wait()
{
    _IOServiceNotifierInvocation * next;
    bool doWait;

    do {
        doWait = false;
        queue_iterate( &handlerInvocations, next,
                        _IOServiceNotifierInvocation *, link) {
            if( next->thread != current_thread() ) {
                doWait = true;
                break;
            }
        }
        if( doWait) {
            state |= kIOServiceNotifyWaiter;
	       SLEEPNOTIFY(this);
        }

    } while( doWait );
}

void _IOServiceInterestNotifier::free()
{
    assert( queue_empty( &handlerInvocations ));
    OSObject::free();
}

void _IOServiceInterestNotifier::remove()
{
    LOCKWRITENOTIFY();

    if( queue_next( &chain )) {
	remqueue(&chain);
	queue_next( &chain) = queue_prev( &chain) = 0;
	release();
    }

    state &= ~kIOServiceNotifyEnable;

    wait();

    UNLOCKNOTIFY();
    
    release();
}

bool _IOServiceInterestNotifier::disable()
{
    bool	ret;

    LOCKWRITENOTIFY();

    ret = (0 != (kIOServiceNotifyEnable & state));
    state &= ~kIOServiceNotifyEnable;
    if( ret)
        wait();

    UNLOCKNOTIFY();

    return( ret );
}

void _IOServiceInterestNotifier::enable( bool was )
{
    LOCKWRITENOTIFY();
    if( was)
        state |= kIOServiceNotifyEnable;
    else
        state &= ~kIOServiceNotifyEnable;
    UNLOCKNOTIFY();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Termination
 */

#define tailQ(o)		setObject(o)
#define headQ(o)		setObject(0, o)
#define TLOG(fmt, args...)  	{ if(kIOLogYield & gIOKitDebug) { IOLog("[%llx] ", thread_tid(current_thread())); IOLog(fmt, ## args); }}

static void _workLoopAction( IOWorkLoop::Action action,
                             IOService * service,
                             void * p0 = 0, void * p1 = 0,
                             void * p2 = 0, void * p3 = 0 )
{
    IOWorkLoop * wl;

    if( (wl = service->getWorkLoop())) {
        wl->retain();
        wl->runAction( action, service, p0, p1, p2, p3 );
        wl->release();
    } else
        (*action)( service, p0, p1, p2, p3 );
}

bool IOService::requestTerminate( IOService * provider, IOOptionBits options )
{
    bool ok;

    // if its our only provider
    ok = isParent( provider, gIOServicePlane, true);

    // -- compat
    if( ok) {
        provider->terminateClient( this, options | kIOServiceRecursing );
        ok = (0 != (__state[1] & kIOServiceRecursing));
    }
    // --

    return( ok );
}

bool IOService::terminatePhase1( IOOptionBits options )
{
    IOService *	 victim;
    IOService *	 client;
    OSIterator * iter;
    OSArray *	 makeInactive;
	int          waitResult = THREAD_AWAKENED;
	bool         wait;
    bool		 ok;
    bool		 didInactive;
    bool		 startPhase2 = false;

    TLOG("%s::terminatePhase1(%08llx)\n", getName(), (long long)options);

    uint64_t regID = getRegistryEntryID();
    IOServiceTrace(
	IOSERVICE_TERMINATE_PHASE1,
	(uintptr_t) regID, 
	(uintptr_t) (regID >> 32),
	(uintptr_t) this,
	(uintptr_t) options);

    // -- compat
    if( options & kIOServiceRecursing) {
        __state[1] |= kIOServiceRecursing;
        return( true );
    }
    // -- 

    makeInactive = OSArray::withCapacity( 16 );
    if( !makeInactive)
        return( false );

    victim = this;
    victim->retain();

    while( victim ) {

		didInactive = victim->lockForArbitration( true );
        if( didInactive) {
            didInactive = (0 == (victim->__state[0] & kIOServiceInactiveState));
            if( didInactive) {
                victim->__state[0] |= kIOServiceInactiveState;
                victim->__state[0] &= ~(kIOServiceRegisteredState | kIOServiceMatchedState
                                        | kIOServiceFirstPublishState | kIOServiceFirstMatchState);

				if (victim == this)
					victim->__state[1] |= kIOServiceTermPhase1State;

                victim->_adjustBusy( 1 );

            } else if (victim != this) do {

				IOLockLock(gIOServiceBusyLock);
				wait = (victim->__state[1] & kIOServiceTermPhase1State);
				if( wait) {
				    TLOG("%s::waitPhase1(%s)\n", getName(), victim->getName());
					victim->__state[1] |= kIOServiceTerm1WaiterState;
					victim->unlockForArbitration();
					assert_wait((event_t)&victim->__state[1], THREAD_UNINT);
				}
				IOLockUnlock(gIOServiceBusyLock);
				if( wait) {
					waitResult = thread_block(THREAD_CONTINUE_NULL);
				    TLOG("%s::did waitPhase1(%s)\n", getName(), victim->getName());
					victim->lockForArbitration();
				}
			} while( wait && (waitResult != THREAD_TIMED_OUT));

			victim->unlockForArbitration();
        }
        if( victim == this)
            startPhase2 = didInactive;
        if( didInactive) {

            victim->deliverNotification( gIOTerminatedNotification, 0, 0xffffffff );
            IOUserClient::destroyUserReferences( victim );

            iter = victim->getClientIterator();
            if( iter) {
                while( (client = (IOService *) iter->getNextObject())) {
                    TLOG("%s::requestTerminate(%s, %08llx)\n",
                            client->getName(), victim->getName(), (long long)options);
                    ok = client->requestTerminate( victim, options );
                    TLOG("%s::requestTerminate(%s, ok = %d)\n",
                            client->getName(), victim->getName(), ok);

		    uint64_t regID1 = client->getRegistryEntryID();
		    uint64_t regID2 = victim->getRegistryEntryID();
		    IOServiceTrace(
			(ok ? IOSERVICE_TERMINATE_REQUEST_OK
			   : IOSERVICE_TERMINATE_REQUEST_FAIL),
			(uintptr_t) regID1, 
			(uintptr_t) (regID1 >> 32),
			(uintptr_t) regID2, 
			(uintptr_t) (regID2 >> 32));

                    if( ok)
                        makeInactive->setObject( client );
                }
                iter->release();
            }
        }
        victim->release();
        victim = (IOService *) makeInactive->getObject(0);
        if( victim) {
            victim->retain();
            makeInactive->removeObject(0);
        }
    }

    makeInactive->release();

    if( startPhase2)
    {
		lockForArbitration();
		__state[1] &= ~kIOServiceTermPhase1State;
		if (kIOServiceTerm1WaiterState & __state[1])
		{
			__state[1] &= ~kIOServiceTerm1WaiterState;
			TLOG("%s::wakePhase1\n", getName());
			IOLockLock( gIOServiceBusyLock );
			thread_wakeup( (event_t) &__state[1]);
			IOLockUnlock( gIOServiceBusyLock );
		}
		unlockForArbitration();

        scheduleTerminatePhase2( options );
    }
    return( true );
}

void IOService::scheduleTerminatePhase2( IOOptionBits options )
{
    AbsoluteTime	deadline;
    int			waitResult = THREAD_AWAKENED;
    bool		wait, haveDeadline = false;

    options |= kIOServiceRequired;

    retain();

    IOLockLock( gJobsLock );

    if( (options & kIOServiceSynchronous)
        && (current_thread() != gIOTerminateThread)) {

        do {
            wait = (gIOTerminateThread != 0);
            if( wait) {
                // wait to become the terminate thread
                IOLockSleep( gJobsLock, &gIOTerminateThread, THREAD_UNINT);
            }
        } while( wait );

        gIOTerminateThread = current_thread();
        gIOTerminatePhase2List->setObject( this );
        gIOTerminateWork++;

        do {
	    while( gIOTerminateWork )
		terminateWorker( options );
            wait = (0 != (__state[1] & kIOServiceBusyStateMask));
            if( wait) {
                // wait for the victim to go non-busy
                if( !haveDeadline) {
                    clock_interval_to_deadline( 15, kSecondScale, &deadline );
                    haveDeadline = true;
                }
                waitResult = IOLockSleepDeadline( gJobsLock, &gIOTerminateWork,
                                                  deadline, THREAD_UNINT );
                if( waitResult == THREAD_TIMED_OUT) {
                    IOLog("%s::terminate(kIOServiceSynchronous) timeout\n", getName());
		}
            }
        } while(gIOTerminateWork || (wait && (waitResult != THREAD_TIMED_OUT)));

	gIOTerminateThread = 0;
	IOLockWakeup( gJobsLock, (event_t) &gIOTerminateThread, /* one-thread */ false);

    } else {
        // ! kIOServiceSynchronous

        gIOTerminatePhase2List->setObject( this );
        if( 0 == gIOTerminateWork++) {
	    if( !gIOTerminateThread)
		kernel_thread_start(&terminateThread, (void *) options, &gIOTerminateThread);
	    else
		IOLockWakeup(gJobsLock, (event_t) &gIOTerminateWork, /* one-thread */ false );
	}
    }

    IOLockUnlock( gJobsLock );

    release();
}

void IOService::terminateThread( void * arg, wait_result_t waitResult )
{
    IOLockLock( gJobsLock );

    while (gIOTerminateWork)
	terminateWorker( (uintptr_t) arg );

    thread_deallocate(gIOTerminateThread);
    gIOTerminateThread = 0;
    IOLockWakeup( gJobsLock, (event_t) &gIOTerminateThread, /* one-thread */ false);

    IOLockUnlock( gJobsLock );
}

void IOService::scheduleStop( IOService * provider )
{
    TLOG("%s::scheduleStop(%s)\n", getName(), provider->getName());

    uint64_t regID1 = getRegistryEntryID();
    uint64_t regID2 = provider->getRegistryEntryID();
    IOServiceTrace(
	IOSERVICE_TERMINATE_SCHEDULE_STOP,
	(uintptr_t) regID1, 
	(uintptr_t) (regID1 >> 32),
	(uintptr_t) regID2, 
	(uintptr_t) (regID2 >> 32));

    IOLockLock( gJobsLock );
    gIOStopList->tailQ( this );
    gIOStopProviderList->tailQ( provider );

    if( 0 == gIOTerminateWork++) {
        if( !gIOTerminateThread)
	    kernel_thread_start(&terminateThread, (void *) 0, &gIOTerminateThread);
        else
            IOLockWakeup(gJobsLock, (event_t) &gIOTerminateWork, /* one-thread */ false );
    }

    IOLockUnlock( gJobsLock );
}

void IOService::scheduleFinalize( void )
{
    TLOG("%s::scheduleFinalize\n", getName());

    uint64_t regID1 = getRegistryEntryID();
    IOServiceTrace(
	IOSERVICE_TERMINATE_SCHEDULE_FINALIZE,
	(uintptr_t) regID1, 
	(uintptr_t) (regID1 >> 32),
	0, 0);

    IOLockLock( gJobsLock );
    gIOFinalizeList->tailQ( this );

    if( 0 == gIOTerminateWork++) {
        if( !gIOTerminateThread)
	    kernel_thread_start(&terminateThread, (void *) 0, &gIOTerminateThread);
        else
            IOLockWakeup(gJobsLock, (event_t) &gIOTerminateWork, /* one-thread */ false );
    }

    IOLockUnlock( gJobsLock );
}

bool IOService::willTerminate( IOService * provider, IOOptionBits options )
{
    return( true );
}

bool IOService::didTerminate( IOService * provider, IOOptionBits options, bool * defer )
{
    if( false == *defer) {

        if( lockForArbitration( true )) {
            if( false == provider->handleIsOpen( this ))
                scheduleStop( provider );
            // -- compat
            else {
                message( kIOMessageServiceIsRequestingClose, provider, (void *) options );
                if( false == provider->handleIsOpen( this ))
                    scheduleStop( provider );
            }
            // --
            unlockForArbitration();
        }
    }

    return( true );
}

void IOService::actionWillTerminate( IOService * victim, IOOptionBits options, 
				     OSArray * doPhase2List,
				     void *unused2 __unused,
				     void *unused3 __unused  )
{
    OSIterator * iter;
    IOService *	 client;
    bool	 ok;

    iter = victim->getClientIterator();
    if( iter) {
        while( (client = (IOService *) iter->getNextObject())) {
            TLOG("%s::willTerminate(%s, %08llx)\n",
                    client->getName(), victim->getName(), (long long)options);

	    uint64_t regID1 = client->getRegistryEntryID();
	    uint64_t regID2 = victim->getRegistryEntryID();
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

void IOService::actionDidTerminate( IOService * victim, IOOptionBits options,
			    void *unused1 __unused, void *unused2 __unused,
			    void *unused3 __unused )
{
    OSIterator * iter;
    IOService *	 client;
    bool defer = false;

    victim->messageClients( kIOMessageServiceIsTerminated, (void *) options );

    iter = victim->getClientIterator();
    if( iter) {
        while( (client = (IOService *) iter->getNextObject())) {
            TLOG("%s::didTerminate(%s, %08llx)\n",
                    client->getName(), victim->getName(), (long long)options);
            client->didTerminate( victim, options, &defer );

	    uint64_t regID1 = client->getRegistryEntryID();
	    uint64_t regID2 = victim->getRegistryEntryID();
	    IOServiceTrace(
		(defer ? IOSERVICE_TERMINATE_DID_DEFER
		       : IOSERVICE_TERMINATE_DID),
		(uintptr_t) regID1, 
		(uintptr_t) (regID1 >> 32),
		(uintptr_t) regID2, 
		(uintptr_t) (regID2 >> 32));

            TLOG("%s::didTerminate(%s, defer %d)\n",
                    client->getName(), victim->getName(), defer);
        }
        iter->release();
    }
}

void IOService::actionFinalize( IOService * victim, IOOptionBits options,
			    void *unused1 __unused, void *unused2 __unused,
			    void *unused3 __unused )
{
    TLOG("%s::finalize(%08llx)\n", victim->getName(), (long long)options);

    uint64_t regID1 = victim->getRegistryEntryID();
    IOServiceTrace(
	IOSERVICE_TERMINATE_FINALIZE,
	(uintptr_t) regID1, 
	(uintptr_t) (regID1 >> 32),
	0, 0);

    victim->finalize( options );
}

void IOService::actionStop( IOService * provider, IOService * client,
			    void *unused1 __unused, void *unused2 __unused,
			    void *unused3 __unused )
{
    TLOG("%s::stop(%s)\n", client->getName(), provider->getName());

    uint64_t regID1 = provider->getRegistryEntryID();
    uint64_t regID2 = client->getRegistryEntryID();
    IOServiceTrace(
	IOSERVICE_TERMINATE_STOP,
	(uintptr_t) regID1, 
	(uintptr_t) (regID1 >> 32),
	(uintptr_t) regID2, 
	(uintptr_t) (regID2 >> 32));

    client->stop( provider );
    if( provider->isOpen( client ))
        provider->close( client );
    TLOG("%s::detach(%s)\n", client->getName(), provider->getName());
    client->detach( provider );
}

void IOService::terminateWorker( IOOptionBits options )
{
    OSArray *		doPhase2List;
    OSArray *		didPhase2List;
    OSSet *		freeList;
    UInt32		workDone;
    IOService * 	victim;
    IOService * 	client;
    IOService * 	provider;
    unsigned int	idx;
    bool		moreToDo;
    bool		doPhase2;
    bool		doPhase3;

    options |= kIOServiceRequired;

    doPhase2List  = OSArray::withCapacity( 16 );
    didPhase2List = OSArray::withCapacity( 16 );
    freeList	  = OSSet::withCapacity( 16 );
    if( (0 == doPhase2List) || (0 == didPhase2List) || (0 == freeList))
        return;

    do {
        workDone = gIOTerminateWork;

        while( (victim = (IOService *) gIOTerminatePhase2List->getObject(0) )) {
    
            victim->retain();
            gIOTerminatePhase2List->removeObject(0);
            IOLockUnlock( gJobsLock );

            while( victim ) {
        
                doPhase2 = victim->lockForArbitration( true );
                if( doPhase2) {
                    doPhase2 = (0 != (kIOServiceInactiveState & victim->__state[0]));
                    if( doPhase2) {
                        doPhase2 = (0 == (victim->__state[1] & kIOServiceTermPhase2State))
                                && (0 == (victim->__state[1] & kIOServiceConfigState));
                        if( doPhase2)
                            victim->__state[1] |= kIOServiceTermPhase2State;
                    }
                    victim->unlockForArbitration();
                }
                if( doPhase2) {
                    if( 0 == victim->getClient()) {
                        // no clients - will go to finalize
                        IOLockLock( gJobsLock );
                        gIOFinalizeList->tailQ( victim );
                        IOLockUnlock( gJobsLock );
                    } else {
                        _workLoopAction( (IOWorkLoop::Action) &actionWillTerminate,
                                            victim, (void *) options, (void *) doPhase2List );
                    }
                    didPhase2List->headQ( victim );
                }
                victim->release();
                victim = (IOService *) doPhase2List->getObject(0);
                if( victim) {
                    victim->retain();
                    doPhase2List->removeObject(0);
                }
            }
        
            while( (victim = (IOService *) didPhase2List->getObject(0)) ) {
    
                if( victim->lockForArbitration( true )) {
                    victim->__state[1] |= kIOServiceTermPhase3State;
                    victim->unlockForArbitration();
                }
                _workLoopAction( (IOWorkLoop::Action) &actionDidTerminate,
                                    victim, (void *) options );
                didPhase2List->removeObject(0);
            }
            IOLockLock( gJobsLock );
        }

        // phase 3
        do {
            doPhase3 = false;
            // finalize leaves
            while( (victim = (IOService *) gIOFinalizeList->getObject(0))) {
    
                IOLockUnlock( gJobsLock );
                _workLoopAction( (IOWorkLoop::Action) &actionFinalize,
                                    victim, (void *) options );
                IOLockLock( gJobsLock );
                // hold off free
                freeList->setObject( victim );
                // safe if finalize list is append only
                gIOFinalizeList->removeObject(0);
            }
        
            for( idx = 0;
                 (!doPhase3) && (client = (IOService *) gIOStopList->getObject(idx)); ) {
        
                provider = (IOService *) gIOStopProviderList->getObject(idx);
                assert( provider );
        
                if( !provider->isChild( client, gIOServicePlane )) {
                    // may be multiply queued - nop it
                    TLOG("%s::nop stop(%s)\n", client->getName(), provider->getName());

		    uint64_t regID1 = provider->getRegistryEntryID();
		    uint64_t regID2 = client->getRegistryEntryID();
		    IOServiceTrace(
			IOSERVICE_TERMINATE_STOP_NOP,
			(uintptr_t) regID1, 
			(uintptr_t) (regID1 >> 32),
			(uintptr_t) regID2, 
			(uintptr_t) (regID2 >> 32));

                } else {
                    // a terminated client is not ready for stop if it has clients, skip it
                    if( (kIOServiceInactiveState & client->__state[0]) && client->getClient()) {
                        TLOG("%s::defer stop(%s)\n", client->getName(), provider->getName());

			uint64_t regID1 = provider->getRegistryEntryID();
			uint64_t regID2 = client->getRegistryEntryID();
			IOServiceTrace(
			    IOSERVICE_TERMINATE_STOP_DEFER,
			    (uintptr_t) regID1, 
			    (uintptr_t) (regID1 >> 32),
			    (uintptr_t) regID2, 
			    (uintptr_t) (regID2 >> 32));

                        idx++;
                        continue;
                    }
        
                    IOLockUnlock( gJobsLock );
                    _workLoopAction( (IOWorkLoop::Action) &actionStop,
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

        } while( doPhase3 );

        gIOTerminateWork -= workDone;
        moreToDo = (gIOTerminateWork != 0);

        if( !moreToDo) {
            TLOG("iokit terminate done, %d stops remain\n", gIOStopList->getCount());
	    IOServiceTrace(
		IOSERVICE_TERMINATE_DONE,
		(uintptr_t) gIOStopList->getCount(), 0, 0, 0);
        }

    } while( moreToDo );

    IOLockUnlock( gJobsLock );

    freeList->release();
    doPhase2List->release();
    didPhase2List->release();

    IOLockLock( gJobsLock );
}

bool IOService::finalize( IOOptionBits options )
{
    OSIterator *	iter;
    IOService *		provider;

    iter = getProviderIterator();
    assert( iter );

    if( iter) {
        while( (provider = (IOService *) iter->getNextObject())) {

            // -- compat
            if( 0 == (__state[1] & kIOServiceTermPhase3State)) {
                /* we come down here on programmatic terminate */
                stop( provider );
                if( provider->isOpen( this ))
                    provider->close( this );
                detach( provider );
            } else {
            //--
                if( provider->lockForArbitration( true )) {
                    if( 0 == (provider->__state[1] & kIOServiceTermPhase3State))
                        scheduleStop( provider );
                    provider->unlockForArbitration();
                }
            }
        }
        iter->release();
    }

    return( true );
}

#undef tailQ
#undef headQ

/*
 * Terminate
 */

void IOService::doServiceTerminate( IOOptionBits options )
{
}

// a method in case someone needs to override it
bool IOService::terminateClient( IOService * client, IOOptionBits options )
{
    bool ok;

    if( client->isParent( this, gIOServicePlane, true))
        // we are the clients only provider
        ok = client->terminate( options );
    else
	ok = true;

    return( ok );
}

bool IOService::terminate( IOOptionBits options )
{
    options |= kIOServiceTerminate;

    return( terminatePhase1( options ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Open & close
 */

struct ServiceOpenMessageContext
{
    IOService *	 service;
    UInt32	 type;
    IOService *  excludeClient;
    IOOptionBits options;
};

static void serviceOpenMessageApplier( OSObject * object, void * ctx )
{
    ServiceOpenMessageContext * context = (ServiceOpenMessageContext *) ctx;

    if( object != context->excludeClient)
        context->service->messageClient( context->type, object, (void *) context->options );    
}

bool IOService::open( 	IOService *	forClient,
                        IOOptionBits	options,
                        void *		arg )
{
    bool			ok;
    ServiceOpenMessageContext	context;

    context.service		= this;
    context.type		= kIOMessageServiceIsAttemptingOpen;
    context.excludeClient	= forClient;
    context.options		= options;

    applyToInterested( gIOGeneralInterest,
                        &serviceOpenMessageApplier, &context );

    if( false == lockForArbitration(false) )
        return false;

    ok = (0 == (__state[0] & kIOServiceInactiveState));
    if( ok)
        ok = handleOpen( forClient, options, arg );

    unlockForArbitration();

    return( ok );
}

void IOService::close( 	IOService *	forClient,
                        IOOptionBits	options )
{
    bool		wasClosed;
    bool		last = false;

    lockForArbitration();

    wasClosed = handleIsOpen( forClient );
    if( wasClosed) {
        handleClose( forClient, options );
	last = (__state[1] & kIOServiceTermPhase3State);
    }

    unlockForArbitration();

    if( last)
        forClient->scheduleStop( this );

    else if( wasClosed) {

        ServiceOpenMessageContext context;
    
        context.service		= this;
        context.type		= kIOMessageServiceWasClosed;
        context.excludeClient	= forClient;
        context.options		= options;

        applyToInterested( gIOGeneralInterest,
                            &serviceOpenMessageApplier, &context );
    }
}

bool IOService::isOpen( const IOService * forClient ) const
{
    IOService *	self = (IOService *) this;
    bool ok;

    self->lockForArbitration();

    ok = handleIsOpen( forClient );

    self->unlockForArbitration();

    return( ok );
}

bool IOService::handleOpen( 	IOService *	forClient,
                                IOOptionBits	options,
                                void *		arg )
{
    bool	ok;

    ok = (0 == __owner);
    if( ok )
        __owner = forClient;

    else if( options & kIOServiceSeize ) {
        ok = (kIOReturnSuccess == messageClient( kIOMessageServiceIsRequestingClose,
                                __owner, (void *) options ));
        if( ok && (0 == __owner ))
            __owner = forClient;
        else
            ok = false;
    }
    return( ok );
}

void IOService::handleClose( 	IOService *	forClient,
                                IOOptionBits	options )
{
    if( __owner == forClient)
        __owner = 0;
}

bool IOService::handleIsOpen( 	const IOService * forClient ) const
{
    if( forClient)
	return( __owner == forClient );
    else
	return( __owner != forClient );
}

/*
 * Probing & starting
 */
static SInt32 IONotifyOrdering( const OSMetaClassBase * inObj1, const OSMetaClassBase * inObj2, void * ref )
{
    const _IOServiceNotifier * obj1 = (const _IOServiceNotifier *) inObj1;
    const _IOServiceNotifier * obj2 = (const _IOServiceNotifier *) inObj2;
    SInt32             val1;
    SInt32             val2;

    val1 = 0;
    val2 = 0;

    if ( obj1 )
        val1 = obj1->priority;

    if ( obj2 )
        val2 = obj2->priority;

    return ( val1 - val2 );
}

static SInt32 IOServiceObjectOrder( const OSObject * entry, void * ref)
{
    OSDictionary *	dict;
    IOService *		service;
    _IOServiceNotifier * notify;
    OSSymbol *		key = (OSSymbol *) ref;
    OSNumber *		offset;

    if( (notify = OSDynamicCast( _IOServiceNotifier, entry)))
	return( notify->priority );

    else if( (service = OSDynamicCast( IOService, entry)))
        offset = OSDynamicCast(OSNumber, service->getProperty( key ));
    else if( (dict = OSDynamicCast( OSDictionary, entry)))
        offset = OSDynamicCast(OSNumber, dict->getObject( key ));
    else {
	assert( false );
	offset = 0;
    }

    if( offset)
        return( (SInt32) offset->unsigned32BitValue());
    else
        return( kIODefaultProbeScore );
}

SInt32 IOServiceOrdering( const OSMetaClassBase * inObj1, const OSMetaClassBase * inObj2, void * ref )
{
    const OSObject *	obj1 = (const OSObject *) inObj1;
    const OSObject *	obj2 = (const OSObject *) inObj2;
    SInt32               val1;
    SInt32               val2;

    val1 = 0;
    val2 = 0;

    if ( obj1 )
        val1 = IOServiceObjectOrder( obj1, ref );

    if ( obj2 )
        val2 = IOServiceObjectOrder( obj2, ref );

    return ( val1 - val2 );
}

IOService * IOService::copyClientWithCategory( const OSSymbol * category )
{
    IOService *		service = 0;
    OSIterator *	iter;
    const OSSymbol *	nextCat;

    iter = getClientIterator();
    if( iter) {
	while( (service = (IOService *) iter->getNextObject())) {
	    if( kIOServiceInactiveState & service->__state[0])
		continue;
            nextCat = (const OSSymbol *) OSDynamicCast( OSSymbol,
			service->getProperty( gIOMatchCategoryKey ));
	    if( category == nextCat)
	    {
		service->retain();
		break;
	    }
	}
	iter->release();
    }
    return( service );
}

IOService * IOService::getClientWithCategory( const OSSymbol * category )
{
    IOService *
    service = copyClientWithCategory(category);
    if (service)
	service->release();
    return (service);
}

bool IOService::invokeNotifer( _IOServiceNotifier * notify )
{
    _IOServiceNotifierInvocation invocation;
    bool			 willNotify;
    bool			 ret = true;

    invocation.thread = current_thread();

    LOCKWRITENOTIFY();
    willNotify = (0 != (kIOServiceNotifyEnable & notify->state));

    if( willNotify) {
        queue_enter( &notify->handlerInvocations, &invocation,
                        _IOServiceNotifierInvocation *, link );
    }
    UNLOCKNOTIFY();

    if( willNotify) {

	ret = (*notify->handler)(notify->target, notify->ref, this, notify);

        LOCKWRITENOTIFY();
        queue_remove( &notify->handlerInvocations, &invocation,
                        _IOServiceNotifierInvocation *, link );
        if( kIOServiceNotifyWaiter & notify->state) {
            notify->state &= ~kIOServiceNotifyWaiter;
            WAKEUPNOTIFY( notify );
        }
        UNLOCKNOTIFY();
    }

    return( ret );
}

/*
 * Alloc and probe matching classes,
 * called on the provider instance
 */

void IOService::probeCandidates( OSOrderedSet * matches )
{
    OSDictionary 	*	match = 0;
    OSSymbol 		*	symbol;
    IOService 		*	inst;
    IOService 		*	newInst;
    OSDictionary 	*	props;
    SInt32			score;
    OSNumber 		*	newPri;
    OSOrderedSet 	*	familyMatches = 0;
    OSOrderedSet 	*	startList;
    OSDictionary	*	startDict = 0;
    const OSSymbol	* 	category;
    OSIterator		*	iter;
    _IOServiceNotifier 	*		notify;
    OSObject 		*	nextMatch = 0;
    bool			started;
    bool			needReloc = false;
#if CONFIG_MACF_KEXT
    OSBoolean		*	isSandbox = 0;
    bool			useSandbox = false;
#endif
#if IOMATCHDEBUG
    SInt64			debugFlags;
#endif
    IOService * client = NULL;


    assert( matches );
    while( !needReloc && (nextMatch = matches->getFirstObject())) {

        nextMatch->retain();
        matches->removeObject(nextMatch);
        
        if( (notify = OSDynamicCast( _IOServiceNotifier, nextMatch ))) {

            lockForArbitration();
            if( 0 == (__state[0] & kIOServiceInactiveState))
                invokeNotifer( notify );
            unlockForArbitration();
            nextMatch->release();
            nextMatch = 0;
            continue;

        } else if( !(match = OSDynamicCast( OSDictionary, nextMatch ))) {
            nextMatch->release();
            nextMatch = 0;
            continue;
	}

	props = 0;
#if IOMATCHDEBUG
        debugFlags = getDebugFlags( match );
#endif

        do {
            category = OSDynamicCast( OSSymbol,
			match->getObject( gIOMatchCategoryKey ));
	    if( 0 == category)
		category = gIODefaultMatchCategoryKey;
	    
	    if( (client = copyClientWithCategory(category)) ) {
#if IOMATCHDEBUG
		if( debugFlags & kIOLogMatch)
		    LOG("%s: match category %s exists\n", getName(),
				category->getCStringNoCopy());
#endif
                nextMatch->release();
                nextMatch = 0;

		client->release();
		client = NULL;

                continue;
	    }

            // create a copy now in case its modified during matching
            props = OSDictionary::withDictionary( match, match->getCount());
            if( 0 == props)
                continue;
	    props->setCapacityIncrement(1);		

	    // check the nub matches
	    if( false == passiveMatch( props, true ))
		continue;

            // Check to see if driver reloc has been loaded.
            needReloc = (false == gIOCatalogue->isModuleLoaded( match ));
            if( needReloc) {
#if IOMATCHDEBUG
		if( debugFlags & kIOLogCatalogue)
		    LOG("%s: stalling for module\n", getName());
#endif
                // If reloc hasn't been loaded, exit;
                // reprobing will occur after reloc has been loaded.
                continue;
	    }

            // reorder on family matchPropertyTable score.
            if( 0 == familyMatches)
                familyMatches = OSOrderedSet::withCapacity( 1,
                        IOServiceOrdering, (void *) gIOProbeScoreKey );
            if( familyMatches)
                familyMatches->setObject( props );

        } while( false );

        if (nextMatch) {
            nextMatch->release();
            nextMatch = 0;
        }
        if( props)
            props->release();
    }
    matches->release();
    matches = 0;

    if( familyMatches) {

        while( !needReloc
             && (props = (OSDictionary *) familyMatches->getFirstObject())) {

            props->retain();
            familyMatches->removeObject( props );
    
            inst = 0;
            newInst = 0;
#if IOMATCHDEBUG
            debugFlags = getDebugFlags( props );
#endif
            do {
                symbol = OSDynamicCast( OSSymbol,
                                props->getObject( gIOClassKey));
                if( !symbol)
                    continue;
    
                //IOLog("%s alloc (symbol %p props %p)\n", symbol->getCStringNoCopy(), symbol, props);

                // alloc the driver instance
                inst = (IOService *) OSMetaClass::allocClassWithName( symbol);
    
                if( !inst) {
                    IOLog("Couldn't alloc class \"%s\"\n",
                        symbol->getCStringNoCopy());
                    continue;
                }
    
                // init driver instance
                if( !(inst->init( props ))) {
#if IOMATCHDEBUG
                    if( debugFlags & kIOLogStart)
                        IOLog("%s::init fails\n", symbol->getCStringNoCopy());
#endif
                    continue;
                }
                if( __state[1] & kIOServiceSynchronousState)
                    inst->__state[1] |= kIOServiceSynchronousState;
    
                // give the driver the default match category if not specified
                category = OSDynamicCast( OSSymbol,
                            props->getObject( gIOMatchCategoryKey ));
                if( 0 == category)
                    category = gIODefaultMatchCategoryKey;
                inst->setProperty( gIOMatchCategoryKey, (OSObject *) category );
#if CONFIG_MACF_KEXT
		isSandbox = OSDynamicCast(OSBoolean,
                            props->getObject("IOKitForceMatch"));
#endif
                // attach driver instance
                if( !(inst->attach( this )))
                        continue;
    
                // pass in score from property table
                score = familyMatches->orderObject( props );
    
                // & probe the new driver instance
#if IOMATCHDEBUG
                if( debugFlags & kIOLogProbe)
                    LOG("%s::probe(%s)\n",
                        inst->getMetaClass()->getClassName(), getName());
#endif
    
                newInst = inst->probe( this, &score );
                inst->detach( this );
#if CONFIG_MACF_KEXT
		/*
		 * If this is the Sandbox driver and it matched, this is a
		 * disallowed device; toss any drivers that were already
		 * matched.
		 */
		if (isSandbox && isSandbox->isTrue() && newInst != 0) {
		    if (startDict != 0) {
			startDict->flushCollection();
			startDict->release();
			startDict = 0;
		    }
		    useSandbox = true;
		}
#endif
                if( 0 == newInst) {
#if IOMATCHDEBUG
                    if( debugFlags & kIOLogProbe)
                        IOLog("%s::probe fails\n", symbol->getCStringNoCopy());
#endif
                    continue;
                }
    
                // save the score
                newPri = OSNumber::withNumber( score, 32 );
                if( newPri) {
                    newInst->setProperty( gIOProbeScoreKey, newPri );
                    newPri->release();
                }
    
                // add to start list for the match category
                if( 0 == startDict)
                    startDict = OSDictionary::withCapacity( 1 );
                assert( startDict );
                startList = (OSOrderedSet *)
                                startDict->getObject( category );
                if( 0 == startList) {
                    startList = OSOrderedSet::withCapacity( 1,
                            IOServiceOrdering, (void *) gIOProbeScoreKey );
                    if( startDict && startList) {
                        startDict->setObject( category, startList );
                        startList->release();
                    }
                }
                assert( startList );
                if( startList)
                    startList->setObject( newInst );
    
            } while( false );

            props->release();
            if( inst)
                inst->release();
#if CONFIG_MACF_KEXT
	    /*
	     * If we're forcing the sandbox, drop out of the loop.
	     */
	    if (isSandbox && isSandbox->isTrue() && useSandbox)
		    break;
#endif
        }
        familyMatches->release();
        familyMatches = 0;
    }

    // start the best (until success) of each category

    iter = OSCollectionIterator::withCollection( startDict );
    if( iter) {
	while( (category = (const OSSymbol *) iter->getNextObject())) {

	    startList = (OSOrderedSet *) startDict->getObject( category );
	    assert( startList );
	    if( !startList)
		continue;

            started = false;
            while( true // (!started)
		   && (inst = (IOService *)startList->getFirstObject())) {

		inst->retain();
		startList->removeObject(inst);

#if IOMATCHDEBUG
        	debugFlags = getDebugFlags( inst->getPropertyTable() );

                if( debugFlags & kIOLogStart) {
                    if( started)
                        LOG( "match category exists, skipping " );
                    LOG( "%s::start(%s) <%d>\n", inst->getName(),
                         getName(), inst->getRetainCount());
                }
#endif
                if( false == started)
                    started = startCandidate( inst );
#if IOMATCHDEBUG
                if( (debugFlags & kIOLogStart) && (false == started))
                    LOG( "%s::start(%s) <%d> failed\n", inst->getName(), getName(),
                         inst->getRetainCount());
#endif
		inst->release();
            }
        }
	iter->release();
    }


    // adjust the busy count by +1 if matching is stalled for a module,
    // or -1 if a previously stalled matching is complete.
    lockForArbitration();
    SInt32 adjBusy = 0;
    uint64_t regID = getRegistryEntryID();

    if( needReloc) {
        adjBusy = (__state[1] & kIOServiceModuleStallState) ? 0 : 1;
        if( adjBusy) {

	    IOServiceTrace(
		IOSERVICE_MODULESTALL,
		(uintptr_t) regID, 
		(uintptr_t) (regID >> 32),
		(uintptr_t) this,
		0);

            __state[1] |= kIOServiceModuleStallState;
	}

    } else if( __state[1] & kIOServiceModuleStallState) {

	    IOServiceTrace(
	    IOSERVICE_MODULEUNSTALL,
	    (uintptr_t) regID, 
	    (uintptr_t) (regID >> 32),
	    (uintptr_t) this,
	    0);

        __state[1] &= ~kIOServiceModuleStallState;
        adjBusy = -1;
    }
    if( adjBusy)
        _adjustBusy( adjBusy );
    unlockForArbitration();

    if( startDict)
	startDict->release();
}

/*
 * Start a previously attached & probed instance,
 * called on exporting object instance
 */

bool IOService::startCandidate( IOService * service )
{
    bool		ok;

    ok = service->attach( this );

    if( ok)
    {
	if (this != gIOResources)
	{
	    // stall for any nub resources
	    checkResources();
	    // stall for any driver resources
	    service->checkResources();
	}
	
	AbsoluteTime startTime;
	AbsoluteTime endTime;
	UInt64       nano;

	if (kIOLogStart & gIOKitDebug)
	    clock_get_uptime(&startTime);

        ok = service->start(this);

	if (kIOLogStart & gIOKitDebug)
	{
	    clock_get_uptime(&endTime);
    
	    if (CMP_ABSOLUTETIME(&endTime, &startTime) > 0)
	    {
		SUB_ABSOLUTETIME(&endTime, &startTime);
		absolutetime_to_nanoseconds(endTime, &nano);
		if (nano > 500000000ULL)
		    IOLog("%s::start took %ld ms\n", service->getName(), (long)(UInt32)(nano / 1000000ULL));
	    }
	}
        if( !ok)
            service->detach( this );
    }
    return( ok );
}

void IOService::publishResource( const char * key, OSObject * value )
{
    const OSSymbol *	sym;

    if( (sym = OSSymbol::withCString( key))) {
        publishResource( sym, value);
	sym->release();
    }
}

void IOService::publishResource( const OSSymbol * key, OSObject * value )
{
    if( 0 == value)
	value = (OSObject *) gIOServiceKey;

    gIOResources->setProperty( key, value);

    if( IORecursiveLockHaveLock( gNotificationLock))
	return;

    gIOResourceGenerationCount++;
    gIOResources->registerService();
}

bool IOService::addNeededResource( const char * key )
{
    OSObject *	resourcesProp;
    OSSet *	set;
    OSString *	newKey;
    bool ret;

    resourcesProp = getProperty( gIOResourceMatchKey );

    newKey = OSString::withCString( key );
    if( (0 == resourcesProp) || (0 == newKey))
	return( false);

    set = OSDynamicCast( OSSet, resourcesProp );
    if( !set) {
	set = OSSet::withCapacity( 1 );
	if( set)
            set->setObject( resourcesProp );
    }
    else
        set->retain();

    set->setObject( newKey );
    newKey->release();
    ret = setProperty( gIOResourceMatchKey, set );
    set->release();

    return( ret );
}

bool IOService::checkResource( OSObject * matching )
{
    OSString *		str;
    OSDictionary *	table;

    if( (str = OSDynamicCast( OSString, matching ))) {
	if( gIOResources->getProperty( str ))
	    return( true );
    }

    if( str)
	table = resourceMatching( str );
    else if( (table = OSDynamicCast( OSDictionary, matching )))
	table->retain();
    else {
	IOLog("%s: Can't match using: %s\n", getName(),
		matching->getMetaClass()->getClassName());
	/* false would stall forever */
	return( true );
    }

    if( gIOKitDebug & kIOLogConfig)
        LOG("config(%p): stalling %s\n", IOThreadSelf(), getName());

    waitForService( table );

    if( gIOKitDebug & kIOLogConfig)
        LOG("config(%p): waking\n", IOThreadSelf() );

    return( true );
}

bool IOService::checkResources( void )
{
    OSObject * 		resourcesProp;
    OSSet *		set;
    OSIterator *	iter;
    bool		ok;

    resourcesProp = getProperty( gIOResourceMatchKey );
    if( 0 == resourcesProp)
        return( true );

    if( (set = OSDynamicCast( OSSet, resourcesProp ))) {

	iter = OSCollectionIterator::withCollection( set );
	ok = (0 != iter);
        while( ok && (resourcesProp = iter->getNextObject()) )
            ok = checkResource( resourcesProp );
	if( iter)
	    iter->release();

    } else
	ok = checkResource( resourcesProp );

    return( ok );
}


void _IOConfigThread::configThread( void )
{
    _IOConfigThread * 	inst;

    do {
	if( !(inst = new _IOConfigThread))
	    continue;
	if( !inst->init())
	    continue;
	thread_t unused;
	if (KERN_SUCCESS != kernel_thread_start(&_IOConfigThread::main, inst, &unused))
	    continue;

	return;

    } while( false);

    if( inst)
	inst->release();

    return;
}

void _IOConfigThread::free( void )
{
    thread_deallocate(current_thread());
    OSObject::free();
}

void IOService::doServiceMatch( IOOptionBits options )
{
    _IOServiceNotifier * notify;
    OSIterator *	iter;
    OSOrderedSet *	matches;
    SInt32		catalogGeneration;
    bool		keepGuessing = true;
    bool		reRegistered = true;

//    job->nub->deliverNotification( gIOPublishNotification,
//  				kIOServiceRegisteredState, 0xffffffff );

    while( keepGuessing ) {

        matches = gIOCatalogue->findDrivers( this, &catalogGeneration );
	// the matches list should always be created by findDrivers()
        if( matches) {

            lockForArbitration();
            if( 0 == (__state[0] & kIOServiceFirstPublishState))
                deliverNotification( gIOFirstPublishNotification,
                                     kIOServiceFirstPublishState, 0xffffffff );
	    LOCKREADNOTIFY();
            __state[1] &= ~kIOServiceNeedConfigState;
            __state[1] |= kIOServiceConfigState;
            __state[0] |= kIOServiceRegisteredState;

	    keepGuessing &= (0 == (__state[0] & kIOServiceInactiveState));
            if (reRegistered && keepGuessing) {
                iter = OSCollectionIterator::withCollection( (OSOrderedSet *)
                        gNotifications->getObject( gIOPublishNotification ) );
                if( iter) {
                    while((notify = (_IOServiceNotifier *)
                           iter->getNextObject())) {

                        if( passiveMatch( notify->matching )
                         && (kIOServiceNotifyEnable & notify->state))
                            matches->setObject( notify );
                    }
                    iter->release();
                }
            }

	    UNLOCKNOTIFY();
            unlockForArbitration();

            if (keepGuessing && matches->getCount() && (kIOReturnSuccess == getResources()))
                probeCandidates( matches );
            else
                matches->release();
        }

        lockForArbitration();
	reRegistered = (0 != (__state[1] & kIOServiceNeedConfigState));
	keepGuessing =
		   (reRegistered || (catalogGeneration !=
					gIOCatalogue->getGenerationCount()))
                && (0 == (__state[0] & kIOServiceInactiveState));

	if( keepGuessing)
            unlockForArbitration();
    }

    if( (0 == (__state[0] & kIOServiceInactiveState))
     && (0 == (__state[1] & kIOServiceModuleStallState)) ) {
        deliverNotification( gIOMatchedNotification,
		kIOServiceMatchedState, 0xffffffff );
	if( 0 == (__state[0] & kIOServiceFirstMatchState))
	    deliverNotification( gIOFirstMatchNotification,
		kIOServiceFirstMatchState, 0xffffffff );
    }

    __state[1] &= ~kIOServiceConfigState;
    if( __state[0] & kIOServiceInactiveState)
        scheduleTerminatePhase2();

    _adjustBusy( -1 );
    unlockForArbitration();
}

UInt32 IOService::_adjustBusy( SInt32 delta )
{
    IOService * next;
    UInt32	count;
    UInt32	result;
    bool	wasQuiet, nowQuiet, needWake;

    next = this;
    result = __state[1] & kIOServiceBusyStateMask;

    if( delta) do {
        if( next != this)
            next->lockForArbitration();
        count = next->__state[1] & kIOServiceBusyStateMask;
        wasQuiet = (0 == count);
	if (((delta < 0) && wasQuiet) || ((delta > 0) && (kIOServiceBusyMax == count)))
	    OSReportWithBacktrace("%s: bad busy count (%d,%d)\n", next->getName(), count, delta);
	else
	    count += delta;
	next->__state[1] = (next->__state[1] & ~kIOServiceBusyStateMask) | count;
        nowQuiet = (0 == count);
	needWake = (0 != (kIOServiceBusyWaiterState & next->__state[1]));

        if( needWake) {
            next->__state[1] &= ~kIOServiceBusyWaiterState;
            IOLockLock( gIOServiceBusyLock );
	    thread_wakeup( (event_t) next);
            IOLockUnlock( gIOServiceBusyLock );
        }
        if( next != this)
            next->unlockForArbitration();

        if( (wasQuiet || nowQuiet) ) {
	    uint64_t regID = next->getRegistryEntryID();

		IOServiceTrace(
		((wasQuiet/*nowBusy*/) ? IOSERVICE_BUSY : IOSERVICE_NONBUSY),
		(uintptr_t) regID, 
		(uintptr_t) (regID >> 32),
		(uintptr_t) next,
		0);

	    if (wasQuiet)
	    {
		next->__timeBusy = mach_absolute_time();
	    }
	    else
	    {
		next->__accumBusy += mach_absolute_time() - next->__timeBusy;
		next->__timeBusy = 0;
	    }

	    MessageClientsContext context;

	    context.service  = next;
	    context.type     = kIOMessageServiceBusyStateChange;
	    context.argument = (void *) wasQuiet;	/*nowBusy*/
	    context.argSize  = 0;

	    applyToInterestNotifiers( next, gIOBusyInterest, 
				     &messageClientsApplier, &context );

#if !NO_KEXTD
            if( nowQuiet && (next == gIOServiceRoot)) {
                OSKext::considerUnloads();
                IOServiceTrace(IOSERVICE_REGISTRY_QUIET, 0, 0, 0, 0);
            }
#endif
        }

        delta = nowQuiet ? -1 : +1;

    } while( (wasQuiet || nowQuiet) && (next = next->getProvider()));

    return( result );
}

void IOService::adjustBusy( SInt32 delta )
{
    lockForArbitration();
    _adjustBusy( delta );
    unlockForArbitration();
}

uint64_t IOService::getAccumulatedBusyTime( void )
{
    uint64_t accumBusy = __accumBusy;
    uint64_t timeBusy = __timeBusy;
    uint64_t nano;

    do
    {
	accumBusy = __accumBusy;
	timeBusy  = __timeBusy;
	if (timeBusy)
	    accumBusy += mach_absolute_time() - timeBusy;
    }
    while (timeBusy != __timeBusy);

    absolutetime_to_nanoseconds(*(AbsoluteTime *)&accumBusy, &nano);

    return (nano);
}

UInt32 IOService::getBusyState( void )
{
    return( __state[1] & kIOServiceBusyStateMask );
}

IOReturn IOService::waitForState( UInt32 mask, UInt32 value,
				  mach_timespec_t * timeout )
{
    panic("waitForState");
    return (kIOReturnUnsupported);
}

IOReturn IOService::waitForState( UInt32 mask, UInt32 value,
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
        if( wait) {
            __state[1] |= kIOServiceBusyWaiterState;
            unlockForArbitration();
            if( timeout != UINT64_MAX ) {
                if( computeDeadline ) {
                    AbsoluteTime  nsinterval;
                    nanoseconds_to_absolutetime(timeout, &nsinterval );
                    clock_absolutetime_interval_to_deadline(nsinterval, &abstime);
                    computeDeadline = false;
                }
                assert_wait_deadline((event_t)this, THREAD_UNINT, __OSAbsoluteTime(abstime));
            }
            else
                assert_wait((event_t)this, THREAD_UNINT );
        } else
            unlockForArbitration();
        IOLockUnlock( gIOServiceBusyLock );
        if( wait)
            waitResult = thread_block(THREAD_CONTINUE_NULL);

    } while( wait && (waitResult != THREAD_TIMED_OUT));

    if( waitResult == THREAD_TIMED_OUT)
        return( kIOReturnTimeout );
    else
        return( kIOReturnSuccess );
}

IOReturn IOService::waitQuiet( uint64_t timeout )
{
    return( waitForState( kIOServiceBusyStateMask, 0, timeout ));
}

IOReturn IOService::waitQuiet( mach_timespec_t * timeout )
{
    uint64_t    timeoutNS;

    if (timeout)
    {
	timeoutNS = timeout->tv_sec;
	timeoutNS *= kSecondScale;
	timeoutNS += timeout->tv_nsec;
    }
    else
	timeoutNS = UINT64_MAX;

    return( waitForState( kIOServiceBusyStateMask, 0, timeoutNS ));
}

bool IOService::serializeProperties( OSSerialize * s ) const
{
#if 0
    ((IOService *)this)->setProperty( ((IOService *)this)->__state,
		sizeof( __state), "__state");
#endif
    return( super::serializeProperties(s) );
}


void _IOConfigThread::main(void * arg, wait_result_t result)
{
    _IOConfigThread * self = (_IOConfigThread *) arg;
    _IOServiceJob * job;
    IOService 	*   nub;
    bool	    alive = true;
    kern_return_t   kr;
    thread_precedence_policy_data_t precedence = { -1 };

    kr = thread_policy_set(current_thread(), 
			    THREAD_PRECEDENCE_POLICY, 
			    (thread_policy_t) &precedence, 
			    THREAD_PRECEDENCE_POLICY_COUNT);
    if (KERN_SUCCESS != kr)
	IOLog("thread_policy_set(%d)\n", kr);

    do {

//	randomDelay();

        semaphore_wait( gJobsSemaphore );

	IOTakeLock( gJobsLock );
	job = (_IOServiceJob *) gJobs->getFirstObject();
        job->retain();
        gJobs->removeObject(job);
	if( job) {
	    gOutstandingJobs--;
//	    gNumConfigThreads--;	// we're out of service
	    gNumWaitingThreads--;	// we're out of service
	}
	IOUnlock( gJobsLock );

	if( job) {

	  nub = job->nub;

          if( gIOKitDebug & kIOLogConfig)
            LOG("config(%p): starting on %s, %d\n",
                        IOThreadSelf(), job->nub->getName(), job->type);

	  switch( job->type) {

	    case kMatchNubJob:
		nub->doServiceMatch( job->options );
		break;

            default:
                LOG("config(%p): strange type (%d)\n",
			IOThreadSelf(), job->type );
		break;
            }

	    nub->release();
            job->release();

            IOTakeLock( gJobsLock );
	    alive = (gOutstandingJobs > gNumWaitingThreads);
	    if( alive)
		gNumWaitingThreads++;	// back in service
//		gNumConfigThreads++;
	    else {
                if( 0 == --gNumConfigThreads) {
//                    IOLog("MATCH IDLE\n");
                    IOLockWakeup( gJobsLock, (event_t) &gNumConfigThreads, /* one-thread */ false );
                }
            }
            IOUnlock( gJobsLock );
	}

    } while( alive );

    if( gIOKitDebug & kIOLogConfig)
        LOG("config(%p): terminating\n", IOThreadSelf() );

    self->release();
}

IOReturn IOService::waitMatchIdle( UInt32 msToWait )
{
    bool            wait;
    int             waitResult = THREAD_AWAKENED;
    bool            computeDeadline = true;
    AbsoluteTime    deadline;

    IOLockLock( gJobsLock );
    do {
        wait = (0 != gNumConfigThreads);
        if( wait) {
            if( msToWait) {
                if( computeDeadline ) {
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
    } while( wait && (waitResult != THREAD_TIMED_OUT));
	IOLockUnlock( gJobsLock );

    if( waitResult == THREAD_TIMED_OUT)
        return( kIOReturnTimeout );
    else
        return( kIOReturnSuccess );
}

void _IOServiceJob::pingConfig( _IOServiceJob * job )
{
    int		count;
    bool	create;

    assert( job );

    IOTakeLock( gJobsLock );

    gOutstandingJobs++;
    gJobs->setLastObject( job );

    count = gNumWaitingThreads;
//    if( gNumConfigThreads) count++;// assume we're called from a config thread

    create = (  (gOutstandingJobs > count)
		&& (gNumConfigThreads < kMaxConfigThreads) );
    if( create) {
	gNumConfigThreads++;
	gNumWaitingThreads++;
    }

    IOUnlock( gJobsLock );

    job->release();

    if( create) {
        if( gIOKitDebug & kIOLogConfig)
            LOG("config(%d): creating\n", gNumConfigThreads - 1);
        _IOConfigThread::configThread();
    }

    semaphore_signal( gJobsSemaphore );
}

// internal - call with gNotificationLock
OSObject * IOService::copyExistingServices( OSDictionary * matching,
		 IOOptionBits inState, IOOptionBits options )
{
    OSObject *		current = 0;
    OSIterator *	iter;
    IOService *		service;
    OSObject *		obj;

    if( !matching)
	return( 0 );

    if(true 
      && (obj = matching->getObject(gIOProviderClassKey))
      && gIOResourcesKey
      && gIOResourcesKey->isEqualTo(obj)
      && (service = gIOResources))
    {
	if( (inState == (service->__state[0] & inState))
	  && (0 == (service->__state[0] & kIOServiceInactiveState))
	  &&  service->passiveMatch( matching ))
	{
	    if( options & kIONotifyOnce)
	    {
		service->retain();
		current = service;
	    }
	    else
		current = OSSet::withObjects(
				(const OSObject **) &service, 1, 1 );
	}
    }
    else
    {
	iter = IORegistryIterator::iterateOver( gIOServicePlane,
					    kIORegistryIterateRecursively );
	if( iter) {
	    do {
		iter->reset();
		while( (service = (IOService *) iter->getNextObject())) {
		    if( (inState == (service->__state[0] & inState))
		    && (0 == (service->__state[0] & kIOServiceInactiveState))
		    &&  service->passiveMatch( matching )) {
    
			if( options & kIONotifyOnce) {
			    service->retain();
			    current = service;
			    break;
			}
			if( current)
			    ((OSSet *)current)->setObject( service );
			else
			    current = OSSet::withObjects(
					    (const OSObject **) &service, 1, 1 );
		    }
		}
	    } while( !service && !iter->isValid());
	    iter->release();
	}
    }

    if( current && (0 == (options & (kIONotifyOnce | kIOServiceExistingSet)))) {
	iter = OSCollectionIterator::withCollection( (OSSet *)current );
	current->release();
	current = iter;
    }

    return( current );
}

// public version
OSIterator * IOService::getMatchingServices( OSDictionary * matching )
{
    OSIterator *	iter;

    // is a lock even needed?
    LOCKWRITENOTIFY();

    iter = (OSIterator *) copyExistingServices( matching,
						kIOServiceMatchedState );
    
    UNLOCKNOTIFY();

    return( iter );
}

struct _IOServiceMatchingNotificationHandlerRef
{
    IOServiceNotificationHandler handler;
    void * ref;
};

static bool _IOServiceMatchingNotificationHandler( void * target, void * refCon,
						   IOService * newService,
						   IONotifier * notifier )
{
    return ((*((_IOServiceNotifier *) notifier)->compatHandler)(target, refCon, newService));
}

// internal - call with gNotificationLock
IONotifier * IOService::setNotification(
	    const OSSymbol * type, OSDictionary * matching,
            IOServiceMatchingNotificationHandler handler, void * target, void * ref,
            SInt32 priority )
{
    _IOServiceNotifier * notify = 0;
    OSOrderedSet *	set;

    if( !matching)
	return( 0 );

    notify = new _IOServiceNotifier;
    if( notify && !notify->init()) {
        notify->release();
        notify = 0;
    }

    if( notify) {
	notify->handler = handler;
        notify->target = target;
        notify->matching = matching;
	matching->retain();
	if (handler == &_IOServiceMatchingNotificationHandler)
	{
	    notify->compatHandler = ((_IOServiceMatchingNotificationHandlerRef *)ref)->handler;
	    notify->ref = ((_IOServiceMatchingNotificationHandlerRef *)ref)->ref;
	}
	else
	    notify->ref = ref;
        notify->priority = priority;
	notify->state = kIOServiceNotifyEnable;
        queue_init( &notify->handlerInvocations );

        ////// queue

        if( 0 == (set = (OSOrderedSet *) gNotifications->getObject( type ))) {
            set = OSOrderedSet::withCapacity( 1,
			IONotifyOrdering, 0 );
            if( set) {
                gNotifications->setObject( type, set );
                set->release();
            }
        }
        notify->whence = set;
        if( set)
            set->setObject( notify );
    }

    return( notify );
}

// internal - call with gNotificationLock
IONotifier * IOService::doInstallNotification(
			const OSSymbol * type, OSDictionary * matching,
			IOServiceMatchingNotificationHandler handler,
			void * target, void * ref,
			SInt32 priority, OSIterator ** existing )
{
    OSIterator *	exist;
    IONotifier *	notify;
    IOOptionBits	inState;

    if( !matching)
	return( 0 );

    if( type == gIOPublishNotification)
	inState = kIOServiceRegisteredState;

    else if( type == gIOFirstPublishNotification)
	inState = kIOServiceFirstPublishState;

    else if( (type == gIOMatchedNotification)
	  || (type == gIOFirstMatchNotification))
	inState = kIOServiceMatchedState;
    else if( type == gIOTerminatedNotification)
	inState = 0;
    else
        return( 0 );

    notify = setNotification( type, matching, handler, target, ref, priority );
    
    if( inState)
        // get the current set
        exist = (OSIterator *) copyExistingServices( matching, inState );
    else
	exist = 0;

    *existing = exist;    

    return( notify );
}

#if !defined(__LP64__)
IONotifier * IOService::installNotification(const OSSymbol * type, OSDictionary * matching,
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
    if (result)
	matching->release();

    return (result);
}
#endif /* !defined(__LP64__) */


IONotifier * IOService::installNotification(
			const OSSymbol * type, OSDictionary * matching,
			IOServiceMatchingNotificationHandler handler,
			void * target, void * ref,
			SInt32 priority, OSIterator ** existing )
{
    IONotifier * notify;

    LOCKWRITENOTIFY();

    notify = doInstallNotification( type, matching, handler, target, ref,
		priority, existing );

    UNLOCKNOTIFY();

    return( notify );
}

IONotifier * IOService::addNotification(
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

    if (result)
	matching->release();

    return (result);
}

IONotifier * IOService::addMatchingNotification(
			const OSSymbol * type, OSDictionary * matching,
			IOServiceMatchingNotificationHandler handler,
			void * target, void * ref,
			SInt32 priority )
{
    OSIterator *		existing = NULL;
    _IOServiceNotifier *	notify;
    IOService *			next;

    notify = (_IOServiceNotifier *) installNotification( type, matching,
		handler, target, ref, priority, &existing );

    // send notifications for existing set
    if( existing) {

        notify->retain();		// in case handler remove()s
        while( (next = (IOService *) existing->getNextObject())) {

	    next->lockForArbitration();
	    if( 0 == (next->__state[0] & kIOServiceInactiveState))
                next->invokeNotifer( notify );
	    next->unlockForArbitration();
	}
        notify->release();
	existing->release();
    }

    return( notify );
}

bool IOService::syncNotificationHandler(
			void * /* target */, void * ref,
			IOService * newService,
			IONotifier * notifier )
{

    LOCKWRITENOTIFY();
    if (!*((IOService **) ref))
    {
	newService->retain();
	(*(IOService **) ref) = newService;
	WAKEUPNOTIFY(ref);
    }
    UNLOCKNOTIFY();

    return( false );
}

IOService * IOService::waitForMatchingService( OSDictionary * matching,
						uint64_t timeout)
{
    IONotifier *	notify = 0;
    // priority doesn't help us much since we need a thread wakeup
    SInt32		priority = 0;
    IOService *  	result;

    if (!matching)
        return( 0 );

    result = NULL;

    LOCKWRITENOTIFY();
    do
    {
        result = (IOService *) copyExistingServices( matching,
                            kIOServiceMatchedState, kIONotifyOnce );
	if (result)
	    break;
        notify = IOService::setNotification( gIOMatchedNotification, matching,
                    &IOService::syncNotificationHandler, (void *) 0,
                    &result, priority );
	 if (!notify)
	    break;
        if (UINT64_MAX != timeout)
	{
	    AbsoluteTime deadline;
	    nanoseconds_to_absolutetime(timeout, &deadline);
	    clock_absolutetime_interval_to_deadline(deadline, &deadline);
	    SLEEPNOTIFYTO(&result, deadline);
	}
        else
	{
	    SLEEPNOTIFY(&result);
	}
    }
    while( false );

    UNLOCKNOTIFY();

    if (notify)
        notify->remove();	// dequeues

    return( result );
}

IOService * IOService::waitForService( OSDictionary * matching,
					mach_timespec_t * timeout )
{
    IOService * result;
    uint64_t    timeoutNS;

    if (timeout)
    {
	timeoutNS = timeout->tv_sec;
	timeoutNS *= kSecondScale;
	timeoutNS += timeout->tv_nsec;
    }
    else
	timeoutNS = UINT64_MAX;

    result = waitForMatchingService(matching, timeoutNS);

    matching->release();
    if (result)
	result->release();

    return (result);
}

void IOService::deliverNotification( const OSSymbol * type,
                            IOOptionBits orNewState, IOOptionBits andNewState )
{
    _IOServiceNotifier * notify;
    OSIterator *	 iter;
    OSArray *		 willSend = 0;

    lockForArbitration();

    if( (0 == (__state[0] & kIOServiceInactiveState))
     ||	(type == gIOTerminatedNotification)) {

	LOCKREADNOTIFY();

        iter = OSCollectionIterator::withCollection( (OSOrderedSet *)
                    gNotifications->getObject( type ) );

        if( iter) {
            while( (notify = (_IOServiceNotifier *) iter->getNextObject())) {

                if( passiveMatch( notify->matching)
                  && (kIOServiceNotifyEnable & notify->state)) {
                    if( 0 == willSend)
                        willSend = OSArray::withCapacity(8);
                    if( willSend)
                        willSend->setObject( notify );
                }
            }
            iter->release();
        }

        __state[0] = (__state[0] | orNewState) & andNewState;

        UNLOCKNOTIFY();
    }

    if( willSend) {
        for( unsigned int idx = 0;
             (notify = (_IOServiceNotifier *) willSend->getObject(idx));
             idx++) {
            invokeNotifer( notify );
        }
        willSend->release();
    }
    unlockForArbitration();
}

IOOptionBits IOService::getState( void ) const
{
    return( __state[0] );
}

/*
 * Helpers to make matching objects for simple cases
 */

OSDictionary * IOService::serviceMatching( const OSString * name,
			OSDictionary * table )
{
    if( !table)
	table = OSDictionary::withCapacity( 2 );
    if( table)
        table->setObject(gIOProviderClassKey, (OSObject *)name );

    return( table );
}

OSDictionary * IOService::serviceMatching( const char * name,
			OSDictionary * table )
{
    const OSString *	str;

    str = OSSymbol::withCString( name );
    if( !str)
	return( 0 );

    table = serviceMatching( str, table );
    str->release();
    return( table );
}

OSDictionary * IOService::nameMatching( const OSString * name,
			OSDictionary * table )
{
    if( !table)
	table = OSDictionary::withCapacity( 2 );
    if( table)
        table->setObject( gIONameMatchKey, (OSObject *)name );

    return( table );
}

OSDictionary * IOService::nameMatching( const char * name,
			OSDictionary * table )
{
    const OSString *	str;

    str = OSSymbol::withCString( name );
    if( !str)
	return( 0 );

    table = nameMatching( str, table );
    str->release();
    return( table );
}

OSDictionary * IOService::resourceMatching( const OSString * str,
			OSDictionary * table )
{
    table = serviceMatching( gIOResourcesKey, table );
    if( table)
        table->setObject( gIOResourceMatchKey, (OSObject *) str );

    return( table );
}

OSDictionary * IOService::resourceMatching( const char * name,
			OSDictionary * table )
{
    const OSSymbol *	str;

    str = OSSymbol::withCString( name );
    if( !str)
	return( 0 );

    table = resourceMatching( str, table );
    str->release();

    return( table );
}

OSDictionary * IOService::propertyMatching( const OSSymbol * key, const OSObject * value,
			OSDictionary * table )
{
    OSDictionary * properties;

    properties = OSDictionary::withCapacity( 2 );
    if( !properties)
	return( 0 );
    properties->setObject( key, value );

    if( !table)
	table = OSDictionary::withCapacity( 2 );
    if( table)
        table->setObject( gIOPropertyMatchKey, properties );

    properties->release();

    return( table );
}

OSDictionary * IOService::registryEntryIDMatching( uint64_t entryID,
			OSDictionary * table )
{
    OSNumber *     num;

    num = OSNumber::withNumber( entryID, 64 );
    if( !num)
	return( 0 );

    if( !table)
	table = OSDictionary::withCapacity( 2 );
    if( table)
        table->setObject( gIORegistryEntryIDKey, num );
	
    if (num)
	num->release();

    return( table );
}


/*
 * _IOServiceNotifier
 */

// wait for all threads, other than the current one,
//  to exit the handler

void _IOServiceNotifier::wait()
{
    _IOServiceNotifierInvocation * next;
    bool doWait;

    do {
        doWait = false;
        queue_iterate( &handlerInvocations, next,
                        _IOServiceNotifierInvocation *, link) {
            if( next->thread != current_thread() ) {
                doWait = true;
                break;
            }
        }
        if( doWait) {
            state |= kIOServiceNotifyWaiter;
            SLEEPNOTIFY(this);
        }

    } while( doWait );
}

void _IOServiceNotifier::free()
{
    assert( queue_empty( &handlerInvocations ));
    OSObject::free();
}

void _IOServiceNotifier::remove()
{
    LOCKWRITENOTIFY();

    if( whence) {
        whence->removeObject( (OSObject *) this );
        whence = 0;
    }
    if( matching) {
        matching->release();
        matching = 0;
    }

    state &= ~kIOServiceNotifyEnable;

    wait();

    UNLOCKNOTIFY();
    
    release();
}

bool _IOServiceNotifier::disable()
{
    bool	ret;

    LOCKWRITENOTIFY();

    ret = (0 != (kIOServiceNotifyEnable & state));
    state &= ~kIOServiceNotifyEnable;
    if( ret)
        wait();

    UNLOCKNOTIFY();

    return( ret );
}

void _IOServiceNotifier::enable( bool was )
{
    LOCKWRITENOTIFY();
    if( was)
        state |= kIOServiceNotifyEnable;
    else
        state &= ~kIOServiceNotifyEnable;
    UNLOCKNOTIFY();
}

/*
 * IOResources
 */

IOService * IOResources::resources( void )
{
    IOResources *	inst;

    inst = new IOResources;
    if( inst && !inst->init()) {
	inst->release();
	inst = 0;
    }

    return( inst );
}

bool IOResources::init( OSDictionary * dictionary )
{
    // Do super init first
    if ( !super::init() )
        return false;

    // Allow PAL layer to publish a value
    const char *property_name;
    int property_value;

    pal_get_resource_property( &property_name, &property_value );

    if( property_name ) {
	OSNumber *num;
	const OSSymbol *	sym;

	if( (num = OSNumber::withNumber(property_value, 32)) != 0 ) {
	    if( (sym = OSSymbol::withCString( property_name)) != 0 ) {
		this->setProperty( sym, num );
		sym->release();
	    }
	    num->release();
	}
    }

    return true;
}

IOWorkLoop * IOResources::getWorkLoop() const
{
    // If we are the resource root
    // then use the platform's workloop
    if (this == (IOResources *) gIOResources)
	return getPlatform()->getWorkLoop();
    else
	return IOService::getWorkLoop();
}

bool IOResources::matchPropertyTable( OSDictionary * table )
{
    OSObject *		prop;
    OSString *		str;
    OSSet *		set;
    OSIterator *	iter;
    bool		ok = false;

    prop = table->getObject( gIOResourceMatchKey );
    str = OSDynamicCast( OSString, prop );
    if( str)
	ok = (0 != getProperty( str ));

    else if( (set = OSDynamicCast( OSSet, prop))) {

	iter = OSCollectionIterator::withCollection( set );
	ok = (iter != 0);
        while( ok && (str = OSDynamicCast( OSString, iter->getNextObject()) ))
            ok = (0 != getProperty( str ));

        if( iter)
	    iter->release();
    }

    return( ok );
}

void IOService::consoleLockTimer(thread_call_param_t p0, thread_call_param_t p1)
{
    IOService::updateConsoleUsers(NULL, 0);
}

void IOService::updateConsoleUsers(OSArray * consoleUsers, IOMessage systemMessage)
{
    IORegistryEntry * regEntry;
    OSObject *        locked = kOSBooleanFalse;
    uint32_t          idx;
    bool              publish;
    OSDictionary *    user;
    static IOMessage  sSystemPower;

    regEntry = IORegistryEntry::getRegistryRoot();

    IOLockLock(gIOConsoleUsersLock);

    if (systemMessage)
    {
        sSystemPower = systemMessage;
    }
    if (consoleUsers)
    {
        OSNumber * num = 0;
	for (idx = 0; 
	      (!num) && (user = OSDynamicCast(OSDictionary, consoleUsers->getObject(idx))); 
	      idx++)
	{
	    num = OSDynamicCast(OSNumber, user->getObject(gIOConsoleSessionScreenLockedTimeKey));
	}
        gIOConsoleLockTime = num ? num->unsigned32BitValue() : 0;
    }

    if (gIOConsoleLockTime)
    {
	if (kIOMessageSystemWillSleep == sSystemPower)
	    locked = kOSBooleanTrue;
	else
	{
	    clock_sec_t  now;
	    clock_usec_t microsecs;

	    clock_get_calendar_microtime(&now, &microsecs);
	    if (gIOConsoleLockTime > now)
	    {
		AbsoluteTime deadline;
		clock_interval_to_deadline(gIOConsoleLockTime - now, kSecondScale, &deadline);
		thread_call_enter_delayed(gIOConsoleLockCallout, deadline);
	    }
	    else
	    {
		locked = kOSBooleanTrue;
	    }
	}
    }

    publish = (consoleUsers || (locked != regEntry->getProperty(gIOConsoleLockedKey)));
    if (publish)
    {
	regEntry->setProperty(gIOConsoleLockedKey, locked);
	if (consoleUsers)
	{
	    regEntry->setProperty(gIOConsoleUsersKey, consoleUsers);
	}
	OSIncrementAtomic( &gIOConsoleUsersSeed );
    }

    IOLockUnlock(gIOConsoleUsersLock);

    if (publish)
    {
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

IOReturn IOResources::setProperties( OSObject * properties )
{
    IOReturn			err;
    const OSSymbol *		key;
    OSDictionary *		dict;
    OSCollectionIterator *	iter;

    err = IOUserClient::clientHasPrivilege(current_task(), kIOClientPrivilegeAdministrator);
    if ( kIOReturnSuccess != err)
	return( err );

    dict = OSDynamicCast(OSDictionary, properties);
    if( 0 == dict)
	return( kIOReturnBadArgument);

    iter = OSCollectionIterator::withCollection( dict);
    if( 0 == iter)
	return( kIOReturnBadArgument);

    while( (key = OSDynamicCast(OSSymbol, iter->getNextObject())))
    {
	if (gIOConsoleUsersKey == key) do
	{
	    OSArray * consoleUsers;
	    consoleUsers = OSDynamicCast(OSArray, dict->getObject(key));
	    if (!consoleUsers)
		continue;
	    IOService::updateConsoleUsers(consoleUsers, 0);
	}
	while (false);

	publishResource( key, dict->getObject(key) );
    }

    iter->release();

    return( kIOReturnSuccess );
}

/*
 * Helpers for matching dictionaries.
 * Keys existing in matching are checked in properties.
 * Keys may be a string or OSCollection of IOStrings
 */

bool IOService::compareProperty( OSDictionary * matching,
                                 const char * 	key )
{
    OSObject *	value;
    bool	ok;

    value = matching->getObject( key );
    if( value)
        ok = value->isEqualTo( getProperty( key ));
    else
	ok = true;

    return( ok );
}


bool IOService::compareProperty( OSDictionary *   matching,
                                 const OSString * key )
{
    OSObject *	value;
    bool	ok;

    value = matching->getObject( key );
    if( value)
        ok = value->isEqualTo( getProperty( key ));
    else
	ok = true;

    return( ok );
}

bool IOService::compareProperties( OSDictionary * matching,
                                   OSCollection * keys )
{
    OSCollectionIterator *	iter;
    const OSString *		key;
    bool			ok = true;

    if( !matching || !keys)
	return( false );

    iter = OSCollectionIterator::withCollection( keys );

    if( iter) {
	while( ok && (key = OSDynamicCast( OSString, iter->getNextObject())))
	    ok = compareProperty( matching, key );

	iter->release();
    }
    keys->release();	// !! consume a ref !!

    return( ok );
}

/* Helper to add a location matching dict to the table */

OSDictionary * IOService::addLocation( OSDictionary * table )
{
    OSDictionary * 	dict;

    if( !table)
	return( 0 );

    dict = OSDictionary::withCapacity( 1 );
    if( dict) {
        table->setObject( gIOLocationMatchKey, dict );
        dict->release(); 
    }

    return( dict );
}

/*
 * Go looking for a provider to match a location dict.
 */

IOService * IOService::matchLocation( IOService * /* client */ )
{
    IOService *	parent;

    parent = getProvider();

    if( parent)
        parent = parent->matchLocation( this );

    return( parent );
}

bool IOService::passiveMatch( OSDictionary * table, bool changesOK )
{
    IOService *		where;
    OSString *		matched;
    OSObject *		obj;
    OSString *		str;
    IORegistryEntry *	entry;
    OSNumber *		num;
    SInt32		score;
    OSNumber *		newPri;
    bool		match = true;
    bool		matchParent = false;
    UInt32		done;

    assert( table );

    where = this;

    do {
        do {
            done = 0;

            str = OSDynamicCast( OSString, table->getObject( gIOProviderClassKey));
            if( str) {
                done++;
                match = (0 != where->metaCast( str ));
                if( !match)
                    break;
            }

            obj = table->getObject( gIONameMatchKey );
            if( obj) {
                done++;
                match = where->compareNames( obj, changesOK ? &matched : 0 );
                if( !match)
                    break;
                if( changesOK && matched) {
                    // leave a hint as to which name matched
                    table->setObject( gIONameMatchedKey, matched );
                    matched->release();
                }
            }

            str = OSDynamicCast( OSString, table->getObject( gIOLocationMatchKey ));
            if( str) {

                const OSSymbol * sym;

                done++;
                match = false;
                sym = where->copyLocation();
                if( sym) {
                    match = sym->isEqualTo( str );
                    sym->release();
                }
                if( !match)
                    break;
            }

            obj = table->getObject( gIOPropertyMatchKey );
            if( obj) {

                OSDictionary * dict;
                OSDictionary * nextDict;
                OSIterator *   iter;

                done++;
                match = false;
                dict = where->dictionaryWithProperties();
                if( dict) {
                    nextDict = OSDynamicCast( OSDictionary, obj);
                    if( nextDict)
                        iter = 0;
                    else
                        iter = OSCollectionIterator::withCollection(
                                    OSDynamicCast(OSCollection, obj));

                    while( nextDict
                        || (iter && (0 != (nextDict = OSDynamicCast(OSDictionary,
                                                iter->getNextObject()))))) {
                        match = dict->isEqualTo( nextDict, nextDict);
                        if( match)
                            break;
                        nextDict = 0;
                    }
                    dict->release();
                    if( iter)
                        iter->release();
                }
                if( !match)
                    break;
            }

            str = OSDynamicCast( OSString, table->getObject( gIOPathMatchKey ));
            if( str) {
                done++;
                entry = IORegistryEntry::fromPath( str->getCStringNoCopy() );
                match = (where == entry);
                if( entry)
                    entry->release();
                if( !match)
                    break;
            }

            num = OSDynamicCast( OSNumber, table->getObject( gIORegistryEntryIDKey ));
            if( num) {
		done++;
                match = (getRegistryEntryID() == num->unsigned64BitValue());
	    }

            num = OSDynamicCast( OSNumber, table->getObject( gIOMatchedServiceCountKey ));
            if( num) {

                OSIterator *	iter;
                IOService *		service = 0;
                UInt32		serviceCount = 0;

                done++;
                iter = where->getClientIterator();
                if( iter) {
                    while( (service = (IOService *) iter->getNextObject())) {
                        if( kIOServiceInactiveState & service->__state[0])
                            continue;
                        if( 0 == service->getProperty( gIOMatchCategoryKey ))
                            continue;
                        ++serviceCount;
                    }
                    iter->release();
                }
                match = (serviceCount == num->unsigned32BitValue());
                if( !match)
                    break;
            }

            if( done == table->getCount()) {
                // don't call family if we've done all the entries in the table
                matchParent = false;
                break;
            }

            // pass in score from property table
            score = IOServiceObjectOrder( table, (void *) gIOProbeScoreKey);

            // do family specific matching
            match = where->matchPropertyTable( table, &score );

            if( !match) {
#if IOMATCHDEBUG
                if( kIOLogMatch & getDebugFlags( table ))
                    LOG("%s: family specific matching fails\n", where->getName());
#endif
                break;
            }

            if( changesOK) {
                // save the score
                newPri = OSNumber::withNumber( score, 32 );
                if( newPri) {
                    table->setObject( gIOProbeScoreKey, newPri );
                    newPri->release();
                }
            }

            if( !(match = where->compareProperty( table, kIOBSDNameKey )))
                break;
            if( !(match = where->compareProperty( table, kIOBSDMajorKey )))
                break;
            if( !(match = where->compareProperty( table, kIOBSDMinorKey )))
                break;
            if( !(match = where->compareProperty( table, kIOBSDUnitKey )))
                break;

            matchParent = false;

            obj = OSDynamicCast( OSDictionary,
                  table->getObject( gIOParentMatchKey ));
            if( obj) {
                match = false;
                matchParent = true;
                table = (OSDictionary *) obj;
                break;
            }

            table = OSDynamicCast( OSDictionary,
                    table->getObject( gIOLocationMatchKey ));
            if( table) {
                match = false;
                where = where->getProvider();
                if( where)
                    where = where->matchLocation( where );
            }

        } while( table && where );

    } while( matchParent && (where = where->getProvider()) );

    if( kIOLogMatch & gIOKitDebug)
        if( where && (where != this) )
            LOG("match parent @ %s = %d\n",
                        where->getName(), match );

    return( match );
}


IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type,  OSDictionary * properties,
                                    IOUserClient ** handler )
{
    const OSSymbol *userClientClass = 0;
    IOUserClient *client;
    OSObject *temp;

    if (kIOReturnSuccess == newUserClient( owningTask, securityID, type, handler ))
	return kIOReturnSuccess;

    // First try my own properties for a user client class name
    temp = getProperty(gIOUserClientClassKey);
    if (temp) {
	if (OSDynamicCast(OSSymbol, temp))
	    userClientClass = (const OSSymbol *) temp;
	else if (OSDynamicCast(OSString, temp)) {
	    userClientClass = OSSymbol::withString((OSString *) temp);
	    if (userClientClass)
		setProperty(kIOUserClientClassKey,
			    (OSObject *) userClientClass);
	}
    }

    // Didn't find one so lets just bomb out now without further ado.
    if (!userClientClass)
        return kIOReturnUnsupported;

    // This reference is consumed by the IOServiceOpen call
    temp = OSMetaClass::allocClassWithName(userClientClass);
    if (!temp)
        return kIOReturnNoMemory;

    if (OSDynamicCast(IOUserClient, temp))
        client = (IOUserClient *) temp;
    else {
        temp->release();
        return kIOReturnUnsupported;
    }

    if ( !client->initWithTask(owningTask, securityID, type, properties) ) {
        client->release();
        return kIOReturnBadArgument;
    }

    if ( !client->attach(this) ) {
        client->release();
        return kIOReturnUnsupported;
    }

    if ( !client->start(this) ) {
        client->detach(this);
        client->release();
        return kIOReturnUnsupported;
    }

    *handler = client;
    return kIOReturnSuccess;
}

IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type, IOUserClient ** handler )
{
    return( kIOReturnUnsupported );
}

IOReturn IOService::requestProbe( IOOptionBits options )
{
    return( kIOReturnUnsupported);
}

/*
 * Convert an IOReturn to text. Subclasses which add additional
 * IOReturn's should override this method and call 
 * super::stringFromReturn if the desired value is not found.
 */

const char * IOService::stringFromReturn( IOReturn rtn )
{
    static const IONamedValue IOReturn_values[] = { 
        {kIOReturnSuccess,          "success"                           },
        {kIOReturnError,            "general error"                     },
        {kIOReturnNoMemory,         "memory allocation error"           },
        {kIOReturnNoResources,      "resource shortage"                 },
        {kIOReturnIPCError,         "Mach IPC failure"                  },
        {kIOReturnNoDevice,         "no such device"                    },
        {kIOReturnNotPrivileged,    "privilege violation"               },
        {kIOReturnBadArgument,      "invalid argument"                  },
        {kIOReturnLockedRead,       "device is read locked"             },
        {kIOReturnLockedWrite,      "device is write locked"            },
        {kIOReturnExclusiveAccess,  "device is exclusive access"        },
        {kIOReturnBadMessageID,     "bad IPC message ID"                },
        {kIOReturnUnsupported,      "unsupported function"              },
        {kIOReturnVMError,          "virtual memory error"              },
        {kIOReturnInternalError,    "internal driver error"             },
        {kIOReturnIOError,          "I/O error"                         },
        {kIOReturnCannotLock,       "cannot acquire lock"               },
        {kIOReturnNotOpen,          "device is not open"                },
        {kIOReturnNotReadable,      "device is not readable"            },
        {kIOReturnNotWritable,      "device is not writeable"           },
        {kIOReturnNotAligned,       "alignment error"                   },
        {kIOReturnBadMedia,         "media error"                       },
        {kIOReturnStillOpen,        "device is still open"              },
        {kIOReturnRLDError,         "rld failure"                       },
        {kIOReturnDMAError,         "DMA failure"                       },
        {kIOReturnBusy,             "device is busy"                    },
        {kIOReturnTimeout,          "I/O timeout"                       },
        {kIOReturnOffline,          "device is offline"                 },
        {kIOReturnNotReady,         "device is not ready"               },
        {kIOReturnNotAttached,      "device/channel is not attached"    },
        {kIOReturnNoChannels,       "no DMA channels available"         },
        {kIOReturnNoSpace,          "no space for data"                 },
        {kIOReturnPortExists,       "device port already exists"        },
        {kIOReturnCannotWire,       "cannot wire physical memory"       },
        {kIOReturnNoInterrupt,      "no interrupt attached"             },
        {kIOReturnNoFrames,         "no DMA frames enqueued"            },
        {kIOReturnMessageTooLarge,  "message is too large"              },
        {kIOReturnNotPermitted,     "operation is not permitted"        },
        {kIOReturnNoPower,          "device is without power"           },
        {kIOReturnNoMedia,          "media is not present"              },
        {kIOReturnUnformattedMedia, "media is not formatted"            },
        {kIOReturnUnsupportedMode,  "unsupported mode"                  },
        {kIOReturnUnderrun,         "data underrun"                     },
        {kIOReturnOverrun,          "data overrun"                      },
        {kIOReturnDeviceError,      "device error"                      },
        {kIOReturnNoCompletion,     "no completion routine"             },
        {kIOReturnAborted,          "operation was aborted"             },
        {kIOReturnNoBandwidth,      "bus bandwidth would be exceeded"   },
        {kIOReturnNotResponding,    "device is not responding"          },
        {kIOReturnInvalid,          "unanticipated driver error"        },
        {0,                         NULL                                }
    };

    return IOFindNameForValue(rtn, IOReturn_values);
}

/*
 * Convert an IOReturn to an errno.
 */
int IOService::errnoFromReturn( IOReturn rtn )
{
    switch(rtn) {
        // (obvious match)
        case kIOReturnSuccess:
            return(0);
        case kIOReturnNoMemory:
            return(ENOMEM);
        case kIOReturnNoDevice:
            return(ENXIO);
        case kIOReturnVMError:
            return(EFAULT);
        case kIOReturnNotPermitted:
            return(EPERM);
        case kIOReturnNotPrivileged:
            return(EACCES);
        case kIOReturnIOError:
            return(EIO);
        case kIOReturnNotWritable:
            return(EROFS);
        case kIOReturnBadArgument:
            return(EINVAL);
        case kIOReturnUnsupported:
            return(ENOTSUP);
        case kIOReturnBusy:
            return(EBUSY);
        case kIOReturnNoPower:
            return(EPWROFF);
        case kIOReturnDeviceError:
            return(EDEVERR);
        case kIOReturnTimeout: 
            return(ETIMEDOUT);
        case kIOReturnMessageTooLarge:
            return(EMSGSIZE);
        case kIOReturnNoSpace:
            return(ENOSPC);
        case kIOReturnCannotLock:
            return(ENOLCK);

        // (best match)
        case kIOReturnBadMessageID:
        case kIOReturnNoCompletion:
        case kIOReturnNotAligned:
            return(EINVAL);
        case kIOReturnNotReady:
            return(EBUSY);
        case kIOReturnRLDError:
            return(EBADMACHO);
        case kIOReturnPortExists:
        case kIOReturnStillOpen:
            return(EEXIST);
        case kIOReturnExclusiveAccess:
        case kIOReturnLockedRead:
        case kIOReturnLockedWrite:
        case kIOReturnNotOpen:
        case kIOReturnNotReadable:
            return(EACCES);
        case kIOReturnCannotWire:
        case kIOReturnNoResources:
            return(ENOMEM);
        case kIOReturnAborted:
        case kIOReturnOffline:
        case kIOReturnNotResponding:
            return(EBUSY);
        case kIOReturnBadMedia:
        case kIOReturnNoMedia:
        case kIOReturnNotAttached:
        case kIOReturnUnformattedMedia:
            return(ENXIO); // (media error)
        case kIOReturnDMAError:
        case kIOReturnOverrun:
        case kIOReturnUnderrun:
            return(EIO); // (transfer error)
        case kIOReturnNoBandwidth:
        case kIOReturnNoChannels:
        case kIOReturnNoFrames:
        case kIOReturnNoInterrupt:
            return(EIO); // (hardware error)
        case kIOReturnError:
        case kIOReturnInternalError:
        case kIOReturnInvalid:
            return(EIO); // (generic error)
        case kIOReturnIPCError:
            return(EIO); // (ipc error)
        default:
            return(EIO); // (all other errors)
    }
}

IOReturn IOService::message( UInt32 type, IOService * provider,
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

IOItemCount IOService::getDeviceMemoryCount( void )
{
    OSArray *		array;
    IOItemCount		count;

    array = OSDynamicCast( OSArray, getProperty( gIODeviceMemoryKey));
    if( array)
	count = array->getCount();
    else
	count = 0;

    return( count);
}

IODeviceMemory * IOService::getDeviceMemoryWithIndex( unsigned int index )
{
    OSArray *		array;
    IODeviceMemory *	range;

    array = OSDynamicCast( OSArray, getProperty( gIODeviceMemoryKey));
    if( array)
	range = (IODeviceMemory *) array->getObject( index );
    else
	range = 0;

    return( range);
}

IOMemoryMap * IOService::mapDeviceMemoryWithIndex( unsigned int index,
						IOOptionBits options )
{
    IODeviceMemory *	range;
    IOMemoryMap *	map;

    range = getDeviceMemoryWithIndex( index );
    if( range)
	map = range->map( options );
    else
	map = 0;

    return( map );
}

OSArray * IOService::getDeviceMemory( void )
{
    return( OSDynamicCast( OSArray, getProperty( gIODeviceMemoryKey)));
}


void IOService::setDeviceMemory( OSArray * array )
{
    setProperty( gIODeviceMemoryKey, array);
}

/*
 * For machines where the transfers on an I/O bus can stall because
 * the CPU is in an idle mode, These APIs allow a driver to specify
 * the maximum bus stall that they can handle.  0 indicates no limit.
 */
void IOService::
setCPUSnoopDelay(UInt32 __unused ns)
{
#if defined(__i386__) || defined(__x86_64__)
    ml_set_maxsnoop(ns); 
#endif /* defined(__i386__) || defined(__x86_64__) */
}

UInt32 IOService::
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
    static const UInt kNoReplace = -1U;	// Must be an illegal index
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
            if ((service == thisService) && sameType)
                replace = i;
            else if (!thisService) {
                if (kNoReplace == replace)
                    replace = i;
            }
            else if (sameType) {
                const UInt32 thisMax = entries[i].fMaxDelay;
                if (thisMax < ns)
		{
                    ns = thisMax;
		    holder = thisService;
		}
            }
        }
        
        setCpuDelay = true;
        if (kNoReplace == replace)
            sCpuDelayData->appendBytes(&ne, sizeof(ne));
        else
            entries[replace] = ne;
    }
    else {
        ns = -1U;	// Set to max unsigned, i.e. no restriction

        for (UInt i = 0; i < count; i++) {
            // Clear a maximum delay.
            IOService *thisService = entries[i].fService;
            if (thisService && (delayType == entries[i].fDelayType)) {
                UInt32 thisMax = entries[i].fMaxDelay;
                if (service == thisService)
                    replace = i;
                else if (thisMax < ns) {
                    ns = thisMax;
		    holder = thisService;
		}
            }
        }

        // Check if entry found
        if (kNoReplace != replace) {
            entries[replace].fService = 0;	// Null the entry
            setCpuDelay = true;
        }
    }

    if (setCpuDelay)
    {
        // Must be safe to call from locked context
        if (delayType == kCpuDelayBusStall)
        {
            ml_set_maxbusdelay(ns);
        }
        else if (delayType == kCpuDelayInterrupt)
        {
            ml_set_maxintdelay(ns);
        }

	OSArray * handlers = sCpuLatencyHandlers[delayType];
	IOService * target;
	if (handlers) for (unsigned int idx = 0; 
			    (target = (IOService *) handlers->getObject(idx));
			    idx++)
	{
	    target->callPlatformFunction(sCPULatencyFunctionName[delayType], false,
					    (void *) (uintptr_t) ns, holder,
					    NULL, NULL);
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

    do
    {
	if (enable && !sCpuLatencyHandlers[delayType])
	    sCpuLatencyHandlers[delayType] = OSArray::withCapacity(4);
	array = sCpuLatencyHandlers[delayType];
	if (!array)
	    break;
	idx = array->getNextIndexOfObject(target, 0);
	if (!enable)
	{
	    if (-1U != idx)
	    {
		array->removeObject(idx);
		result = kIOReturnSuccess;
	    }
	}
	else
	{
	    if (-1U != idx) {
		result = kIOReturnExclusiveAccess;
		break;
	    }
	    array->setObject(target);
	    
	    UInt count = sCpuDelayData->getLength() / sizeof(CpuDelayEntry);
	    CpuDelayEntry *entries = (CpuDelayEntry *) sCpuDelayData->getBytesNoCopy();
	    UInt32 ns = -1U;	// Set to max unsigned, i.e. no restriction
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
    }
    while (false);

    IORecursiveLockUnlock(sCpuDelayLock);

    return (result);
}

#endif /* defined(__i386__) || defined(__x86_64__) */

void IOService::
requireMaxBusStall(UInt32 __unused ns)
{
#if defined(__i386__) || defined(__x86_64__)
    requireMaxCpuDelay(this, ns, kCpuDelayBusStall);
#endif
}

void IOService::
requireMaxInterruptDelay(uint32_t __unused ns)
{
#if defined(__i386__) || defined(__x86_64__)
    requireMaxCpuDelay(this, ns, kCpuDelayInterrupt);
#endif
}

/*
 * Device interrupts
 */

IOReturn IOService::resolveInterrupt(IOService *nub, int source)
{
  IOInterruptController *interruptController;
  OSArray               *array;
  OSData                *data;
  OSSymbol              *interruptControllerName;
  long                  numSources;
  IOInterruptSource     *interruptSources;
  
  // Get the parents list from the nub.
  array = OSDynamicCast(OSArray, nub->getProperty(gIOInterruptControllersKey));
  if (array == 0) return kIOReturnNoResources;
  
  // Allocate space for the IOInterruptSources if needed... then return early.
  if (nub->_interruptSources == 0) {
    numSources = array->getCount();
    interruptSources = (IOInterruptSource *)IOMalloc(numSources * sizeof(IOInterruptSource));
    if (interruptSources == 0) return kIOReturnNoMemory;
    
    bzero(interruptSources, numSources * sizeof(IOInterruptSource));
    
    nub->_numInterruptSources = numSources;
    nub->_interruptSources = interruptSources;
    return kIOReturnSuccess;
  }
  
  interruptControllerName = OSDynamicCast(OSSymbol,array->getObject(source));
  if (interruptControllerName == 0) return kIOReturnNoResources;
  
  interruptController = getPlatform()->lookUpInterruptController(interruptControllerName);
  if (interruptController == 0) return kIOReturnNoResources;
  
  // Get the interrupt numbers from the nub.
  array = OSDynamicCast(OSArray, nub->getProperty(gIOInterruptSpecifiersKey));
  if (array == 0) return kIOReturnNoResources;
  data = OSDynamicCast(OSData, array->getObject(source));
  if (data == 0) return kIOReturnNoResources;
  
  // Set the interruptController and interruptSource in the nub's table.
  interruptSources = nub->_interruptSources;
  interruptSources[source].interruptController = interruptController;
  interruptSources[source].vectorData = data;
  
  return kIOReturnSuccess;
}

IOReturn IOService::lookupInterrupt(int source, bool resolve, IOInterruptController **interruptController)
{
  IOReturn ret;
  
  /* Make sure the _interruptSources are set */
  if (_interruptSources == 0) {
    ret = resolveInterrupt(this, source);
    if (ret != kIOReturnSuccess) return ret;
  }
  
  /* Make sure the local source number is valid */
  if ((source < 0) || (source >= _numInterruptSources))
    return kIOReturnNoInterrupt;
  
  /* Look up the contoller for the local source */
  *interruptController = _interruptSources[source].interruptController;
  
  if (*interruptController == NULL) {
    if (!resolve) return kIOReturnNoInterrupt;
    
    /* Try to reslove the interrupt */
    ret = resolveInterrupt(this, source);
    if (ret != kIOReturnSuccess) return ret;    
    
    *interruptController = _interruptSources[source].interruptController;
  }
  
  return kIOReturnSuccess;
}

IOReturn IOService::registerInterrupt(int source, OSObject *target,
				      IOInterruptAction handler,
				      void *refCon)
{
  IOInterruptController *interruptController;
  IOReturn              ret;
  
  ret = lookupInterrupt(source, true, &interruptController);
  if (ret != kIOReturnSuccess) return ret;
  
  /* Register the source */
  return interruptController->registerInterrupt(this, source, target,
						(IOInterruptHandler)handler,
						refCon);
}

IOReturn IOService::unregisterInterrupt(int source)
{
  IOInterruptController *interruptController;
  IOReturn              ret;
  
  ret = lookupInterrupt(source, false, &interruptController);
  if (ret != kIOReturnSuccess) return ret;
  
  /* Unregister the source */
  return interruptController->unregisterInterrupt(this, source);
}

IOReturn IOService::getInterruptType(int source, int *interruptType)
{
  IOInterruptController *interruptController;
  IOReturn              ret;
  
  ret = lookupInterrupt(source, true, &interruptController);
  if (ret != kIOReturnSuccess) return ret;
    
  /* Return the type */
  return interruptController->getInterruptType(this, source, interruptType);
}

IOReturn IOService::enableInterrupt(int source)
{
  IOInterruptController *interruptController;
  IOReturn              ret;
  
  ret = lookupInterrupt(source, false, &interruptController);
  if (ret != kIOReturnSuccess) return ret;
  
  /* Enable the source */
  return interruptController->enableInterrupt(this, source);
}

IOReturn IOService::disableInterrupt(int source)
{
  IOInterruptController *interruptController;
  IOReturn              ret;
  
  ret = lookupInterrupt(source, false, &interruptController);
  if (ret != kIOReturnSuccess) return ret;
  
  /* Disable the source */
  return interruptController->disableInterrupt(this, source);
}

IOReturn IOService::causeInterrupt(int source)
{
  IOInterruptController *interruptController;
  IOReturn              ret;
  
  ret = lookupInterrupt(source, false, &interruptController);
  if (ret != kIOReturnSuccess) return ret;
  
  /* Cause an interrupt for the source */
  return interruptController->causeInterrupt(this, source);
}

#if __LP64__
OSMetaClassDefineReservedUnused(IOService, 0);
OSMetaClassDefineReservedUnused(IOService, 1);
OSMetaClassDefineReservedUnused(IOService, 2);
OSMetaClassDefineReservedUnused(IOService, 3);
OSMetaClassDefineReservedUnused(IOService, 4);
OSMetaClassDefineReservedUnused(IOService, 5);
#else
OSMetaClassDefineReservedUsed(IOService, 0);
OSMetaClassDefineReservedUsed(IOService, 1);
OSMetaClassDefineReservedUsed(IOService, 2);
OSMetaClassDefineReservedUsed(IOService, 3);
OSMetaClassDefineReservedUsed(IOService, 4);
OSMetaClassDefineReservedUsed(IOService, 5);
#endif
OSMetaClassDefineReservedUnused(IOService, 6);
OSMetaClassDefineReservedUnused(IOService, 7);
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
