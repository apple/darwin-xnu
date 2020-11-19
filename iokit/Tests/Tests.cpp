/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 *
 */

#define TEST_HEADERS    0

#if TEST_HEADERS

#include <libkern/OSByteOrder.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSAllocation.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSBoundedArray.h>
#include <libkern/c++/OSBoundedArrayRef.h>
#include <libkern/c++/OSBoundedPtr.h>
#include <libkern/c++/OSCollection.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSCPPDebug.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSEndianTypes.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSOrderedSet.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSSet.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/crypto/aes.h>
#include <libkern/crypto/aesxts.h>
#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/des.h>
#include <libkern/crypto/md5.h>
#include <libkern/crypto/register_crypto.h>
#include <libkern/crypto/sha1.h>
#include <libkern/crypto/sha2.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/kext_request_keys.h>
#include <libkern/kxld.h>
#include <libkern/kxld_types.h>
#include <libkern/locks.h>
#include <libkern/mkext.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSBase.h>
#include <libkern/OSDebug.h>
#include <libkern/OSKextLib.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/OSReturn.h>
#include <libkern/OSSerializeBinary.h>
#include <libkern/OSTypes.h>
#include <libkern/prelink.h>
#include <libkern/stack_protector.h>
#include <libkern/sysctl.h>
#include <libkern/tree.h>
#include <libkern/zconf.h>
#include <libkern/zlib.h>

#include <IOKit/AppleKeyStoreInterface.h>
#include <IOKit/assert.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOCommand.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOCommandPool.h>
#include <IOKit/IOCommandQueue.h>
#include <IOKit/IOConditionLock.h>
#include <IOKit/IOCPU.h>
//#include <IOKit/IODataQueue.h>
#include <IOKit/IODataQueueShared.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IODMAController.h>
#include <IOKit/IODMAEventSource.h>
#include <IOKit/IOEventSource.h>
#include <IOKit/IOFilterInterruptEventSource.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOInterleavedMemoryDescriptor.h>
#include <IOKit/IOInterruptAccounting.h>
#include <IOKit/IOInterruptAccountingPrivate.h>
#include <IOKit/IOInterruptController.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOInterrupts.h>
#include <IOKit/IOKernelReporters.h>
#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOKitDiagnosticsUserClient.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOKitServer.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOLocksPrivate.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOMemoryCursor.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOMultiMemoryDescriptor.h>
#include <IOKit/IONotifier.h>
#include <IOKit/IONVRAM.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IORangeAllocator.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOReportMacros.h>
#include <IOKit/IOReportTypes.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOServicePM.h>
#include <IOKit/IOSharedDataQueue.h>
#include <IOKit/IOSharedLock.h>
#include <IOKit/IOStatistics.h>
#include <IOKit/IOStatisticsPrivate.h>
#include <IOKit/IOSubMemoryDescriptor.h>
#include <IOKit/IOSyncer.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/nvram/IONVRAMController.h>
#include <IOKit/OSMessageNotification.h>
#include <IOKit/platform/AppleMacIO.h>
#include <IOKit/platform/AppleMacIODevice.h>
#include <IOKit/platform/AppleNMI.h>
#include <IOKit/platform/ApplePlatformExpert.h>
#include <IOKit/power/IOPwrController.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMinformee.h>
#include <IOKit/pwr_mgt/IOPMinformeeList.h>
#include <IOKit/pwr_mgt/IOPMLibDefs.h>
#include <IOKit/pwr_mgt/IOPMlog.h>
#include <IOKit/pwr_mgt/IOPMPowerSource.h>
#include <IOKit/pwr_mgt/IOPMPowerSourceList.h>
#include <IOKit/pwr_mgt/IOPMpowerState.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/pwr_mgt/IOPowerConnection.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/rtc/IORTCController.h>
#include <IOKit/system.h>
#include <IOKit/system_management/IOWatchDogTimer.h>

#endif /* TEST_HEADERS */

#include <sys/sysctl.h>
#include <libkern/c++/OSData.h>
#include "Tests.h"


#if DEVELOPMENT || DEBUG

#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOSharedDataQueue.h>
#include <IOKit/IODataQueueShared.h>
#include <libkern/Block.h>
#include <libkern/Block_private.h>
#include <libkern/c++/OSAllocation.h>
#include <libkern/c++/OSBoundedArray.h>
#include <libkern/c++/OSBoundedArrayRef.h>
#include <libkern/c++/OSBoundedPtr.h>
#include <libkern/c++/OSSharedPtr.h>
#include <os/cpp_util.h>

static uint64_t gIOWorkLoopTestDeadline;

static void
TESAction(OSObject * owner, IOTimerEventSource * tes)
{
	if (mach_absolute_time() < gIOWorkLoopTestDeadline) {
		tes->setTimeout(1, kMicrosecondScale);
	}
}

static int
IOWorkLoopTest(int newValue)
{
	IOReturn err;
	uint32_t idx;
	IOWorkLoop * wl;
	IOTimerEventSource * tes;
	IOInterruptEventSource * ies;

	wl = IOWorkLoop::workLoop();
	assert(wl);
	tes = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsPriorityWorkLoop, wl, &TESAction);
	assert(tes);
	err = wl->addEventSource(tes);
	assert(kIOReturnSuccess == err);
	clock_interval_to_deadline(100, kMillisecondScale, &gIOWorkLoopTestDeadline);
	for (idx = 0; mach_absolute_time() < gIOWorkLoopTestDeadline; idx++) {
		tes->setTimeout(idx & 1023, kNanosecondScale);
	}
	tes->cancelTimeout();
	wl->removeEventSource(tes);
	tes->release();

	int value = 3;

	tes = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsDefault, wl, ^(IOTimerEventSource * tes){
		kprintf("wl %p, value %d\n", wl, value);
	});
	err = wl->addEventSource(tes);
	assert(kIOReturnSuccess == err);

	value = 2;
	tes->setTimeout(1, kNanosecondScale);
	IOSleep(1);
	wl->removeEventSource(tes);
	tes->release();

	ies = IOInterruptEventSource::interruptEventSource(wl, NULL, 0, ^void (IOInterruptEventSource *sender, int count){
		kprintf("ies block %p, %d\n", sender, count);
	});

	assert(ies);
	kprintf("ies %p\n", ies);
	err = wl->addEventSource(ies);
	assert(kIOReturnSuccess == err);
	ies->interruptOccurred(NULL, NULL, 0);
	IOSleep(1);
	ies->interruptOccurred(NULL, NULL, 0);
	IOSleep(1);
	wl->removeEventSource(ies);
	ies->release();

	wl->release();

	return 0;
}

static int
OSCollectionTest(int newValue)
{
	OSArray * array = OSArray::withCapacity(8);
	array->setObject(kOSBooleanTrue);
	array->setObject(kOSBooleanFalse);
	array->setObject(kOSBooleanFalse);
	array->setObject(kOSBooleanTrue);
	array->setObject(kOSBooleanFalse);
	array->setObject(kOSBooleanTrue);

	__block unsigned int index;
	index = 0;
	array->iterateObjects(^bool (OSObject * obj) {
		kprintf("%d:%d ", index, (obj == kOSBooleanTrue) ? 1 : (obj == kOSBooleanFalse) ? 0 : 2);
		index++;
		return false;
	});
	kprintf("\n");
	array->release();

	OSDictionary * dict = IOService::resourceMatching("hello");
	assert(dict);
	index = 0;
	dict->iterateObjects(^bool (const OSSymbol * sym, OSObject * obj) {
		OSString * str = OSDynamicCast(OSString, obj);
		assert(str);
		kprintf("%d:%s=%s\n", index, sym->getCStringNoCopy(), str->getCStringNoCopy());
		index++;
		return false;
	});
	dict->release();

	OSSerializer * serializer = OSSerializer::withBlock(^bool (OSSerialize * s){
		return gIOBSDUnitKey->serialize(s);
	});
	assert(serializer);
	IOService::getPlatform()->setProperty("OSSerializer_withBlock", serializer);
	serializer->release();

	return 0;
}

static int
OSAllocationTests(int)
{
	OSAllocation<int> ints(100, OSAllocateMemory);
	assert(ints);

	{
		int counter = 0;
		for (int& i : ints) {
			i = counter++;
		}
	}

	{
		int counter = 0;
		for (int& i : ints) {
			assert(i == counter);
			++counter;
		}
	}

	// Make sure we can have two-level OSAllocations
	{
		OSAllocation<OSAllocation<int> > testArray(10, OSAllocateMemory);
		for (int i = 0; i < 10; i++) {
			testArray[i] = OSAllocation<int>(10, OSAllocateMemory);
			for (int j = 0; j < 10; ++j) {
				testArray[i][j] = i + j;
			}
		}

		for (int i = 0; i < 10; i++) {
			for (int j = 0; j < 10; ++j) {
				assert(testArray[i][j] == i + j);
			}
		}
	}

	return 0;
}

static int
OSBoundedArrayTests(int)
{
	OSBoundedArray<int, 5> ints = {0, 1, 2, 3, 4};
	assert(ints.size() == 5);

	{
		int counter = 0;
		for (int& i : ints) {
			i = counter++;
		}
	}

	{
		int counter = 0;
		for (int& i : ints) {
			assert(i == counter);
			++counter;
		}
	}

	return 0;
}

static int
OSBoundedArrayRefTests(int)
{
	OSBoundedArray<int, 5> storage = {0, 1, 2, 3, 4};
	OSBoundedArrayRef<int> ints(storage);
	assert(ints);

	{
		int counter = 0;
		for (int& i : ints) {
			i = counter++;
		}
	}

	{
		int counter = 0;
		for (int& i : ints) {
			assert(i == counter);
			++counter;
		}
	}

	return 0;
}

static int
OSBoundedPtrTests(int)
{
	int array[5] = {55, 66, 77, 88, 99};
	OSBoundedPtr<int> begin(&array[0], &array[0], &array[5]);
	OSBoundedPtr<int> end(&array[5], &array[0], &array[5]);

	{
		int counter = 0;
		for (OSBoundedPtr<int> b = begin; b != end; ++b) {
			*b = counter++;
		}
	}

	{
		int counter = 0;
		for (OSBoundedPtr<int> b = begin; b != end; ++b) {
			assert(*b == counter);
			++counter;
		}
	}

	return 0;
}

static int
IOSharedDataQueue_44636964(__unused int newValue)
{
	IOSharedDataQueue* sd = IOSharedDataQueue::withCapacity(DATA_QUEUE_ENTRY_HEADER_SIZE + sizeof(UInt64));
	UInt64 data = 0x11223344aa55aa55;
	UInt32 data2 = 0x44332211;
	UInt32 size = sizeof(UInt32);
	/* enqueue moves tail to end */
	sd->enqueue(&data, sizeof(UInt64));
	/* dequeue moves head to end */
	sd->dequeue(&data, &size);
	/* Tail wraps around, head is still at end */
	sd->enqueue(&data2, sizeof(UInt32));
	/* something in the queue so peek() should return non-null */
	assert(sd->peek() != NULL);
	return KERN_SUCCESS;
}

#if 0
#include <IOKit/IOUserClient.h>
class TestUserClient : public IOUserClient
{
	OSDeclareDefaultStructors(TestUserClient);
	virtual void stop( IOService *provider) APPLE_KEXT_OVERRIDE;
	virtual bool finalize(IOOptionBits options) APPLE_KEXT_OVERRIDE;
	virtual IOReturn externalMethod( uint32_t selector,
	    IOExternalMethodArguments * arguments,
	    IOExternalMethodDispatch * dispatch,
	    OSObject * target,
	    void * reference ) APPLE_KEXT_OVERRIDE;
};

void
TestUserClient::stop( IOService *provider)
{
	kprintf("TestUserClient::stop\n");
}
bool
TestUserClient::finalize(IOOptionBits options)
{
	kprintf("TestUserClient::finalize\n");
	return true;
}
IOReturn
TestUserClient::externalMethod( uint32_t selector,
    IOExternalMethodArguments * arguments,
    IOExternalMethodDispatch * dispatch,
    OSObject * target,
    void * reference )
{
	getProvider()->terminate();
	IOSleep(500);
	return 0;
}
OSDefineMetaClassAndStructors(TestUserClient, IOUserClient);
#endif

static int
IOServiceTest(int newValue)
{
	OSDictionary      * matching;
	IONotifier        * note;
	__block IOService * found;

#if 0
	found = new IOService;
	found->init();
	found->setName("IOTestUserClientProvider");
	found->attach(IOService::getPlatform());
	found->setProperty("IOUserClientClass", "TestUserClient");
	found->registerService();
#endif

	matching = IOService::serviceMatching("IOPlatformExpert");
	assert(matching);
	found = nullptr;
	note = IOService::addMatchingNotification(gIOMatchedNotification, matching, 0,
	    ^bool (IOService * newService, IONotifier * notifier) {
		kprintf("found %s, %d\n", newService->getName(), newService->getRetainCount());
		found = newService;
		found->retain();
		return true;
	}
	    );
	assert(note);
	assert(found);
	matching->release();
	note->remove();

	note = found->registerInterest(gIOBusyInterest,
	    ^IOReturn (uint32_t messageType, IOService * provider,
	    void   * messageArgument, size_t argSize) {
		kprintf("%p messageType 0x%08x %p\n", provider, messageType, messageArgument);
		return kIOReturnSuccess;
	});
	assert(note);
	IOSleep(1 * 1000);
	note->remove();
	found->release();

	return 0;
}

static void
OSStaticPtrCastTests()
{
	// const& overload
	{
		OSSharedPtr<OSDictionary> const dict = OSMakeShared<OSDictionary>();
		OSSharedPtr<OSCollection> collection = OSStaticPtrCast<OSCollection>(dict);
		assert(collection == dict);
	}
	{
		OSSharedPtr<OSDictionary> const dict = nullptr;
		OSSharedPtr<OSCollection> collection = OSStaticPtrCast<OSCollection>(dict);
		assert(collection == nullptr);
	}
	// && overload
	{
		OSSharedPtr<OSDictionary> dict = OSMakeShared<OSDictionary>();
		OSDictionary* oldDict = dict.get();
		OSSharedPtr<OSCollection> collection = OSStaticPtrCast<OSCollection>(os::move(dict));
		assert(collection.get() == oldDict);
		assert(dict == nullptr);
	}
	{
		OSSharedPtr<OSDictionary> dict = nullptr;
		OSSharedPtr<OSCollection> collection = OSStaticPtrCast<OSCollection>(os::move(dict));
		assert(collection == nullptr);
		assert(dict == nullptr);
	}
}

static void
OSConstPtrCastTests()
{
	// const& overload
	{
		OSSharedPtr<OSDictionary const> const dict = OSMakeShared<OSDictionary>();
		OSSharedPtr<OSDictionary> dict2 = OSConstPtrCast<OSDictionary>(dict);
		assert(dict2 == dict);
	}
	{
		OSSharedPtr<OSDictionary const> const dict = OSMakeShared<OSDictionary>();
		OSSharedPtr<OSDictionary const> dict2 = OSConstPtrCast<OSDictionary const>(dict);
		assert(dict2 == dict);
	}
	{
		OSSharedPtr<OSDictionary const> const dict = nullptr;
		OSSharedPtr<OSDictionary> dict2 = OSConstPtrCast<OSDictionary>(dict);
		assert(dict2 == nullptr);
	}
	{
		OSSharedPtr<OSDictionary const> const dict = nullptr;
		OSSharedPtr<OSDictionary const> dict2 = OSConstPtrCast<OSDictionary const>(dict);
		assert(dict2 == nullptr);
	}

	// && overload
	{
		OSSharedPtr<OSDictionary const> dict = OSMakeShared<OSDictionary>();
		OSDictionary const* oldDict = dict.get();
		OSSharedPtr<OSDictionary> dict2 = OSConstPtrCast<OSDictionary>(os::move(dict));
		assert(dict == nullptr);
		assert(dict2 == oldDict);
	}
	{
		OSSharedPtr<OSDictionary const> dict = nullptr;
		OSSharedPtr<OSDictionary> dict2 = OSConstPtrCast<OSDictionary>(os::move(dict));
		assert(dict == nullptr);
		assert(dict2 == nullptr);
	}
}

static void
OSDynamicPtrCastTests()
{
	OSSharedPtr<OSDictionary> const dict = OSMakeShared<OSDictionary>();
	{
		OSSharedPtr<OSCollection> collection = OSDynamicPtrCast<OSCollection>(dict);
		assert(collection != nullptr);
	}
	{
		OSSharedPtr<OSArray> array = OSDynamicPtrCast<OSArray>(dict);
		assert(array == nullptr);
		assert(dict != nullptr);
	}
	{
		OSTaggedSharedPtr<OSCollection, OSCollection> taggedDict(dict.get(), OSRetain);
		OSTaggedSharedPtr<OSCollection, OSCollection> collection = OSDynamicPtrCast<OSCollection>(taggedDict);
		assert(collection != nullptr);
	}
	{
		OSTaggedSharedPtr<OSCollection, OSCollection> taggedDict(dict.get(), OSRetain);
		OSTaggedSharedPtr<OSArray, OSCollection> array = OSDynamicPtrCast<OSArray>(taggedDict);
		assert(array == nullptr);
		assert(dict != nullptr);
	}
	{
		OSSharedPtr<OSCollection> collection = OSDynamicPtrCast<OSCollection>(dict);
		assert(collection.get() == OSDynamicCast(OSDictionary, dict.get()));
		OSSharedPtr<OSDictionary> newDict = OSDynamicPtrCast<OSDictionary>(os::move(collection));
		assert(collection == nullptr);
		assert(newDict != nullptr);
		assert(newDict.get() == dict.get());
	}
}

static int
OSSharedPtrTests(int)
{
	OSDynamicPtrCastTests();
	OSConstPtrCastTests();
	OSStaticPtrCastTests();
	return 0;
}

#endif  /* DEVELOPMENT || DEBUG */

#ifndef __clang_analyzer__
// All the scary things that this function is doing, such as the intentional
// overrelease of an OSData, are hidden from the static analyzer.
static int
sysctl_iokittest(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	int newValue, changed;

	error = sysctl_io_number(req, 0, sizeof(int), &newValue, &changed);
	if (error) {
		return error;
	}

#if DEVELOPMENT || DEBUG
	if (changed && (66 == newValue)) {
		IOReturn ret;
		IOWorkLoop * wl = IOWorkLoop::workLoop();
		IOCommandGate * cg = IOCommandGate::commandGate(wl);
		ret = wl->addEventSource(cg);

		struct x {
			uint64_t h;
			uint64_t l;
		};
		struct x y;

		y.h = 0x1111111122222222;
		y.l = 0x3333333344444444;

		kprintf("ret1 %d\n", ret);
		ret = cg->runActionBlock(^(){
			printf("hello %d 0x%qx\n", wl->inGate(), y.h);
			return 99;
		});
		kprintf("ret %d\n", ret);
	}

	if (changed && (999 == newValue)) {
		OSData * data = OSData::withCapacity(16);
		data->release();
		data->release();
	}

	if (changed && (newValue >= 6666) && (newValue <= 6669)) {
		OSIterator * iter;
		IOService  * service;

		service = NULL;
		iter = IOService::getMatchingServices(IOService::nameMatching("XHC1"));
		if (iter && (service = (IOService *) iter->getNextObject())) {
			if (newValue == 6666) {
				IOLog("terminating 0x%qx\n", service->getRegistryEntryID());
				service->terminate();
			} else if (newValue == 6667) {
				IOLog("register 0x%qx\n", service->getRegistryEntryID());
				service->registerService();
			}
		}
		OSSafeReleaseNULL(iter);
		if (service) {
			return 0;
		}
	}


	if (changed && newValue) {
		error = IOWorkLoopTest(newValue);
		assert(KERN_SUCCESS == error);
		error = IOServiceTest(newValue);
		assert(KERN_SUCCESS == error);
		error = OSCollectionTest(newValue);
		assert(KERN_SUCCESS == error);
		error = OSAllocationTests(newValue);
		assert(KERN_SUCCESS == error);
		error = OSBoundedArrayTests(newValue);
		assert(KERN_SUCCESS == error);
		error = OSBoundedArrayRefTests(newValue);
		assert(KERN_SUCCESS == error);
		error = OSBoundedPtrTests(newValue);
		assert(KERN_SUCCESS == error);
		error = IOMemoryDescriptorTest(newValue);
		assert(KERN_SUCCESS == error);
		error = OSSharedPtrTests(newValue);
		assert(KERN_SUCCESS == error);
		error = IOSharedDataQueue_44636964(newValue);
		assert(KERN_SUCCESS == error);
	}
#endif  /* DEVELOPMENT || DEBUG */

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, iokittest,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
    NULL, 0, sysctl_iokittest, "I", "");
#endif // __clang_analyzer__
