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

#define TEST_HEADERS	0

#if TEST_HEADERS

#include <libkern/OSByteOrder.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSBoolean.h>
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
#include <libkern/OSMalloc.h>
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

#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

#if DEVELOPMENT || DEBUG

static uint64_t gIOWorkLoopTestDeadline;

static void
TESAction(OSObject * owner, IOTimerEventSource * tes)
{
    if (mach_absolute_time() < gIOWorkLoopTestDeadline) tes->setTimeout(1, kMicrosecondScale);
}

static int
IOWorkLoopTest(int newValue)
{
    IOReturn err;
    uint32_t idx;
    IOWorkLoop * wl;
    IOTimerEventSource * tes;

    wl = IOWorkLoop::workLoop();
    assert(wl);
    tes = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsPriorityWorkLoop, wl, &TESAction);
    assert(tes);
    err = wl->addEventSource(tes);
    assert(kIOReturnSuccess == err);
    clock_interval_to_deadline(2000, kMillisecondScale, &gIOWorkLoopTestDeadline);
    for (idx = 0; mach_absolute_time() < gIOWorkLoopTestDeadline; idx++)
    {
	tes->setTimeout(idx & 1023, kNanosecondScale);
    }
    tes->cancelTimeout();
    wl->removeEventSource(tes);
    tes->release();
    wl->release();

    return (0);
}

#endif  /* DEVELOPMENT || DEBUG */

static int
sysctl_iokittest(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
    int error;
    int newValue, changed;

    error = sysctl_io_number(req, 0, sizeof(int), &newValue, &changed);
    if (error) return (error);

#if DEVELOPMENT || DEBUG
    if (changed && (999==newValue))
    {
    	OSData * data = OSData::withCapacity(16);
	data->release();
	data->release();
    }

    if (changed && newValue)
    {
	error = IOWorkLoopTest(newValue);
	assert(KERN_SUCCESS == error);
	error = IOMemoryDescriptorTest(newValue);
	assert(KERN_SUCCESS == error);
    }
#endif  /* DEVELOPMENT || DEBUG */

    return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, iokittest,
        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
        0, 0, sysctl_iokittest, "I", "");


