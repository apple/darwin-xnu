/*
 * Copyright (c) 1998-2014 Apple Inc. All rights reserved.
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

#include <ptrauth.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOInterrupts.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOInterruptAccountingPrivate.h>
#include <libkern/Block_private.h>

#if IOKITSTATS

#define IOStatisticsInitializeCounter() \
do { \
	IOStatistics::setCounterType(IOEventSource::reserved->counter, kIOStatisticsInterruptEventSourceCounter); \
} while (0)

#define IOStatisticsCheckForWork() \
do { \
	IOStatistics::countInterruptCheckForWork(IOEventSource::reserved->counter); \
} while (0)

#define IOStatisticsInterrupt() \
do { \
	IOStatistics::countInterrupt(IOEventSource::reserved->counter); \
} while (0)

#else

#define IOStatisticsInitializeCounter()
#define IOStatisticsCheckForWork()
#define IOStatisticsInterrupt()

#endif // IOKITSTATS

#define super IOEventSource

OSDefineMetaClassAndStructors(IOInterruptEventSource, IOEventSource)
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 0);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 1);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 2);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 3);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 4);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 5);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 6);
OSMetaClassDefineReservedUnused(IOInterruptEventSource, 7);

bool
IOInterruptEventSource::init(OSObject *inOwner,
    Action inAction,
    IOService *inProvider,
    int inIntIndex)
{
	bool res = true;

	if (!super::init(inOwner, (IOEventSourceAction) inAction)) {
		return false;
	}

	reserved = IONew(ExpansionData, 1);

	if (!reserved) {
		return false;
	}

	bzero(reserved, sizeof(ExpansionData));

	provider = inProvider;
	producerCount = consumerCount = 0;
	autoDisable = explicitDisable = false;
	intIndex = ~inIntIndex;

	// Assumes inOwner holds a reference(retain) on the provider
	if (inProvider) {
		if (IA_ANY_STATISTICS_ENABLED) {
			/*
			 * We only treat this as an "interrupt" if it has a provider; if it does,
			 * set up the objects necessary to track interrupt statistics.  Interrupt
			 * event sources without providers are most likely being used as simple
			 * event source in order to poke at workloops and kick off work.
			 *
			 * We also avoid try to avoid interrupt accounting overhead if none of
			 * the statistics are enabled.
			 */
			reserved->statistics = IONew(IOInterruptAccountingData, 1);

			if (!reserved->statistics) {
				/*
				 * We rely on the free() routine to clean up after us if init fails
				 * midway.
				 */
				return false;
			}

			bzero(reserved->statistics, sizeof(IOInterruptAccountingData));

			reserved->statistics->owner = this;
		}

		res = (kIOReturnSuccess == registerInterruptHandler(inProvider, inIntIndex));

		if (res) {
			intIndex = inIntIndex;
		}
	}

	IOStatisticsInitializeCounter();

	return res;
}

IOReturn
IOInterruptEventSource::registerInterruptHandler(IOService *inProvider,
    int inIntIndex)
{
	IOReturn ret;
	int intType;
	IOInterruptAction intHandler;

	ret = inProvider->getInterruptType(inIntIndex, &intType);
	if (kIOReturnSuccess != ret) {
		return ret;
	}

	autoDisable = (intType == kIOInterruptTypeLevel);
	if (autoDisable) {
		intHandler = OSMemberFunctionCast(IOInterruptAction,
		    this, &IOInterruptEventSource::disableInterruptOccurred);
	} else {
		intHandler = OSMemberFunctionCast(IOInterruptAction,
		    this, &IOInterruptEventSource::normalInterruptOccurred);
	}

	ret = provider->registerInterrupt(inIntIndex, this, intHandler);

	/*
	 * Add statistics to the provider.  The setWorkLoop convention should ensure
	 * that we always go down the unregister path before we register (outside of
	 * init()), so we don't have to worry that we will invoke addInterruptStatistics
	 * erroneously.
	 */
	if ((ret == kIOReturnSuccess) && (reserved->statistics)) {
		/*
		 * Stash the normal index value, for the sake of debugging.
		 */
		reserved->statistics->interruptIndex = inIntIndex;

		/*
		 * We need to hook the interrupt information up to the provider so that it
		 * can find the statistics for this interrupt when desired.  The provider is
		 * responsible for maintaining the reporter for a particular interrupt, and
		 * needs a handle on the statistics so that it can request that the reporter
		 * be updated as needed.  Errors are considered "soft" for the moment (it
		 * will either panic, or fail in a way such that we can still service the
		 * interrupt).
		 */
		provider->addInterruptStatistics(reserved->statistics, inIntIndex);

		/*
		 * Add the statistics object to the global list of statistics objects; this
		 * is an aid to debugging (we can trivially find statistics for all eligible
		 * interrupts, and dump them; potentially helpful if the system is wedged
		 * due to interrupt activity).
		 */
		interruptAccountingDataAddToList(reserved->statistics);
	}

	return ret;
}

void
IOInterruptEventSource::unregisterInterruptHandler(IOService *inProvider,
    int inIntIndex)
{
	if (reserved->statistics) {
		interruptAccountingDataRemoveFromList(reserved->statistics);
		provider->removeInterruptStatistics(reserved->statistics->interruptIndex);
	}

	provider->unregisterInterrupt(inIntIndex);
}


OSSharedPtr<IOInterruptEventSource>
IOInterruptEventSource::interruptEventSource(OSObject *inOwner,
    Action inAction,
    IOService *inProvider,
    int inIntIndex)
{
	OSSharedPtr<IOInterruptEventSource> me = OSMakeShared<IOInterruptEventSource>();

	if (me && !me->init(inOwner, inAction, inProvider, inIntIndex)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<IOInterruptEventSource>
IOInterruptEventSource::interruptEventSource(OSObject *inOwner,
    IOService *inProvider,
    int inIntIndex,
    ActionBlock inAction)
{
	OSSharedPtr<IOInterruptEventSource> ies;
	ies = IOInterruptEventSource::interruptEventSource(inOwner, (Action) NULL, inProvider, inIntIndex);
	if (ies) {
		ies->setActionBlock((IOEventSource::ActionBlock) inAction);
	}

	return ies;
}

void
IOInterruptEventSource::free()
{
	if (provider && intIndex >= 0) {
		unregisterInterruptHandler(provider, intIndex);
	}

	if (reserved) {
		if (reserved->statistics) {
			IODelete(reserved->statistics, IOInterruptAccountingData, 1);
		}

		IODelete(reserved, ExpansionData, 1);
	}

	super::free();
}

void
IOInterruptEventSource::enable()
{
	if (provider && intIndex >= 0) {
		provider->enableInterrupt(intIndex);
		explicitDisable = false;
		enabled = true;
	}
}

void
IOInterruptEventSource::disable()
{
	if (provider && intIndex >= 0) {
		provider->disableInterrupt(intIndex);
		explicitDisable = true;
		enabled = false;
	}
}

void
IOInterruptEventSource::setWorkLoop(IOWorkLoop *inWorkLoop)
{
	if (inWorkLoop) {
		super::setWorkLoop(inWorkLoop);
	}

	if (provider) {
		if (!inWorkLoop) {
			if (intIndex >= 0) {
				/*
				 * It isn't necessarily safe to wait until free() to unregister the interrupt;
				 * our provider may disappear.
				 */
				unregisterInterruptHandler(provider, intIndex);
				intIndex = ~intIndex;
			}
		} else if ((intIndex < 0) && (kIOReturnSuccess == registerInterruptHandler(provider, ~intIndex))) {
			intIndex = ~intIndex;
		}
	}

	if (!inWorkLoop) {
		super::setWorkLoop(inWorkLoop);
	}
}

const IOService *
IOInterruptEventSource::getProvider() const
{
	return provider;
}

int
IOInterruptEventSource::getIntIndex() const
{
	return intIndex;
}

bool
IOInterruptEventSource::getAutoDisable() const
{
	return autoDisable;
}

bool
IOInterruptEventSource::checkForWork()
{
	uint64_t startSystemTime = 0;
	uint64_t endSystemTime = 0;
	uint64_t startCPUTime = 0;
	uint64_t endCPUTime = 0;
	unsigned int cacheProdCount = producerCount;
	int numInts = cacheProdCount - consumerCount;
	IOEventSource::Action intAction = action;
	ActionBlock intActionBlock = (ActionBlock) actionBlock;
	void *address;
	bool trace = (gIOKitTrace & kIOTraceIntEventSource) ? true : false;

	if (kActionBlock & flags) {
		address = ptrauth_nop_cast(void *, _Block_get_invoke_fn((struct Block_layout *)intActionBlock));
	} else {
		address = ptrauth_nop_cast(void *, intAction);
	}

	IOStatisticsCheckForWork();

	if (numInts > 0) {
		if (trace) {
			IOTimeStampStartConstant(IODBG_INTES(IOINTES_ACTION),
			    VM_KERNEL_ADDRHIDE(address),
			    VM_KERNEL_ADDRHIDE(owner),
			    VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(workLoop));
		}

		if (reserved->statistics) {
			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelSystemTimeIndex)) {
				startSystemTime = mach_absolute_time();
			}

			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelCPUTimeIndex)) {
				startCPUTime = thread_get_runtime_self();
			}
		}

		// Call the handler
		if (kActionBlock & flags) {
			(intActionBlock)(this, numInts);
		} else {
			((IOInterruptEventAction)intAction)(owner, this, numInts);
		}

		if (reserved->statistics) {
			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelCountIndex)) {
				IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingSecondLevelCountIndex], 1);
			}

			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelCPUTimeIndex)) {
				endCPUTime = thread_get_runtime_self();
				IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingSecondLevelCPUTimeIndex], endCPUTime - startCPUTime);
			}

			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelSystemTimeIndex)) {
				endSystemTime = mach_absolute_time();
				IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingSecondLevelSystemTimeIndex], endSystemTime - startSystemTime);
			}
		}

		if (trace) {
			IOTimeStampEndConstant(IODBG_INTES(IOINTES_ACTION),
			    VM_KERNEL_ADDRHIDE(address),
			    VM_KERNEL_ADDRHIDE(owner),
			    VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(workLoop));
		}

		consumerCount = cacheProdCount;
		if (autoDisable && !explicitDisable) {
			enable();
		}
	} else if (numInts < 0) {
		if (trace) {
			IOTimeStampStartConstant(IODBG_INTES(IOINTES_ACTION),
			    VM_KERNEL_ADDRHIDE(address),
			    VM_KERNEL_ADDRHIDE(owner),
			    VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(workLoop));
		}

		if (reserved->statistics) {
			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelSystemTimeIndex)) {
				startSystemTime = mach_absolute_time();
			}

			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelCPUTimeIndex)) {
				startCPUTime = thread_get_runtime_self();
			}
		}

		// Call the handler
		if (kActionBlock & flags) {
			(intActionBlock)(this, numInts);
		} else {
			((IOInterruptEventAction)intAction)(owner, this, numInts);
		}

		if (reserved->statistics) {
			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelCountIndex)) {
				IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingSecondLevelCountIndex], 1);
			}

			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelCPUTimeIndex)) {
				endCPUTime = thread_get_runtime_self();
				IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingSecondLevelCPUTimeIndex], endCPUTime - startCPUTime);
			}

			if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingSecondLevelSystemTimeIndex)) {
				endSystemTime = mach_absolute_time();
				IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingSecondLevelSystemTimeIndex], endSystemTime - startSystemTime);
			}
		}

		if (trace) {
			IOTimeStampEndConstant(IODBG_INTES(IOINTES_ACTION),
			    VM_KERNEL_ADDRHIDE(address),
			    VM_KERNEL_ADDRHIDE(owner),
			    VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(workLoop));
		}

		consumerCount = cacheProdCount;
		if (autoDisable && !explicitDisable) {
			enable();
		}
	}

	return false;
}

void
IOInterruptEventSource::normalInterruptOccurred
(void */*refcon*/, IOService */*prov*/, int /*source*/)
{
	bool trace = (gIOKitTrace & kIOTraceIntEventSource) ? true : false;

	IOStatisticsInterrupt();
	producerCount++;

	if (trace) {
		IOTimeStampStartConstant(IODBG_INTES(IOINTES_SEMA), VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(owner));
	}

	if (reserved->statistics) {
		if (reserved->statistics->enablePrimaryTimestamp) {
			reserved->statistics->primaryTimestamp = mach_absolute_time();
		}
		if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingFirstLevelCountIndex)) {
			IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingFirstLevelCountIndex], 1);
		}
	}

	signalWorkAvailable();

	if (trace) {
		IOTimeStampEndConstant(IODBG_INTES(IOINTES_SEMA), VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(owner));
	}
}

void
IOInterruptEventSource::disableInterruptOccurred
(void */*refcon*/, IOService *prov, int source)
{
	bool trace = (gIOKitTrace & kIOTraceIntEventSource) ? true : false;

	prov->disableInterrupt(source); /* disable the interrupt */

	IOStatisticsInterrupt();
	producerCount++;

	if (trace) {
		IOTimeStampStartConstant(IODBG_INTES(IOINTES_SEMA), VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(owner));
	}

	if (reserved->statistics) {
		if (reserved->statistics->enablePrimaryTimestamp) {
			reserved->statistics->primaryTimestamp = mach_absolute_time();
		}
		if (IA_GET_STATISTIC_ENABLED(kInterruptAccountingFirstLevelCountIndex)) {
			IA_ADD_VALUE(&reserved->statistics->interruptStatistics[kInterruptAccountingFirstLevelCountIndex], 1);
		}
	}

	signalWorkAvailable();

	if (trace) {
		IOTimeStampEndConstant(IODBG_INTES(IOINTES_SEMA), VM_KERNEL_ADDRHIDE(this), VM_KERNEL_ADDRHIDE(owner));
	}
}

void
IOInterruptEventSource::interruptOccurred
(void *_refcon, IOService *prov, int source)
{
	if (autoDisable && prov) {
		disableInterruptOccurred(_refcon, prov, source);
	} else {
		normalInterruptOccurred(_refcon, prov, source);
	}
}

IOReturn
IOInterruptEventSource::warmCPU
(uint64_t abstime)
{
	return ml_interrupt_prewarm(abstime);
}

void
IOInterruptEventSource::enablePrimaryInterruptTimestamp(bool enable)
{
	if (reserved->statistics) {
		reserved->statistics->enablePrimaryTimestamp = enable;
	}
}

uint64_t
IOInterruptEventSource::getPrimaryInterruptTimestamp()
{
	if (reserved->statistics && reserved->statistics->enablePrimaryTimestamp) {
		return reserved->statistics->primaryTimestamp;
	}
	return -1ULL;
}
