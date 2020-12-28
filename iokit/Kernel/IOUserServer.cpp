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

#include <IOKit/IORPC.h>
#include <IOKit/IOKitServer.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOService.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/system.h>
#include <IOKit/IOUserServer.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <libkern/c++/OSKext.h>
#include <libkern/OSDebug.h>
#include <libkern/Block.h>
#include <sys/proc.h>
#include "IOKitKernelInternal.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

#include <DriverKit/IODispatchQueue.h>
#include <DriverKit/OSObject.h>
#include <DriverKit/OSAction.h>
#include <DriverKit/IODispatchSource.h>
#include <DriverKit/IOInterruptDispatchSource.h>
#include <DriverKit/IOService.h>
#include <DriverKit/IOMemoryDescriptor.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>
#include <DriverKit/IOMemoryMap.h>
#include <DriverKit/IODataQueueDispatchSource.h>
#include <DriverKit/IOServiceNotificationDispatchSource.h>
#include <DriverKit/IOUserServer.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

#include <System/IODataQueueDispatchSourceShared.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

SInt64    gIODKDebug = kIODKEnable;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

struct IOPStrings;

class OSUserMetaClass : public OSObject
{
	OSDeclareDefaultStructors(OSUserMetaClass);
public:
	const OSSymbol    * name;
	const OSMetaClass * meta;
	OSUserMetaClass   * superMeta;

	queue_chain_t       link;

	OSClassDescription * description;
	IOPStrings * queueNames;
	uint32_t     methodCount;
	uint64_t   * methods;

	virtual void free() override;
	virtual kern_return_t Dispatch(const IORPC rpc) APPLE_KEXT_OVERRIDE;
};
OSDefineMetaClassAndStructors(OSUserMetaClass, OSObject);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserService : public IOService
{
	friend class IOService;

	OSDeclareDefaultStructors(IOUserService)

	virtual bool
	start(IOService * provider) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(IOUserService, IOService)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserUserClient : public IOUserClient
{
	OSDeclareDefaultStructors(IOUserUserClient);
public:
	task_t          fTask;

	IOReturn                   setTask(task_t task);
	virtual void           stop(IOService * provider) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       clientClose(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       setProperties(OSObject * properties) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       externalMethod(uint32_t selector, IOExternalMethodArguments * args,
	    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference) APPLE_KEXT_OVERRIDE;
	virtual IOReturn           clientMemoryForType(UInt32 type,
	    IOOptionBits * options,
	    IOMemoryDescriptor ** memory) APPLE_KEXT_OVERRIDE;
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


bool
IOUserService::start(IOService * provider)
{
	bool     ok = true;
	IOReturn ret;

	ret = Start(provider);
	if (kIOReturnSuccess != ret) {
		return false;
	}

	return ok;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

#undef super

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

struct IODispatchQueue_IVars {
	IOUserServer * userServer;
	IODispatchQueue   * queue;
	queue_chain_t  link;
	uint64_t       tid;

	mach_port_t    serverPort;
};

struct OSAction_IVars {
	OSObject             * target;
	uint64_t               targetmsgid;
	uint64_t               msgid;
	OSActionAbortedHandler abortedHandler;
	size_t                 referenceSize;
	void                 * reference[0];
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IOService, GetRegistryEntryID)
{
	IOReturn ret = kIOReturnSuccess;

	*registryEntryID = getRegistryEntryID();

	return ret;
}

kern_return_t
IMPL(IOService, SetName)
{
	IOReturn ret = kIOReturnSuccess;

	setName(name);

	return ret;
}

kern_return_t
IMPL(IOService, Start)
{
	IOReturn ret = kIOReturnSuccess;
	return ret;
}

kern_return_t
IMPL(IOService, RegisterService)
{
	IOReturn ret = kIOReturnSuccess;

	registerService();

	return ret;
}

kern_return_t
IMPL(IOService, CopyDispatchQueue)
{
	IODispatchQueue * result;
	IOService  * service;
	IOReturn     ret;
	uint32_t index;

	ret = kIOReturnNotFound;
	index = -1U;
	if (!strcmp("Default", name)) {
		index = 0;
	} else if (reserved->uvars->userMeta
	    && reserved->uvars->userMeta->queueNames) {
		index = reserved->uvars->userServer->stringArrayIndex(reserved->uvars->userMeta->queueNames, name);
		if (index != -1U) {
			index++;
		}
	}
	if (index == -1U) {
		if ((service = getProvider())) {
			ret = service->CopyDispatchQueue(name, queue);
		}
	} else {
		result = reserved->uvars->queueArray[index];
		if (result) {
			result->retain();
			*queue = result;
			ret = kIOReturnSuccess;
		}
	}

	return ret;
}

kern_return_t
IMPL(IOService, SetDispatchQueue)
{
	IOReturn ret = kIOReturnSuccess;
	uint32_t index;

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG(DKS "::SetDispatchQueue(%s)\n", DKN(this), name);
	}
	queue->ivars->userServer = reserved->uvars->userServer;
	index = -1U;
	if (!strcmp("Default", name)) {
		index = 0;
	} else if (reserved->uvars->userMeta
	    && reserved->uvars->userMeta->queueNames) {
		index = reserved->uvars->userServer->stringArrayIndex(reserved->uvars->userMeta->queueNames, name);
		if (index != -1U) {
			index++;
		}
	}
	if (index == -1U) {
		ret = kIOReturnBadArgument;
	} else {
		reserved->uvars->queueArray[index] = queue;
		queue->retain();
	}

	return ret;
}

kern_return_t
IMPL(IOService, SetProperties)
{
	IOUserServer   * us;
	OSDictionary   * dict;
	IOReturn         ret;

	ret = setProperties(properties);

	if (kIOReturnUnsupported == ret) {
		dict = OSDynamicCast(OSDictionary, properties);
		us = (typeof(us))thread_iokit_tls_get(0);
		if (dict && reserved->uvars && (reserved->uvars->userServer == us)) {
			ret = runPropertyActionBlock(^IOReturn (void) {
				OSDictionary   * userProps;
				IOReturn         ret;

				userProps = OSDynamicCast(OSDictionary, getProperty(gIOUserServicePropertiesKey));
				if (userProps) {
				        userProps = (typeof(userProps))userProps->copyCollection();
				} else {
				        userProps = OSDictionary::withCapacity(4);
				}
				if (!userProps) {
				        ret = kIOReturnNoMemory;
				} else {
				        bool ok = userProps->merge(dict);
				        if (ok) {
				                ok = setProperty(gIOUserServicePropertiesKey, userProps);
					}
				        OSSafeReleaseNULL(userProps);
				        ret = ok ? kIOReturnSuccess : kIOReturnNotWritable;
				}
				return ret;
			});
		}
	}

	return ret;
}

kern_return_t
IMPL(IOService, CopyProperties)
{
	IOReturn ret = kIOReturnSuccess;
	*properties = dictionaryWithProperties();
	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IOMemoryDescriptor, _CopyState)
{
	IOReturn ret;

	state->length = _length;
	state->options = _flags;

	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IOMemoryDescriptor::GetLength(uint64_t * returnLength)
{
	*returnLength = getLength();

	return kIOReturnSuccess;
}

kern_return_t
IMPL(IOMemoryDescriptor, CreateMapping)
{
	IOReturn          ret;
	IOMemoryMap     * resultMap;
	IOOptionBits      koptions;
	mach_vm_address_t atAddress;

	ret       = kIOReturnSuccess;
	koptions  = 0;
	resultMap = NULL;

	if (kIOMemoryMapFixedAddress & options) {
		atAddress   = address;
		koptions    = 0;
	} else {
		atAddress   = 0;
		koptions   |= kIOMapAnywhere;
	}

	if (kIOMemoryMapReadOnly & options || (kIODirectionOut == getDirection())) {
		if (!reserved || (current_task() != reserved->creator)) {
			koptions   |= kIOMapReadOnly;
		}
	}

	switch (0xFF00 & options) {
	case kIOMemoryMapCacheModeDefault:
		koptions |= kIOMapDefaultCache;
		break;
	case kIOMemoryMapCacheModeInhibit:
		koptions |= kIOMapInhibitCache;
		break;
	case kIOMemoryMapCacheModeCopyback:
		koptions |= kIOMapCopybackCache;
		break;
	case kIOMemoryMapCacheModeWriteThrough:
		koptions |= kIOMapWriteThruCache;
		break;
	default:
		ret = kIOReturnBadArgument;
	}

	if (kIOReturnSuccess == ret) {
		resultMap = createMappingInTask(current_task(), atAddress, koptions, offset, length);
		if (!resultMap) {
			ret = kIOReturnError;
		}
	}

	*map = resultMap;

	return ret;
}

kern_return_t
IMPL(IOMemoryDescriptor, PrepareForDMA)
{
	IOReturn    ret;
	uint32_t    idx, count;
	uint64_t    sumLength;
	uint64_t    lflags;

	if (!device) {
		return kIOReturnBadArgument;
	}

	count = *segmentsCount;
	sumLength = 0;
	for (idx = 0; idx < count; idx++) {
#ifdef __LP64__
		segments[idx].address = getPhysicalSegment(offset, &segments[idx].length);
#else
		segments[idx].address = 0;
#endif
		if (!segments[idx].address) {
			break;
		}
		sumLength += segments[idx].length;
		offset += segments[idx].length;
	}
	*returnLength = sumLength;
	*segmentsCount = idx;

	// !!translate flags
	lflags = 0;
	if (kIODirectionOut & _flags) {
		lflags |= kIOMemoryDirectionOut;
	}
	if (kIODirectionIn  & _flags) {
		lflags |= kIOMemoryDirectionIn;
	}

	*flags = lflags;
	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IOMemoryMap, _CopyState)
{
	IOReturn ret;

	state->offset  = fOffset;
	state->length  = getLength();
	state->address = getAddress();
	state->options = getMapOptions();

	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IOBufferMemoryDescriptor, Create)
{
	IOReturn ret;
	IOBufferMemoryDescriptor   * bmd;
	IOMemoryDescriptorReserved * reserved;

	if (options & ~((uint64_t) kIOMemoryDirectionOutIn)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}
	options &= kIOMemoryDirectionOutIn;
	options |= kIOMemoryKernelUserShared;
	bmd = IOBufferMemoryDescriptor::inTaskWithOptions(
		kernel_task, options, capacity, alignment);

	*memory = bmd;

	if (!bmd) {
		return kIOReturnNoMemory;
	}

	reserved = bmd->getKernelReserved();
	reserved->creator = current_task();
	task_reference(reserved->creator);

	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IMPL(IOBufferMemoryDescriptor, SetLength)
{
	setLength(length);
	return kIOReturnSuccess;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IODMACommand, Create)
{
	IOReturn ret;
	IODMACommand   * dma;
	IODMACommand::SegmentOptions segmentOptions;
	IOMapper             * mapper;

	if (options & ~((uint64_t) kIODMACommandCreateNoOptions)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	if (os_convert_overflow(specification->maxAddressBits, &segmentOptions.fNumAddressBits)) {
		return kIOReturnBadArgument;
	}
	segmentOptions.fMaxSegmentSize            = 0;
	segmentOptions.fMaxTransferSize           = 0;
	segmentOptions.fAlignment                 = 1;
	segmentOptions.fAlignmentLength           = 1;
	segmentOptions.fAlignmentInternalSegments = 1;
	segmentOptions.fStructSize                = sizeof(segmentOptions);

	mapper = IOMapper::copyMapperForDevice(device);

	dma = IODMACommand::withSpecification(
		kIODMACommandOutputHost64,
		&segmentOptions,
		kIODMAMapOptionMapped,
		mapper,
		NULL);

	OSSafeReleaseNULL(mapper);
	*command = dma;

	if (!dma) {
		return kIOReturnNoMemory;
	}
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IMPL(IODMACommand, PrepareForDMA)
{
	IOReturn ret;
	uint64_t lflags, mdFlags;
	UInt32   numSegments;
	UInt64   genOffset;

	if (options & ~((uint64_t) kIODMACommandPrepareForDMANoOptions)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	ret = setMemoryDescriptor(memory, false);
	if (kIOReturnSuccess != ret) {
		return ret;
	}

	ret = prepare(offset, length);
	if (kIOReturnSuccess != ret) {
		clearMemoryDescriptor(false);
		return ret;
	}

	static_assert(sizeof(IODMACommand::Segment64) == sizeof(IOAddressSegment));

	numSegments = *segmentsCount;
	genOffset   = offset;
	ret = genIOVMSegments(&genOffset, segments, &numSegments);

	if (kIOReturnSuccess == ret) {
		IOMemoryDescriptor * mem;
		mem = __IODEQUALIFY(IOMemoryDescriptor *, fMemory);
		mdFlags = mem->getFlags();
		lflags  = 0;
		if (kIODirectionOut & mdFlags) {
			lflags |= kIOMemoryDirectionOut;
		}
		if (kIODirectionIn & mdFlags) {
			lflags |= kIOMemoryDirectionIn;
		}
		*flags = lflags;
		*segmentsCount = numSegments;
	}

	return ret;
}

kern_return_t
IMPL(IODMACommand, CompleteDMA)
{
	IOReturn ret;

	if (options & ~((uint64_t) kIODMACommandCompleteDMANoOptions)) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	ret = clearMemoryDescriptor(true);

	return ret;
}

kern_return_t
IMPL(IODMACommand, GetPreparation)
{
	IOReturn ret;
	IOMemoryDescriptor * md;

	if (!fActive) {
		return kIOReturnNotReady;
	}

	ret = getPreparedOffsetAndLength(offset, length);
	if (kIOReturnSuccess != ret) {
		return ret;
	}

	if (memory) {
		md = __DECONST(IOMemoryDescriptor *, fMemory);
		*memory = md;
		if (!md) {
			ret = kIOReturnNotReady;
		} else {
			md->retain();
		}
	}
	return ret;
}

kern_return_t
IMPL(IODMACommand, PerformOperation)
{
	IOReturn ret;
	void * buffer;
	UInt64 copiedDMA;
	IOByteCount mdOffset, mdLength, copied;

	if (options & ~((uint64_t)
	    (kIODMACommandPerformOperationOptionRead
	    | kIODMACommandPerformOperationOptionWrite
	    | kIODMACommandPerformOperationOptionZero))) {
		// no other options currently defined
		return kIOReturnBadArgument;
	}

	if (!fActive) {
		return kIOReturnNotReady;
	}
	if (os_convert_overflow(dataOffset, &mdOffset)) {
		return kIOReturnBadArgument;
	}
	if (os_convert_overflow(length, &mdLength)) {
		return kIOReturnBadArgument;
	}
	if (length > fMemory->getLength()) {
		return kIOReturnBadArgument;
	}
	buffer = IONew(uint8_t, length);
	if (NULL == buffer) {
		return kIOReturnNoMemory;
	}

	switch (options) {
	case kIODMACommandPerformOperationOptionZero:
		bzero(buffer, length);
		copiedDMA = writeBytes(dmaOffset, buffer, length);
		if (copiedDMA != length) {
			ret = kIOReturnUnderrun;
			break;
		}
		ret = kIOReturnSuccess;
		break;

	case kIODMACommandPerformOperationOptionRead:
	case kIODMACommandPerformOperationOptionWrite:

		if (!data) {
			ret = kIOReturnBadArgument;
			break;
		}
		if (length > data->getLength()) {
			ret = kIOReturnBadArgument;
			break;
		}
		if (kIODMACommandPerformOperationOptionWrite == options) {
			copied = data->readBytes(mdOffset, buffer, mdLength);
			if (copied != mdLength) {
				ret = kIOReturnUnderrun;
				break;
			}
			copiedDMA = writeBytes(dmaOffset, buffer, length);
			if (copiedDMA != length) {
				ret = kIOReturnUnderrun;
				break;
			}
		} else {       /* kIODMACommandPerformOperationOptionRead */
			copiedDMA = readBytes(dmaOffset, buffer, length);
			if (copiedDMA != length) {
				ret = kIOReturnUnderrun;
				break;
			}
			copied = data->writeBytes(mdOffset, buffer, mdLength);
			if (copied != mdLength) {
				ret = kIOReturnUnderrun;
				break;
			}
		}
		ret = kIOReturnSuccess;
		break;
	default:
		ret = kIOReturnBadArgument;
		break;
	}

	IODelete(buffer, uint8_t, length);

	return ret;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
OSAction::Create(OSAction_Create_Args)
{
	kern_return_t ret;
	ret = OSAction::Create_Call(target, targetmsgid, msgid, referenceSize, action);
	return ret;
}

kern_return_t
IMPL(OSAction, Create)
{
	OSAction * inst;
	vm_size_t  allocsize;

	if (os_add_overflow(referenceSize, sizeof(OSAction_IVars), &allocsize)) {
		return kIOReturnBadArgument;
	}
	inst = OSTypeAlloc(OSAction);
	if (!inst) {
		return kIOReturnNoMemory;
	}
	inst->ivars = (typeof(inst->ivars))(uintptr_t) IONewZero(uint8_t, allocsize);
	if (!inst->ivars) {
		inst->release();
		return kIOReturnNoMemory;
	}
	target->retain();
	inst->ivars->target        = target;
	inst->ivars->targetmsgid   = targetmsgid;
	inst->ivars->msgid         = msgid;
	inst->ivars->referenceSize = referenceSize;

	*action = inst;

	return kIOReturnSuccess;
}

void
OSAction::free()
{
	if (ivars) {
		if (ivars->abortedHandler) {
			Block_release(ivars->abortedHandler);
			ivars->abortedHandler = NULL;
		}
		OSSafeReleaseNULL(ivars->target);
		IOSafeDeleteNULL(ivars, uint8_t, ivars->referenceSize + sizeof(OSAction_IVars));
	}
	return super::free();
}

void *
OSAction::GetReference()
{
	assert(ivars && ivars->referenceSize);
	return &ivars->reference[0];
}

kern_return_t
OSAction::SetAbortedHandler(OSActionAbortedHandler handler)
{
	ivars->abortedHandler = Block_copy(handler);
	return kIOReturnSuccess;
}

void
OSAction::Aborted_Impl(void)
{
	if (ivars->abortedHandler) {
		ivars->abortedHandler();
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

struct IODispatchSource_IVars {
	queue_chain_t           link;
	IODispatchSource      * source;
	IOUserServer          * server;
	IODispatchQueue_IVars * queue;
	bool                    enabled;
};

bool
IODispatchSource::init()
{
	if (!super::init()) {
		return false;
	}

	ivars = IONewZero(IODispatchSource_IVars, 1);

	ivars->source = this;

	return true;
}

void
IODispatchSource::free()
{
	IOSafeDeleteNULL(ivars, IODispatchSource_IVars, 1);
	super::free();
}

kern_return_t
IMPL(IODispatchSource, SetEnable)
{
	return SetEnableWithCompletion(enable, NULL);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

struct IOInterruptDispatchSource_IVars {
	IOService    * provider;
	uint32_t       intIndex;
	IOSimpleLock * lock;
	thread_t       waiter;
	uint64_t       count;
	uint64_t       time;
	OSAction     * action;
	bool           enable;
};

static void
IOInterruptDispatchSourceInterrupt(OSObject * target, void * refCon,
    IOService * nub, int source )
{
	IOInterruptDispatchSource_IVars * ivars = (typeof(ivars))refCon;
	IOInterruptState is;

	is = IOSimpleLockLockDisableInterrupt(ivars->lock);
	ivars->count++;
	if (ivars->waiter) {
		ivars->time = mach_absolute_time();
		thread_wakeup_thread((event_t) ivars, ivars->waiter);
		ivars->waiter = NULL;
	}
	IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
}

kern_return_t
IMPL(IOInterruptDispatchSource, Create)
{
	IOReturn ret;
	IOInterruptDispatchSource * inst;

	inst = OSTypeAlloc(IOInterruptDispatchSource);
	if (!inst->init()) {
		inst->free();
		return kIOReturnNoMemory;
	}

	inst->ivars->lock = IOSimpleLockAlloc();

	ret = provider->registerInterrupt(index, inst, IOInterruptDispatchSourceInterrupt, inst->ivars);
	if (kIOReturnSuccess == ret) {
		inst->ivars->intIndex = index;
		inst->ivars->provider = provider;
		*source = inst;
	}
	return ret;
}

kern_return_t
IMPL(IOInterruptDispatchSource, GetInterruptType)
{
	IOReturn ret;
	int      type;

	*interruptType = 0;
	ret = provider->getInterruptType(index, &type);
	if (kIOReturnSuccess == ret) {
		*interruptType = type;
	}

	return ret;
}

bool
IOInterruptDispatchSource::init()
{
	if (!super::init()) {
		return false;
	}
	ivars = IONewZero(IOInterruptDispatchSource_IVars, 1);
	if (!ivars) {
		return false;
	}

	return true;
}

void
IOInterruptDispatchSource::free()
{
	IOReturn ret;

	if (ivars && ivars->provider) {
		ret = ivars->provider->unregisterInterrupt(ivars->intIndex);
		assert(kIOReturnSuccess == ret);
	}

	if (ivars && ivars->lock) {
		IOSimpleLockFree(ivars->lock);
	}

	IOSafeDeleteNULL(ivars, IOInterruptDispatchSource_IVars, 1);

	super::free();
}

kern_return_t
IMPL(IOInterruptDispatchSource, SetHandler)
{
	IOReturn ret;
	OSAction * oldAction;

	oldAction = (typeof(oldAction))ivars->action;
	if (oldAction && OSCompareAndSwapPtr(oldAction, NULL, &ivars->action)) {
		oldAction->release();
	}
	action->retain();
	ivars->action = action;

	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IMPL(IOInterruptDispatchSource, SetEnableWithCompletion)
{
	IOReturn ret;
	IOInterruptState is;

	if (enable == ivars->enable) {
		return kIOReturnSuccess;
	}

	if (enable) {
		is = IOSimpleLockLockDisableInterrupt(ivars->lock);
		ivars->enable = enable;
		IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
		ret = ivars->provider->enableInterrupt(ivars->intIndex);
	} else {
		ret = ivars->provider->disableInterrupt(ivars->intIndex);
		is = IOSimpleLockLockDisableInterrupt(ivars->lock);
		ivars->enable = enable;
		IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
	}

	return ret;
}

kern_return_t
IMPL(IOInterruptDispatchSource, Cancel)
{
	return kIOReturnUnsupported;
}

kern_return_t
IMPL(IOInterruptDispatchSource, CheckForWork)
{
	IOReturn         ret = kIOReturnNotReady;
	IOInterruptState is;
	wait_result_t    waitResult;
	uint64_t         icount;
	uint64_t         itime;
	thread_t         self;

	self = current_thread();
	icount = 0;
	do {
		is = IOSimpleLockLockDisableInterrupt(ivars->lock);
		if ((icount = ivars->count)) {
			itime = ivars->time;
			ivars->count = 0;
			waitResult = THREAD_AWAKENED;
		} else if (synchronous) {
			assert(NULL == ivars->waiter);
			ivars->waiter = self;
			waitResult = assert_wait((event_t) ivars, THREAD_INTERRUPTIBLE);
		}
		IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
		if (synchronous && (waitResult == THREAD_WAITING)) {
			waitResult = thread_block(THREAD_CONTINUE_NULL);
			if (THREAD_INTERRUPTED == waitResult) {
				break;
			}
		}
	} while (synchronous && !icount);

	if (icount && ivars->action) {
		ret = InterruptOccurred(rpc, ivars->action, icount, itime);
	}

	return ret;
}

void
IMPL(IOInterruptDispatchSource, InterruptOccurred)
{
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

enum {
	kIOServiceNotificationTypeCount = kIOServiceNotificationTypeLast + 1,
};

struct IOServiceNotificationDispatchSource_IVars {
	OSObject     * serverName;
	OSAction     * action;
	IOLock       * lock;
	IONotifier   * notifier;
	OSDictionary * interestNotifiers;
	OSArray      * pending[kIOServiceNotificationTypeCount];
	bool           enable;
};

kern_return_t
IMPL(IOServiceNotificationDispatchSource, Create)
{
	IOUserServer * us;
	IOReturn       ret;
	IOServiceNotificationDispatchSource * inst;

	inst = OSTypeAlloc(IOServiceNotificationDispatchSource);
	if (!inst->init()) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}

	us = (typeof(us))thread_iokit_tls_get(0);
	assert(OSDynamicCast(IOUserServer, us));
	if (!us) {
		OSSafeReleaseNULL(inst);
		return kIOReturnError;
	}
	inst->ivars->serverName = us->copyProperty(gIOUserServerNameKey);
	if (!inst->ivars->serverName) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}

	inst->ivars->lock    = IOLockAlloc();
	if (!inst->ivars->lock) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}
	for (uint32_t idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
		inst->ivars->pending[idx] = OSArray::withCapacity(4);
		if (!inst->ivars->pending[idx]) {
			OSSafeReleaseNULL(inst);
			return kIOReturnNoMemory;
		}
	}
	inst->ivars->interestNotifiers = OSDictionary::withCapacity(4);
	if (!inst->ivars->interestNotifiers) {
		OSSafeReleaseNULL(inst);
		return kIOReturnNoMemory;
	}

	inst->ivars->notifier = IOService::addMatchingNotification(gIOMatchedNotification, matching, 0 /*priority*/,
	    ^bool (IOService * newService, IONotifier * notifier) {
		bool         notifyReady = false;
		IONotifier * interest;
		OSObject   * serverName;
		bool         okToUse;

		serverName = newService->copyProperty(gIOUserServerNameKey);
		okToUse = (serverName && inst->ivars->serverName->isEqualTo(serverName));
		OSSafeReleaseNULL(serverName);
		if (!okToUse) {
		        return false;
		}

		IOLockLock(inst->ivars->lock);
		notifyReady = (0 == inst->ivars->pending[kIOServiceNotificationTypeMatched]->getCount());
		inst->ivars->pending[kIOServiceNotificationTypeMatched]->setObject(newService);
		IOLockUnlock(inst->ivars->lock);

		interest = newService->registerInterest(gIOGeneralInterest,
		^IOReturn (uint32_t messageType, IOService * provider,
		void * messageArgument, size_t argSize) {
			IONotifier * interest;
			bool         notifyReady = false;

			switch (messageType) {
			case kIOMessageServiceIsTerminated:
				IOLockLock(inst->ivars->lock);
				notifyReady = (0 == inst->ivars->pending[kIOServiceNotificationTypeTerminated]->getCount());
				inst->ivars->pending[kIOServiceNotificationTypeTerminated]->setObject(provider);
				interest = (typeof(interest))inst->ivars->interestNotifiers->getObject((const OSSymbol *) newService);
				assert(interest);
				interest->remove();
				inst->ivars->interestNotifiers->removeObject((const OSSymbol *) newService);
				IOLockUnlock(inst->ivars->lock);
				break;
			default:
				break;
			}
			if (notifyReady && inst->ivars->action) {
			        inst->ServiceNotificationReady(inst->ivars->action);
			}
			return kIOReturnSuccess;
		});
		if (interest) {
		        IOLockLock(inst->ivars->lock);
		        inst->ivars->interestNotifiers->setObject((const OSSymbol *) newService, interest);
		        IOLockUnlock(inst->ivars->lock);
		}
		if (notifyReady) {
		        if (inst->ivars->action) {
		                inst->ServiceNotificationReady(inst->ivars->action);
			}
		}
		return false;
	});

	if (!inst->ivars->notifier) {
		OSSafeReleaseNULL(inst);
		ret = kIOReturnError;
	}

	*notification = inst;
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IMPL(IOServiceNotificationDispatchSource, CopyNextNotification)
{
	IOService * next;
	uint32_t    idx;

	IOLockLock(ivars->lock);
	for (idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
		next = (IOService *) ivars->pending[idx]->getObject(0);
		if (next) {
			next->retain();
			ivars->pending[idx]->removeObject(0);
			break;
		}
	}
	IOLockUnlock(ivars->lock);

	if (idx == kIOServiceNotificationTypeCount) {
		idx = kIOServiceNotificationTypeNone;
	}
	*type    = idx;
	*service = next;
	*options = 0;

	return kIOReturnSuccess;
}

bool
IOServiceNotificationDispatchSource::init()
{
	if (!super::init()) {
		return false;
	}
	ivars = IONewZero(IOServiceNotificationDispatchSource_IVars, 1);
	if (!ivars) {
		return false;
	}

	return true;
}

void
IOServiceNotificationDispatchSource::free()
{
	if (ivars) {
		OSSafeReleaseNULL(ivars->serverName);
		if (ivars->interestNotifiers) {
			ivars->interestNotifiers->iterateObjects(^bool (const OSSymbol * key, OSObject * object) {
				IONotifier * interest = (typeof(interest))object;
				interest->remove();
				return false;
			});
			OSSafeReleaseNULL(ivars->interestNotifiers);
		}
		for (uint32_t idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
			OSSafeReleaseNULL(ivars->pending[idx]);
		}
		if (ivars->lock) {
			IOLockFree(ivars->lock);
			ivars->lock = NULL;
		}
		if (ivars->notifier) {
			ivars->notifier->remove();
			ivars->notifier = NULL;
		}
		IOSafeDeleteNULL(ivars, IOServiceNotificationDispatchSource_IVars, 1);
	}

	super::free();
}

kern_return_t
IMPL(IOServiceNotificationDispatchSource, SetHandler)
{
	IOReturn ret;
	bool     notifyReady;

	notifyReady = false;

	IOLockLock(ivars->lock);
	OSSafeReleaseNULL(ivars->action);
	action->retain();
	ivars->action = action;
	if (action) {
		for (uint32_t idx = 0; idx < kIOServiceNotificationTypeCount; idx++) {
			notifyReady = (ivars->pending[idx]->getCount());
			if (notifyReady) {
				break;
			}
		}
	}
	IOLockUnlock(ivars->lock);

	if (notifyReady) {
		ServiceNotificationReady(action);
	}
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IMPL(IOServiceNotificationDispatchSource, SetEnableWithCompletion)
{
	if (enable == ivars->enable) {
		return kIOReturnSuccess;
	}

	IOLockLock(ivars->lock);
	ivars->enable = enable;
	IOLockUnlock(ivars->lock);

	return kIOReturnSuccess;
}

kern_return_t
IMPL(IOServiceNotificationDispatchSource, Cancel)
{
	return kIOReturnUnsupported;
}

kern_return_t
IMPL(IOServiceNotificationDispatchSource, CheckForWork)
{
	return kIOReturnNotReady;
}

kern_return_t
IOServiceNotificationDispatchSource::DeliverNotifications(IOServiceNotificationBlock block)
{
	return kIOReturnUnsupported;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOUserServer::waitInterruptTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)
{
	IOReturn         ret = kIOReturnBadArgument;
	IOInterruptState is;
	IOInterruptDispatchSource * interrupt;
	IOInterruptDispatchSource_IVars * ivars;
	IOInterruptDispatchSourcePayload payload;

	wait_result_t    waitResult;
	thread_t         self;

	OSObject * object;

	object = iokit_lookup_object_with_port_name((mach_port_name_t)(uintptr_t)p1, IKOT_UEXT_OBJECT, current_task());

	if (!object) {
		return kIOReturnBadArgument;
	}
	if (!(interrupt = OSDynamicCast(IOInterruptDispatchSource, object))) {
		ret = kIOReturnBadArgument;
	} else {
		self = current_thread();
		ivars = interrupt->ivars;
		payload.count = 0;
		do {
			is = IOSimpleLockLockDisableInterrupt(ivars->lock);
			if ((payload.count = ivars->count)) {
				payload.time = ivars->time;
				ivars->count = 0;
				waitResult = THREAD_AWAKENED;
			} else {
				assert(NULL == ivars->waiter);
				ivars->waiter = self;
				waitResult = assert_wait((event_t) ivars, THREAD_INTERRUPTIBLE);
			}
			IOSimpleLockUnlockEnableInterrupt(ivars->lock, is);
			if (waitResult == THREAD_WAITING) {
				waitResult = thread_block(THREAD_CONTINUE_NULL);
				if (THREAD_INTERRUPTED == waitResult) {
					break;
				}
			}
		} while (!payload.count);
		ret = (payload.count ? kIOReturnSuccess : kIOReturnAborted);
	}

	if (kIOReturnSuccess == ret) {
		int copyerr = copyout(&payload, (user_addr_t) p2, sizeof(payload));
		if (copyerr) {
			ret = kIOReturnVMError;
		}
	}

	object->release();

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IOUserServer, Create)
{
	IOReturn          ret;
	IOUserServer    * us;
	const OSSymbol  * sym;
	OSNumber        * serverTag;
	io_name_t         rname;

	us = (typeof(us))thread_iokit_tls_get(0);
	assert(OSDynamicCast(IOUserServer, us));
	if (kIODKLogSetup & gIODKDebug) {
		DKLOG(DKS "::Create(" DKS ") %p\n", DKN(us), name, tag, us);
	}
	if (!us) {
		return kIOReturnError;
	}

	sym       = OSSymbol::withCString(name);
	serverTag = OSNumber::withNumber(tag, 64);

	us->setProperty(gIOUserServerNameKey, (OSObject *) sym);
	us->setProperty(gIOUserServerTagKey, serverTag);

	serverTag->release();
	OSSafeReleaseNULL(sym);

	snprintf(rname, sizeof(rname), "IOUserServer(%s-0x%qx)", name, tag);
	us->setName(rname);

	us->retain();
	*server = us;
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IMPL(IOUserServer, Exit)
{
	return kIOReturnUnsupported;
}

kern_return_t
IMPL(IOUserServer, LoadModule)
{
	return kIOReturnUnsupported;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
IMPL(IODispatchQueue, Create)
{
	IODispatchQueue * result;
	IOUserServer    * us;

	result = OSTypeAlloc(IODispatchQueue);
	if (!result) {
		return kIOReturnNoMemory;
	}
	if (!result->init()) {
		return kIOReturnNoMemory;
	}

	*queue = result;

	if (!strcmp("Root", name)) {
		us = (typeof(us))thread_iokit_tls_get(0);
		assert(OSDynamicCast(IOUserServer, us));
		us->setRootQueue(result);
	}

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("IODispatchQueue::Create %s %p\n", name, result);
	}

	return kIOReturnSuccess;
}

kern_return_t
IMPL(IODispatchQueue, SetPort)
{
	if (MACH_PORT_NULL != ivars->serverPort) {
		return kIOReturnNotReady;
	}

	ivars->serverPort = port;
	return kIOReturnSuccess;
}

bool
IODispatchQueue::init()
{
	ivars = IONewZero(IODispatchQueue_IVars, 1);
	if (!ivars) {
		return false;
	}
	ivars->queue = this;

	return true;
}

void
IODispatchQueue::free()
{
	if (ivars && ivars->serverPort) {
		ipc_port_release_send(ivars->serverPort);
		ivars->serverPort = MACH_PORT_NULL;
	}
	IOSafeDeleteNULL(ivars, IODispatchQueue_IVars, 1);
	super::free();
}

bool
IODispatchQueue::OnQueue()
{
	return false;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


kern_return_t
OSMetaClassBase::Dispatch(IORPC rpc)
{
	return kIOReturnUnsupported;
}

kern_return_t
OSMetaClassBase::Invoke(IORPC rpc)
{
	IOReturn          ret = kIOReturnUnsupported;
	OSMetaClassBase * object;
	OSAction        * action;
	IOService       * service;
	IOUserServer    * us;
	IORPCMessage    * message;

	assert(rpc.sendSize >= (sizeof(IORPCMessageMach) + sizeof(IORPCMessage)));
	message = IORPCMessageFromMach(rpc.message, false);
	if (!message) {
		return kIOReturnIPCError;
	}
	message->flags |= kIORPCMessageKernel;

	us = NULL;
	if (!(kIORPCMessageLocalHost & message->flags)) {
		us = OSDynamicCast(IOUserServer, this);
		if (!us) {
			if ((action = OSDynamicCast(OSAction, this))) {
				object = IOUserServer::target(action, message);
			} else {
				object = this;
			}
			if ((service = OSDynamicCast(IOService, object))
			    && service->reserved->uvars) {
				// xxx other classes
				us = service->reserved->uvars->userServer;
			}
		}
	}
	if (us) {
		message->flags |= kIORPCMessageRemote;
		ret = us->rpc(rpc);
		if (kIOReturnSuccess != ret) {
			if (kIODKLogIPC & gIODKDebug) {
				DKLOG("OSMetaClassBase::Invoke user 0x%x\n", ret);
			}
		}
	} else {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("OSMetaClassBase::Invoke kernel %s 0x%qx\n", getMetaClass()->getClassName(), message->msgid);
		}
		ret = Dispatch(rpc);
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOPStrings {
	uint32_t     dataSize;
	uint32_t     count;
	const char   strings[0];
};

kern_return_t
OSUserMetaClass::Dispatch(IORPC rpc)
{
	if (meta) {
		return const_cast<OSMetaClass *>(meta)->Dispatch(rpc);
	} else {
		return kIOReturnUnsupported;
	}
}

void
OSUserMetaClass::free()
{
	if (queueNames) {
		IOFree(queueNames, sizeof(IOPStrings) + queueNames->dataSize * sizeof(char));
		queueNames = NULL;
	}
	if (description) {
		IOFree(description, description->descriptionSize);
		description = NULL;
	}
	IOSafeDeleteNULL(methods, uint64_t, 2 * methodCount);
	if (meta) {
		meta->releaseMetaClass();
	}
	if (name) {
		name->release();
	}
	OSObject::free();
}

/*
 * Sets the loadTag of the associated OSKext
 * in the dext task.
 * NOTE: different instances of the same OSKext
 * (so same BounleID but different tasks)
 * will have the same loadTag.
 */
void
IOUserServer::setTaskLoadTag(OSKext *kext)
{
	task_t owningTask;
	uint32_t loadTag, prev_taskloadTag;

	owningTask = this->fOwningTask;
	if (!owningTask) {
		printf("%s: fOwningTask not found\n", __FUNCTION__);
		return;
	}

	loadTag = kext->getLoadTag();
	prev_taskloadTag = set_task_loadTag(owningTask, loadTag);
	if (prev_taskloadTag) {
		printf("%s: found the task loadTag already set to %u (set to %u)\n",
		    __FUNCTION__, prev_taskloadTag, loadTag);
	}
}

/*
 * Sets the OSKext uuid as the uuid of the userspace
 * dext executable.
 */
void
IOUserServer::setDriverKitUUID(OSKext *kext)
{
	task_t task;
	proc_t p;
	uuid_t p_uuid, k_uuid;
	OSData *k_data_uuid;
	OSData *new_uuid;
	uuid_string_t       uuid_string = "";

	task = this->fOwningTask;
	if (!task) {
		printf("%s: fOwningTask not found\n", __FUNCTION__);
		return;
	}

	p = (proc_t)(get_bsdtask_info(task));
	if (!p) {
		printf("%s: proc not found\n", __FUNCTION__);
		return;
	}
	proc_getexecutableuuid(p, p_uuid, sizeof(p_uuid));

	k_data_uuid = kext->copyUUID();
	if (k_data_uuid) {
		memcpy(&k_uuid, k_data_uuid->getBytesNoCopy(), sizeof(k_uuid));
		OSSafeReleaseNULL(k_data_uuid);
		if (uuid_compare(k_uuid, p_uuid) != 0) {
			printf("%s: uuid not matching\n", __FUNCTION__);
		}
		return;
	}

	uuid_unparse(p_uuid, uuid_string);
	new_uuid = OSData::withBytes(p_uuid, sizeof(p_uuid));
	kext->setDriverKitUUID(new_uuid);
}

bool
IOUserServer::serviceMatchesCDHash(IOService *service)
{
	OSObject   *obj               = NULL;
	bool        result            = false;
	OSString   *requiredCDHashStr = NULL;
	const char *requiredCDHash    = NULL;
	char        taskCDHash[CS_CDHASH_LEN];

	task_t owningTask = this->fOwningTask;
	if (!owningTask) {
		printf("%s: fOwningTask not found\n", __FUNCTION__);
		goto out;
	}

	obj = service->copyProperty(gIOUserServerCDHashKey);
	requiredCDHashStr = OSDynamicCast(OSString, obj);
	if (!requiredCDHashStr) {
		printf("%s: required cdhash not found as property of personality\n", __FUNCTION__);
		goto out;
	}

	requiredCDHash = requiredCDHashStr->getCStringNoCopy();
	if (!requiredCDHash) {
		printf("%s: required cdhash unable to be read as string\n", __FUNCTION__);
		goto out;
	}

	if (strlen(requiredCDHash) != CS_CDHASH_LEN * 2) {
		printf("%s: required cdhash string has incorrect length\n", __FUNCTION__);
		goto out;
	}

	get_task_cdhash(owningTask, taskCDHash);
	for (int i = 0; i < (int)CS_CDHASH_LEN * 2; i++) {
		uint8_t which  = (i + 1) & 0x1; /* 1 for upper nibble, 0 for lower */
		uint8_t nibble = requiredCDHash[i];
		uint8_t byte   = taskCDHash[i / 2];
		if ('0' <= nibble && nibble <= '9') {
			nibble -= '0';
		} else if ('a' <= nibble && nibble <= 'f') {
			nibble -= 'a' - 10;
		} else if ('A' <= nibble && nibble <= 'F') {
			nibble -= 'A' - 10;
		} else {
			printf("%s: required cdhash contains invalid token '%c'\n", __FUNCTION__, nibble);
			goto out;
		}

		/*
		 * Decide which half of the byte to compare
		 */
		if (nibble != (which ? (byte >> 4) : (byte & 0x0f))) {
			printf("%s: required cdhash %s in personality does not match service\n", __FUNCTION__, requiredCDHash);
			goto out;
		}
	}

	result = true;
out:
	OSSafeReleaseNULL(obj);
	return result;
}

bool
IOUserServer::checkEntitlements(
	OSDictionary * entitlements, OSObject * prop,
	IOService * provider, IOService * dext)
{
	OSDictionary * matching;

	if (!prop) {
		return true;
	}
	if (!entitlements) {
		return false;
	}

	matching = NULL;
	if (dext) {
		matching = dext->dictionaryWithProperties();
		if (!matching) {
			return false;
		}
	}

	bool allPresent __block;
	prop->iterateObjects(^bool (OSObject * object) {
		allPresent = false;
		object->iterateObjects(^bool (OSObject * object) {
			OSString * string;
			OSObject * value;
			string = OSDynamicCast(OSString, object);
			value = entitlements->getObject(string);
			if (matching && value) {
			        matching->setObject(string, value);
			}
			allPresent = (NULL != value);
			return !allPresent;
		});
		return allPresent;
	});

	if (allPresent && matching && provider) {
		allPresent = provider->matchPropertyTable(matching);
	}

	OSSafeReleaseNULL(matching);
	OSSafeReleaseNULL(prop);

	return allPresent;
}

bool
IOUserServer::checkEntitlements(IOService * provider, IOService * dext)
{
	OSObject     * prop;
	bool           ok;

	if (!fOwningTask) {
		return false;
	}

	prop = provider->copyProperty(gIOServiceDEXTEntitlementsKey);
	ok = checkEntitlements(fEntitlements, prop, provider, dext);
	if (!ok) {
		DKLOG(DKS ": provider entitlements check failed\n", DKN(dext));
	}
	if (ok) {
		prop = dext->copyProperty(gIOServiceDEXTEntitlementsKey);
		ok = checkEntitlements(fEntitlements, prop, NULL, NULL);
		if (!ok) {
			DKLOG(DKS ": family entitlements check failed\n", DKN(dext));
		}
	}

	return ok;
}

IOReturn
IOUserServer::exit(const char * reason)
{
	DKLOG("%s::exit(%s)\n", getName(), reason);
	Exit(reason);
	return kIOReturnSuccess;
}

OSObjectUserVars *
IOUserServer::varsForObject(OSObject * obj)
{
	IOService * service;

	if ((service = OSDynamicCast(IOService, obj))) {
		return service->reserved->uvars;
	}

	return NULL;
}

IOPStrings *
IOUserServer::copyInStringArray(const char * string, uint32_t userSize)
{
	IOPStrings * array;
	vm_size_t    alloc;
	size_t       len;
	const char * cstr;
	const char * end;

	if (userSize <= 1) {
		return NULL;
	}

	if (os_add_overflow(sizeof(IOPStrings), userSize, &alloc)) {
		assert(false);
		return NULL;
	}
	if (alloc > 16384) {
		assert(false);
		return NULL;
	}
	array = (typeof(array))IOMalloc(alloc);
	if (!array) {
		return NULL;
	}
	array->dataSize = userSize;
	bcopy(string, (void *) &array->strings[0], userSize);

	array->count = 0;
	cstr = &array->strings[0];
	end =  &array->strings[array->dataSize];
	while ((len = (unsigned char)cstr[0])) {
		cstr++;
		if ((cstr + len) >= end) {
			break;
		}
		cstr += len;
		array->count++;
	}
	if (len) {
		IOFree(array, alloc);
		array = NULL;
	}

	return array;
}

uint32_t
IOUserServer::stringArrayIndex(IOPStrings * array, const char * look)
{
	uint32_t     idx;
	size_t       len, llen;
	const char * cstr;
	const char * end;

	idx  = 0;
	cstr = &array->strings[0];
	end  =  &array->strings[array->dataSize];
	llen = strlen(look);
	while ((len = (unsigned char)cstr[0])) {
		cstr++;
		if ((cstr + len) >= end) {
			break;
		}
		if ((len == llen) && !strncmp(cstr, look, len)) {
			return idx;
		}
		cstr += len;
		idx++;
	}

	return -1U;
}
#define kIODispatchQueueStopped ((IODispatchQueue *) -1L)

IODispatchQueue *
IOUserServer::queueForObject(OSObject * obj, uint64_t msgid)
{
	IODispatchQueue  * queue;
	OSObjectUserVars * uvars;
	uint64_t           option;

	uvars = varsForObject(obj);
	if (!uvars) {
		return NULL;
	}
	if (!uvars->queueArray) {
		if (uvars->stopped) {
			return kIODispatchQueueStopped;
		}
		return NULL;
	}
	queue = uvars->queueArray[0];

	if (uvars->userMeta
	    && uvars->userMeta->methods) {
		uint32_t idx, baseIdx;
		uint32_t lim;
		// bsearch
		for (baseIdx = 0, lim = uvars->userMeta->methodCount; lim; lim >>= 1) {
			idx = baseIdx + (lim >> 1);
			if (msgid == uvars->userMeta->methods[idx]) {
				option = uvars->userMeta->methods[uvars->userMeta->methodCount + idx];
				option &= 0xFF;
				if (option < uvars->userMeta->queueNames->count) {
					queue = uvars->queueArray[option + 1];
				}
				break;
			} else if (msgid > uvars->userMeta->methods[idx]) {
				// move right
				baseIdx += (lim >> 1) + 1;
				lim--;
			}
			// else move left
		}
	}
	return queue;
}

IOReturn
IOUserServer::objectInstantiate(OSObject * obj, IORPC rpc, IORPCMessage * message)
{
	IOReturn         ret;
	OSString       * str;
	OSObject       * prop;
	IOService      * service;

	OSAction       * action;
	OSObject       * target;
	uint32_t         queueCount, queueAlloc;
	const char     * resultClassName;
	uint64_t         resultFlags;

	size_t             replySize;
	uint32_t           methodCount;
	const uint64_t   * methods;
	IODispatchQueue  * queue;
	OSUserMetaClass  * userMeta;
	OSObjectUserVars * uvars;
	uint32_t           idx;
	ipc_port_t         sendPort;

	OSObject_Instantiate_Rpl_Content * reply;

	queueCount      = 0;
	methodCount     = 0;
	methods         = NULL;
	str             = NULL;
	prop            = NULL;
	userMeta        = NULL;
	resultClassName = NULL;
	resultFlags     = 0;
	ret = kIOReturnUnsupportedMode;

	service = OSDynamicCast(IOService, obj);
	if (!service) {
		// xxx other classes hosted
		resultFlags |= kOSObjectRPCKernel;
		resultFlags |= kOSObjectRPCRemote;
	} else {
		if (service->isInactive()) {
			DKLOG(DKS "::instantiate inactive\n", DKN(service));
			return kIOReturnOffline;
		}
		prop = service->copyProperty(gIOUserClassKey);
		str = OSDynamicCast(OSString, prop);
		if (!service->reserved->uvars) {
			resultFlags |= kOSObjectRPCRemote;
			resultFlags |= kOSObjectRPCKernel;
		} else if (this != service->reserved->uvars->userServer) {
			// remote, use base class
			resultFlags |= kOSObjectRPCRemote;
		}
		if (service->reserved->uvars && service->reserved->uvars->userServer) {
			IOLockLock(service->reserved->uvars->userServer->fLock);
			userMeta = (typeof(userMeta))service->reserved->uvars->userServer->fClasses->getObject(str);
			IOLockUnlock(service->reserved->uvars->userServer->fLock);
		}
	}
	if (!str && !userMeta) {
		const OSMetaClass * meta;
		meta = obj->getMetaClass();
		IOLockLock(fLock);
		while (meta && !userMeta) {
			str = (OSString *) meta->getClassNameSymbol();
			userMeta = (typeof(userMeta))fClasses->getObject(str);
			if (!userMeta) {
				meta = meta->getSuperClass();
			}
		}
		IOLockUnlock(fLock);
	}
	if (str) {
		if (!userMeta) {
			IOLockLock(fLock);
			userMeta = (typeof(userMeta))fClasses->getObject(str);
			IOLockUnlock(fLock);
		}
		if (kIODKLogSetup & gIODKDebug) {
			DKLOG("userMeta %s %p\n", str->getCStringNoCopy(), userMeta);
		}
		if (userMeta) {
			if (kOSObjectRPCRemote & resultFlags) {
				while (userMeta && !(kOSClassCanRemote & userMeta->description->flags)) {
					userMeta = userMeta->superMeta;
				}
				if (userMeta) {
					resultClassName = userMeta->description->name;
					ret = kIOReturnSuccess;
				}
			} else {
				service->reserved->uvars->userMeta = userMeta;
				queueAlloc = 1;
				if (userMeta->queueNames) {
					queueAlloc += userMeta->queueNames->count;
				}
				service->reserved->uvars->queueArray =
				    IONewZero(IODispatchQueue *, queueAlloc);
				resultClassName = str->getCStringNoCopy();
				ret = kIOReturnSuccess;
			}
		}
	}
	OSSafeReleaseNULL(prop);

	IORPCMessageMach * machReply = rpc.reply;
	replySize = sizeof(OSObject_Instantiate_Rpl);

	if ((kIOReturnSuccess == ret) && (kOSObjectRPCRemote & resultFlags)) {
		target = obj;
		if ((action = OSDynamicCast(OSAction, obj))) {
			if (action->ivars->referenceSize) {
				resultFlags |= kOSObjectRPCKernel;
			} else {
				resultFlags &= ~kOSObjectRPCKernel;
				target = action->ivars->target;

				queueCount = 1;
				queue = queueForObject(target, action->ivars->targetmsgid);
				idx = 0;
				sendPort = NULL;
				if (queue && (kIODispatchQueueStopped != queue)) {
					sendPort = ipc_port_copy_send(queue->ivars->serverPort);
				}
				replySize = sizeof(OSObject_Instantiate_Rpl)
				    + queueCount * sizeof(machReply->objects[0])
				    + 2 * methodCount * sizeof(reply->methods[0]);
				if (replySize > rpc.replySize) {
					assert(false);
					return kIOReturnIPCError;
				}
				machReply->objects[idx].type        = MACH_MSG_PORT_DESCRIPTOR;
				machReply->objects[idx].disposition = MACH_MSG_TYPE_MOVE_SEND;
				machReply->objects[idx].name        = sendPort;
				machReply->objects[idx].pad2        = 0;
				machReply->objects[idx].pad_end     = 0;
			}
		} else {
			uvars = varsForObject(target);
			if (uvars && uvars->userMeta) {
				queueCount = 1;
				if (uvars->userMeta->queueNames) {
					queueCount += uvars->userMeta->queueNames->count;
				}
				methods = &uvars->userMeta->methods[0];
				methodCount = uvars->userMeta->methodCount;
				replySize = sizeof(OSObject_Instantiate_Rpl)
				    + queueCount * sizeof(machReply->objects[0])
				    + 2 * methodCount * sizeof(reply->methods[0]);
				if (replySize > rpc.replySize) {
					assert(false);
					return kIOReturnIPCError;
				}
				for (idx = 0; idx < queueCount; idx++) {
					queue = uvars->queueArray[idx];
					sendPort = NULL;
					if (queue) {
						sendPort = ipc_port_copy_send(queue->ivars->serverPort);
					}
					machReply->objects[idx].type        = MACH_MSG_PORT_DESCRIPTOR;
					machReply->objects[idx].disposition = MACH_MSG_TYPE_MOVE_SEND;
					machReply->objects[idx].name        = sendPort;
					machReply->objects[idx].pad2        = 0;
					machReply->objects[idx].pad_end     = 0;
				}
			}
		}
	}

	if (kIODKLogIPC & gIODKDebug) {
		DKLOG("instantiate %s\n", obj->getMetaClass()->getClassName());
	}

	if (kIOReturnSuccess != ret) {
		DKLOG("%s: no user class found\n", str ? str->getCStringNoCopy() : obj->getMetaClass()->getClassName());
		resultClassName = "unknown";
	}

	machReply->msgh.msgh_id                    = kIORPCVersionCurrentReply;
	machReply->msgh.msgh_size                  = replySize;
	machReply->msgh_body.msgh_descriptor_count = queueCount;

	reply = (typeof(reply))IORPCMessageFromMach(machReply, true);
	if (!reply) {
		return kIOReturnIPCError;
	}
	if (methodCount) {
		bcopy(methods, &reply->methods[0], methodCount * 2 * sizeof(reply->methods[0]));
	}
	reply->__hdr.msgid       = OSObject_Instantiate_ID;
	reply->__hdr.flags       = kIORPCMessageOneway;
	reply->__hdr.objectRefs  = 0;
	reply->__pad             = 0;
	reply->flags             = resultFlags;
	strlcpy(reply->classname, resultClassName, sizeof(reply->classname));
	reply->__result          = ret;

	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::kernelDispatch(OSObject * obj, IORPC rpc)
{
	IOReturn       ret;
	IORPCMessage * message;

	message = IORPCMessageFromMach(rpc.message, false);
	if (!message) {
		return kIOReturnIPCError;
	}

	if (OSObject_Instantiate_ID == message->msgid) {
		ret = objectInstantiate(obj, rpc, message);
		if (kIOReturnSuccess != ret) {
			DKLOG("%s: instantiate failed 0x%x\n", obj->getMetaClass()->getClassName(), ret);
		}
	} else {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch kernel 0x%qx\n", obj->getMetaClass()->getClassName(), message->msgid);
		}
		ret = obj->Dispatch(rpc);
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch kernel 0x%qx result 0x%x\n", obj->getMetaClass()->getClassName(), message->msgid, ret);
		}
	}

	return ret;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

OSObject *
IOUserServer::target(OSAction * action, IORPCMessage * message)
{
	OSObject * object;

	if (message->msgid != action->ivars->msgid) {
		return action;
	}
	object              = action->ivars->target;
	message->msgid      = action->ivars->targetmsgid;
	message->objects[0] = (OSObjectRef) object;
	if (kIORPCMessageRemote & message->flags) {
		object->retain();
		action->release();
	}
	if (kIODKLogIPC & gIODKDebug) {
		DKLOG("TARGET %s msg 0x%qx from 0x%qx\n", object->getMetaClass()->getClassName(), message->msgid, action->ivars->msgid);
	}

	return object;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

kern_return_t
uext_server(ipc_kmsg_t requestkmsg, ipc_kmsg_t * pReply)
{
	kern_return_t      ret;
	IORPCMessageMach * msgin;
	OSObject         * object;
	IOUserServer     * server;

	msgin   = (typeof(msgin))ipc_kmsg_msg_header(requestkmsg);

	object = IOUserServer::copyObjectForSendRight(msgin->msgh.msgh_remote_port, IKOT_UEXT_OBJECT);
	server = OSDynamicCast(IOUserServer, object);
	if (!server) {
		OSSafeReleaseNULL(object);
		return KERN_INVALID_NAME;
	}
	ret = server->server(requestkmsg, pReply);
	object->release();

	return ret;
}

#define MAX_UEXT_REPLY_SIZE     0x17c0

kern_return_t
IOUserServer::server(ipc_kmsg_t requestkmsg, ipc_kmsg_t * pReply)
{
	kern_return_t      ret;
	mach_msg_size_t    replyAlloc;
	ipc_kmsg_t         replykmsg;
	IORPCMessageMach * msgin;
	IORPCMessage     * message;
	IORPCMessageMach * msgout;
	IORPCMessage     * reply;
	uint32_t           replySize;
	OSObject         * object;
	OSAction         * action;
	bool               oneway;
	uint64_t           msgid;

	msgin   = (typeof(msgin))ipc_kmsg_msg_header(requestkmsg);
	replyAlloc = 0;
	msgout = NULL;
	replykmsg = NULL;

	if (msgin->msgh.msgh_size < (sizeof(IORPCMessageMach) + sizeof(IORPCMessage))) {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("UEXT notify %o\n", msgin->msgh.msgh_id);
		}
		return KERN_NOT_SUPPORTED;
	}

	if (!(MACH_MSGH_BITS_COMPLEX & msgin->msgh.msgh_bits)) {
		msgin->msgh_body.msgh_descriptor_count = 0;
	}
	message = IORPCMessageFromMach(msgin, false);
	if (!message) {
		return kIOReturnIPCError;
	}
	if (message->objectRefs == 0) {
		return kIOReturnIPCError;
	}
	ret = copyInObjects(msgin, message, msgin->msgh.msgh_size, true, false);
	if (kIOReturnSuccess != ret) {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("UEXT copyin(0x%x) %x\n", ret, msgin->msgh.msgh_id);
		}
		return KERN_NOT_SUPPORTED;
	}

	if (msgin->msgh_body.msgh_descriptor_count < 1) {
		return KERN_NOT_SUPPORTED;
	}
	object = (OSObject *) message->objects[0];
	msgid = message->msgid;
	message->flags &= ~kIORPCMessageKernel;
	message->flags |= kIORPCMessageRemote;

	if ((action = OSDynamicCast(OSAction, object))) {
		object = target(action, message);
		msgid  = message->msgid;
	}

	oneway = (0 != (kIORPCMessageOneway & message->flags));
	assert(oneway || (MACH_PORT_NULL != msgin->msgh.msgh_local_port));

	// includes trailer size
	replyAlloc = oneway ? 0 : MAX_UEXT_REPLY_SIZE;
	if (replyAlloc) {
		replykmsg = ipc_kmsg_alloc(replyAlloc);
		if (replykmsg == NULL) {
//			printf("uext_server: dropping request\n");
			//	ipc_kmsg_trace_send(request, option);
			consumeObjects(message, msgin->msgh.msgh_size);
			ipc_kmsg_destroy(requestkmsg);
			return KERN_MEMORY_FAILURE;
		}

		msgout = (typeof(msgout))ipc_kmsg_msg_header(replykmsg);
		/*
		 * MIG should really assure no data leakage -
		 * but until it does, pessimistically zero the
		 * whole reply buffer.
		 */
		bzero((void *)msgout, replyAlloc);
	}

	IORPC rpc = { .message = msgin, .reply = msgout, .sendSize = msgin->msgh.msgh_size, .replySize = replyAlloc };

	if (object) {
		thread_iokit_tls_set(0, this);
		ret = kernelDispatch(object, rpc);
		thread_iokit_tls_set(0, NULL);
	} else {
		ret = kIOReturnBadArgument;
	}

	// release objects
	consumeObjects(message, msgin->msgh.msgh_size);

	// release ports
	copyInObjects(msgin, message, msgin->msgh.msgh_size, false, true);

	if (!oneway) {
		if (kIOReturnSuccess == ret) {
			replySize = msgout->msgh.msgh_size;
			reply = IORPCMessageFromMach(msgout, true);
			if (!reply) {
				ret = kIOReturnIPCError;
			} else {
				ret = copyOutObjects(msgout, reply, replySize, (kIORPCVersionCurrentReply == msgout->msgh.msgh_id) /* =>!InvokeReply */);
			}
		}
		if (kIOReturnSuccess != ret) {
			IORPCMessageErrorReturnContent * errorMsg;

			msgout->msgh_body.msgh_descriptor_count = 0;
			msgout->msgh.msgh_id                    = kIORPCVersionCurrentReply;
			errorMsg = (typeof(errorMsg))IORPCMessageFromMach(msgout, true);
			errorMsg->hdr.msgid      = message->msgid;
			errorMsg->hdr.flags      = kIORPCMessageOneway | kIORPCMessageError;
			errorMsg->hdr.objectRefs = 0;
			errorMsg->result         = ret;
			errorMsg->pad            = 0;
			replySize                = sizeof(IORPCMessageErrorReturn);
		}

		msgout->msgh.msgh_bits = MACH_MSGH_BITS_COMPLEX |
		    MACH_MSGH_BITS_SET(MACH_MSGH_BITS_LOCAL(msgin->msgh.msgh_bits) /*remote*/, 0 /*local*/, 0, 0);

		msgout->msgh.msgh_remote_port  = msgin->msgh.msgh_local_port;
		msgout->msgh.msgh_local_port   = MACH_PORT_NULL;
		msgout->msgh.msgh_voucher_port = (mach_port_name_t) 0;
		msgout->msgh.msgh_reserved     = 0;
		msgout->msgh.msgh_size         = replySize;
	}

	*pReply = replykmsg;

	return oneway ? MIG_NO_REPLY : KERN_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

#define MAX_OBJECT_COUNT(mach, size, message) \
	((((size) + ((uintptr_t) (mach))) - ((uintptr_t) (&message->objects[0]))) / sizeof(OSObjectRef))

kern_return_t
IOUserServerUEXTTrap(OSObject * object, void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)
{
	const user_addr_t msg              = (uintptr_t) p1;
	size_t            inSize           = (uintptr_t) p2;
	user_addr_t       out              = (uintptr_t) p3;
	size_t            outSize          = (uintptr_t) p4;
	mach_port_name_t  objectName1      = (uintptr_t) p5;
	size_t            totalSize;
	OSObject        * objectArg1;

	IORPCMessageMach *  mach;
	mach_msg_port_descriptor_t * descs;

#pragma pack(4)
	struct {
		uint32_t                   pad;
		IORPCMessageMach           mach;
		mach_msg_port_descriptor_t objects[2];
		IOTrapMessageBuffer        buffer;
	} buffer;
#pragma pack()

	IOReturn           ret;
	OSAction         * action;
	int                copyerr;
	IORPCMessage     * message;
	IORPCMessage     * reply;
	IORPC              rpc;
	uint64_t           refs;
	uint32_t           maxObjectCount;
	size_t             copySize;
	uint64_t         * replyHdr;
	uintptr_t          p;

	bzero(&buffer, sizeof(buffer));

	p = (typeof(p)) & buffer.buffer[0];
	if (os_add_overflow(inSize, outSize, &totalSize)) {
		return kIOReturnMessageTooLarge;
	}
	if (totalSize > sizeof(buffer.buffer)) {
		return kIOReturnMessageTooLarge;
	}
	if (inSize < sizeof(IORPCMessage)) {
		return kIOReturnIPCError;
	}
	copyerr = copyin(msg, &buffer.buffer[0], inSize);
	if (copyerr) {
		return kIOReturnVMError;
	}

	message = (typeof(message))p;
	refs    = message->objectRefs;
	if ((refs > 2) || !refs) {
		return kIOReturnUnsupported;
	}
	if (!(kIORPCMessageSimpleReply & message->flags)) {
		return kIOReturnUnsupported;
	}

	descs = (typeof(descs))(p - refs * sizeof(*descs));
	mach  = (typeof(mach))(p - refs * sizeof(*descs) - sizeof(*mach));

	mach->msgh.msgh_id   = kIORPCVersionCurrent;
	mach->msgh.msgh_size = sizeof(IORPCMessageMach) + refs * sizeof(*descs) + inSize;
	mach->msgh_body.msgh_descriptor_count = refs;

	rpc.message   = mach;
	rpc.sendSize  = mach->msgh.msgh_size;
	rpc.reply     = (IORPCMessageMach *) (p + inSize);
	rpc.replySize = sizeof(buffer.buffer) - inSize;

	message->objects[0] = 0;
	if ((action = OSDynamicCast(OSAction, object))) {
		maxObjectCount = MAX_OBJECT_COUNT(rpc.message, rpc.sendSize, message);
		if (refs > maxObjectCount) {
			return kIOReturnBadArgument;
		}
		object = IOUserServer::target(action, message);
		message->objects[1] = (OSObjectRef) action;
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch(trap) kernel 0x%qx\n", object->getMetaClass()->getClassName(), message->msgid);
		}
		ret = object->Dispatch(rpc);
	} else {
		objectArg1 = NULL;
		if (refs > 1) {
			if (objectName1) {
				objectArg1 = iokit_lookup_uext_ref_current_task(objectName1);
				if (!objectArg1) {
					return kIOReturnIPCError;
				}
			}
			message->objects[1] = (OSObjectRef) objectArg1;
		}
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch(trap) kernel 0x%qx\n", object->getMetaClass()->getClassName(), message->msgid);
		}
		ret = object->Dispatch(rpc);
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("%s::Dispatch(trap) kernel 0x%qx 0x%x\n", object->getMetaClass()->getClassName(), message->msgid, ret);
		}
		OSSafeReleaseNULL(objectArg1);

		if (kIOReturnSuccess == ret) {
			if (rpc.reply->msgh_body.msgh_descriptor_count) {
				return kIOReturnIPCError;
			}
			reply = IORPCMessageFromMach(rpc.reply, rpc.reply->msgh.msgh_size);
			if (!reply) {
				return kIOReturnIPCError;
			}
			copySize = rpc.reply->msgh.msgh_size - (((uintptr_t) reply) - ((uintptr_t) rpc.reply)) + sizeof(uint64_t);
			if (copySize > outSize) {
				return kIOReturnIPCError;
			}
			replyHdr = (uint64_t *) reply;
			replyHdr--;
			replyHdr[0] = copySize;
			copyerr = copyout(replyHdr, out, copySize);
			if (copyerr) {
				return kIOReturnVMError;
			}
		}
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::rpc(IORPC rpc)
{
	if (isInactive() && !fRootQueue) {
		return kIOReturnOffline;
	}

	IOReturn           ret;
	IORPCMessage     * message;
	IORPCMessageMach * mach;
	mach_msg_id_t      machid;
	uint32_t           sendSize, replySize;
	bool               oneway;
	uint64_t           msgid;
	IODispatchQueue  * queue;
	IOService        * service;
	ipc_port_t         port;
	ipc_port_t         sendPort;

	queue    = NULL;
	port     = NULL;
	sendPort = NULL;

	mach      = rpc.message;
	sendSize  = rpc.sendSize;
	replySize = rpc.replySize;

	assert(sendSize >= (sizeof(IORPCMessageMach) + sizeof(IORPCMessage)));

	message = IORPCMessageFromMach(mach, false);
	if (!message) {
		ret = kIOReturnIPCError;
	}
	msgid   = message->msgid;
	machid  = (msgid >> 32);

	if (mach->msgh_body.msgh_descriptor_count < 1) {
		return kIOReturnNoMedia;
	}

	IOLockLock(gIOUserServerLock);
	if ((service = OSDynamicCast(IOService, (OSObject *) message->objects[0]))) {
		queue = queueForObject(service, msgid);
	}
	if (!queue) {
		queue = fRootQueue;
	}
	if (queue && (kIODispatchQueueStopped != queue)) {
		port = queue->ivars->serverPort;
	}
	if (port) {
		sendPort = ipc_port_copy_send(port);
	}
	IOLockUnlock(gIOUserServerLock);
	if (!sendPort) {
		return kIOReturnNotReady;
	}

	oneway = (0 != (kIORPCMessageOneway & message->flags));

	ret = copyOutObjects(mach, message, sendSize, false);

	mach->msgh.msgh_bits = MACH_MSGH_BITS_COMPLEX |
	    MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, (oneway ? 0 : MACH_MSG_TYPE_MAKE_SEND_ONCE));
	mach->msgh.msgh_remote_port  = sendPort;
	mach->msgh.msgh_local_port   = (oneway ? MACH_PORT_NULL : mig_get_reply_port());
	mach->msgh.msgh_id           = kIORPCVersionCurrent;
	mach->msgh.msgh_reserved     = 0;

	boolean_t message_moved;

	if (oneway) {
		ret = kernel_mach_msg_send(&mach->msgh, sendSize,
		    MACH_SEND_MSG | MACH_SEND_ALWAYS | MACH_SEND_NOIMPORTANCE,
		    0, &message_moved);
	} else {
		assert(replySize >= (sizeof(IORPCMessageMach) + sizeof(IORPCMessage)));
		ret = kernel_mach_msg_rpc(&mach->msgh, sendSize, replySize, FALSE, &message_moved);
	}

	ipc_port_release_send(sendPort);

	if (MACH_MSG_SUCCESS != ret) {
		if (kIODKLogIPC & gIODKDebug) {
			DKLOG("mach_msg() failed 0x%x\n", ret);
		}
		if (!message_moved) {
			// release ports
			copyInObjects(mach, message, sendSize, false, true);
		}
	}

	if ((KERN_SUCCESS == ret) && !oneway) {
		if (kIORPCVersionCurrentReply != mach->msgh.msgh_id) {
			ret = (MACH_NOTIFY_SEND_ONCE == mach->msgh.msgh_id) ? MIG_SERVER_DIED : MIG_REPLY_MISMATCH;
		} else if ((replySize = mach->msgh.msgh_size) < (sizeof(IORPCMessageMach) + sizeof(IORPCMessage))) {
//				printf("BAD REPLY SIZE\n");
			ret = MIG_BAD_ARGUMENTS;
		} else {
			if (!(MACH_MSGH_BITS_COMPLEX & mach->msgh.msgh_bits)) {
				mach->msgh_body.msgh_descriptor_count = 0;
			}
			message = IORPCMessageFromMach(mach, true);
			if (!message) {
				ret = kIOReturnIPCError;
			} else if (message->msgid != msgid) {
//					printf("BAD REPLY ID\n");
				ret = MIG_BAD_ARGUMENTS;
			} else {
				bool isError = (0 != (kIORPCMessageError & message->flags));
				ret = copyInObjects(mach, message, replySize, !isError, true);
				if (kIOReturnSuccess != ret) {
					if (kIODKLogIPC & gIODKDebug) {
						DKLOG("rpc copyin(0x%x) %x\n", ret, mach->msgh.msgh_id);
					}
					return KERN_NOT_SUPPORTED;
				}
				if (isError) {
					IORPCMessageErrorReturnContent * errorMsg = (typeof(errorMsg))message;
					ret = errorMsg->result;
				}
			}
		}
	}

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IORPCMessage *
IORPCMessageFromMach(IORPCMessageMach * msg, bool reply)
{
	mach_msg_size_t              idx, count;
	mach_msg_port_descriptor_t * desc;
	mach_msg_port_descriptor_t * maxDesc;
	size_t                       size, msgsize;
	bool                         upgrade;

	msgsize = msg->msgh.msgh_size;
	count   = msg->msgh_body.msgh_descriptor_count;
	desc    = &msg->objects[0];
	maxDesc = (typeof(maxDesc))(((uintptr_t) msg) + msgsize);
	upgrade = (msg->msgh.msgh_id != (reply ? kIORPCVersionCurrentReply : kIORPCVersionCurrent));

	if (upgrade) {
		OSReportWithBacktrace("obsolete message");
		return NULL;
	}

	for (idx = 0; idx < count; idx++) {
		if (desc >= maxDesc) {
			return NULL;
		}
		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			size = sizeof(mach_msg_port_descriptor_t);
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
			size = sizeof(mach_msg_ool_descriptor_t);
			break;
		default:
			return NULL;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + size);
	}
	return (IORPCMessage *)(uintptr_t) desc;
}

ipc_port_t
IOUserServer::copySendRightForObject(OSObject * object, ipc_kobject_type_t type)
{
	ipc_port_t port;
	ipc_port_t sendPort = NULL;

	port = iokit_port_for_object(object, type);
	if (port) {
		sendPort = ipc_port_make_send(port);
		iokit_release_port(port);
	}

	return sendPort;
}

OSObject *
IOUserServer::copyObjectForSendRight(ipc_port_t port, ipc_kobject_type_t type)
{
	OSObject * object;
	object = iokit_lookup_io_object(port, type);
	return object;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Create a vm_map_copy_t or kalloc'ed data for memory
// to be copied out. ipc will free after the copyout.

static kern_return_t
copyoutkdata(const void * data, vm_size_t len, void ** buf)
{
	kern_return_t       err;
	vm_map_copy_t       copy;

	err = vm_map_copyin( kernel_map, CAST_USER_ADDR_T(data), len,
	    false /* src_destroy */, &copy);

	assert( err == KERN_SUCCESS );
	if (err == KERN_SUCCESS) {
		*buf = (char *) copy;
	}

	return err;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::copyOutObjects(IORPCMessageMach * mach, IORPCMessage * message,
    size_t size, bool consume)
{
	uint64_t           refs;
	uint32_t           idx, maxObjectCount;
	ipc_port_t         port;
	OSObject         * object;
	size_t             descsize;
	mach_msg_port_descriptor_t * desc;
	mach_msg_ool_descriptor_t  * ool;
	vm_map_copy_t                copy;
	void                       * address;
	mach_msg_size_t              length;
	kern_return_t                kr;
	OSSerialize                * s;

	refs           = message->objectRefs;
	maxObjectCount = MAX_OBJECT_COUNT(mach, size, message);
//	assert(refs <= mach->msgh_body.msgh_descriptor_count);
//	assert(refs <= maxObjectCount);
	if (refs > mach->msgh_body.msgh_descriptor_count) {
		return kIOReturnBadArgument;
	}
	if (refs > maxObjectCount) {
		return kIOReturnBadArgument;
	}

	desc = &mach->objects[0];
	for (idx = 0; idx < refs; idx++) {
		object = (OSObject *) message->objects[idx];

		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			descsize = sizeof(mach_msg_port_descriptor_t);
			port = NULL;
			if (object) {
				port = copySendRightForObject(object, IKOT_UEXT_OBJECT);
				if (!port) {
					break;
				}
				if (consume) {
					object->release();
				}
				message->objects[idx] = 0;
			}
//		    desc->type        = MACH_MSG_PORT_DESCRIPTOR;
			desc->disposition = MACH_MSG_TYPE_MOVE_SEND;
			desc->name        = port;
			desc->pad2        = 0;
			desc->pad_end     = 0;
			break;

		case MACH_MSG_OOL_DESCRIPTOR:
			descsize = sizeof(mach_msg_ool_descriptor_t);

			length = 0;
			address = NULL;
			if (object) {
				s = OSSerialize::binaryWithCapacity(4096);
				assert(s);
				if (!s) {
					break;
				}
				s->setIndexed(true);
				if (!object->serialize(s)) {
					assert(false);
					descsize = -1UL;
					s->release();
					break;
				}
				length = s->getLength();
				kr = copyoutkdata(s->text(), length, &address);
				s->release();
				if (KERN_SUCCESS != kr) {
					descsize = -1UL;
					address = NULL;
					length = 0;
				}
				if (consume) {
					object->release();
				}
				message->objects[idx] = 0;
			}
			ool = (typeof(ool))desc;
//		    ool->type        = MACH_MSG_OOL_DESCRIPTOR;
			ool->deallocate  = false;
			ool->copy        = MACH_MSG_PHYSICAL_COPY;
			ool->size        = length;
			ool->address     = address;
			break;

		default:
			descsize = -1UL;
			break;
		}
		if (-1UL == descsize) {
			break;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + descsize);
	}

	if (idx >= refs) {
		return kIOReturnSuccess;
	}

	desc = &mach->objects[0];
	while (idx--) {
		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			descsize = sizeof(mach_msg_port_descriptor_t);
			port = desc->name;
			if (port) {
				ipc_port_release_send(port);
			}
			break;

		case MACH_MSG_OOL_DESCRIPTOR:
			descsize = sizeof(mach_msg_ool_descriptor_t);
			ool = (typeof(ool))desc;
			copy = (vm_map_copy_t) ool->address;
			if (copy) {
				vm_map_copy_discard(copy);
			}
			break;

		default:
			descsize = -1UL;
			break;
		}
		if (-1UL == descsize) {
			break;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + descsize);
	}

	return kIOReturnBadArgument;
}

IOReturn
IOUserServer::copyInObjects(IORPCMessageMach * mach, IORPCMessage * message,
    size_t size, bool copyObjects, bool consumePorts)
{
	uint64_t           refs;
	uint32_t           idx, maxObjectCount;
	ipc_port_t         port;
	OSObject         * object;
	size_t                       descsize;
	mach_msg_port_descriptor_t * desc;
	mach_msg_ool_descriptor_t  * ool;
	vm_map_address_t             copyoutdata;
	kern_return_t                kr;

	refs           = message->objectRefs;
	maxObjectCount = MAX_OBJECT_COUNT(mach, size, message);
//	assert(refs <= mach->msgh_body.msgh_descriptor_count);
//	assert(refs <= maxObjectCount);
	if (refs > mach->msgh_body.msgh_descriptor_count) {
		return kIOReturnBadArgument;
	}
	if (refs > maxObjectCount) {
		return kIOReturnBadArgument;
	}

	desc = &mach->objects[0];
	for (idx = 0; idx < refs; idx++) {
		switch (desc->type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			descsize = sizeof(mach_msg_port_descriptor_t);

			object = NULL;
			port = desc->name;
			if (port) {
				if (copyObjects) {
					object = copyObjectForSendRight(port, IKOT_UEXT_OBJECT);
					if (!object) {
						descsize = -1UL;
						break;
					}
				}
				if (consumePorts) {
					ipc_port_release_send(port);
				}
			}
			break;

		case MACH_MSG_OOL_DESCRIPTOR:
			descsize = sizeof(mach_msg_ool_descriptor_t);
			ool = (typeof(ool))desc;

			object = NULL;
			if (copyObjects && ool->size && ool->address) {
				kr = vm_map_copyout(kernel_map, &copyoutdata, (vm_map_copy_t) ool->address);
				if (KERN_SUCCESS == kr) {
					object = OSUnserializeXML((const char *) copyoutdata, ool->size);
					// vm_map_copyout() has consumed the vm_map_copy_t in the message
					ool->size = 0;
					ool->address = NULL;
					kr = vm_deallocate(kernel_map, copyoutdata, ool->size);
					assert(KERN_SUCCESS == kr);
				}
				if (!object) {
					descsize = -1UL;
					break;
				}
			}
			break;

		default:
			descsize = -1UL;
			break;
		}
		if (-1UL == descsize) {
			break;
		}
		if (copyObjects) {
			message->objects[idx] = (OSObjectRef) object;
		}
		desc = (typeof(desc))(((uintptr_t) desc) + descsize);
	}

	if (idx >= refs) {
		return kIOReturnSuccess;
	}

	while (idx--) {
		object = (OSObject *) message->objects[idx];
		object->release();
		message->objects[idx] = 0;
	}

	return kIOReturnBadArgument;
}

IOReturn
IOUserServer::consumeObjects(IORPCMessage * message, size_t messageSize)
{
	uint64_t    refs, idx;
	OSObject  * object;

	refs   = message->objectRefs;
	for (idx = 0; idx < refs; idx++) {
		object = (OSObject *) message->objects[idx];
		if (object) {
			object->release();
			message->objects[idx] = 0;
		}
	}

	return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IOUserServer::finalize(IOOptionBits options)
{
	OSArray   * services;

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("%s::finalize(%p)\n", getName(), this);
	}

	IOLockLock(gIOUserServerLock);
	OSSafeReleaseNULL(fRootQueue);
	IOLockUnlock(gIOUserServerLock);

	services = NULL;
	IOLockLock(fLock);
	if (fServices) {
		services = OSArray::withArray(fServices);
	}
	IOLockUnlock(fLock);

	if (services) {
		services->iterateObjects(^bool (OSObject * obj) {
			IOService * service;
			IOService * provider;
			bool        started = false;

			service = (IOService *) obj;
			if (kIODKLogSetup & gIODKDebug) {
			        DKLOG("%s::terminate(" DKS ")\n", getName(), DKN(service));
			}
			if (service->reserved->uvars) {
			        started = service->reserved->uvars->started;
			        service->reserved->uvars->serverDied = true;
			        if (started) {
			                provider = service->getProvider();
			                serviceDidStop(service, provider);
			                service->terminate(kIOServiceTerminateNeedWillTerminate | kIOServiceTerminateWithRematch);
				}
			}
			if (!started) {
			        DKLOG("%s::terminate(" DKS ") server exit before start()\n", getName(), DKN(service));
			        serviceStop(service, NULL);
			}
			return false;
		});
		services->release();
	}

	return IOUserClient::finalize(options);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient

OSDefineMetaClassAndStructors(IOUserServer, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOUserClient * IOUserServer::withTask(task_t owningTask)
{
	IOUserServer * inst;

	inst = new IOUserServer;
	if (inst && !inst->init()) {
		inst->release();
		inst = NULL;
		return inst;
	}
	inst->PMinit();

	inst->fOwningTask = current_task();
	inst->fEntitlements = IOUserClient::copyClientEntitlements(inst->fOwningTask);

	if (!(kIODKDisableEntitlementChecking & gIODKDebug)) {
		if (!inst->fEntitlements || !inst->fEntitlements->getObject(gIODriverKitEntitlementKey)) {
			proc_t p;
			pid_t  pid;

			p = (proc_t)get_bsdtask_info(inst->fOwningTask);
			if (p) {
				pid = proc_pid(p);
				IOLog(kIODriverKitEntitlementKey " entitlement check failed for %s[%d]\n", proc_best_name(p), pid);
			}
			inst->release();
			inst = NULL;
			return inst;
		}
	}

	/* Mark the current task's space as eligible for uext object ports */
	iokit_label_dext_task(inst->fOwningTask);

	inst->fLock     = IOLockAlloc();
	inst->fServices = OSArray::withCapacity(4);
	inst->fClasses  = OSDictionary::withCapacity(16);
	inst->fClasses->setOptions(OSCollection::kSort, OSCollection::kSort);

	return inst;
}

IOReturn
IOUserServer::clientClose(void)
{
	terminate();
	return kIOReturnSuccess;
}

IOReturn
IOUserServer::setProperties(OSObject * properties)
{
	IOReturn kr = kIOReturnUnsupported;
	return kr;
}

void
IOUserServer::stop(IOService * provider)
{
	fOwningTask = TASK_NULL;

	PMstop();

	IOServicePH::serverRemove(this);

	OSSafeReleaseNULL(fRootQueue);

	if (fInterruptLock) {
		IOSimpleLockFree(fInterruptLock);
	}
}

void
IOUserServer::free()
{
	OSSafeReleaseNULL(fEntitlements);
	OSSafeReleaseNULL(fClasses);
	if (fLock) {
		IOLockFree(fLock);
	}
	OSSafeReleaseNULL(fServices);
	IOUserClient::free();
}

IOReturn
IOUserServer::registerClass(OSClassDescription * desc, uint32_t size, OSUserMetaClass ** pCls)
{
	OSUserMetaClass * cls;
	const OSSymbol  * sym;
	uint64_t        * methodOptions;
	const char      * queueNames;
	uint32_t          methodOptionsEnd, queueNamesEnd;
	IOReturn          ret = kIOReturnSuccess;

	if (size < sizeof(OSClassDescription)) {
		assert(false);
		return kIOReturnBadArgument;
	}

	if (kIODKLogSetup & gIODKDebug) {
		DKLOG("%s::registerClass %s, %d, %d\n", getName(), desc->name, desc->queueNamesSize, desc->methodNamesSize);
	}

	if (desc->descriptionSize != size) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (os_add_overflow(desc->queueNamesOffset, desc->queueNamesSize, &queueNamesEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (queueNamesEnd > size) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (os_add_overflow(desc->methodOptionsOffset, desc->methodOptionsSize, &methodOptionsEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (methodOptionsEnd > size) {
		assert(false);
		return kIOReturnBadArgument;
	}
	// overlaps?
	if ((desc->queueNamesOffset >= desc->methodOptionsOffset) && (desc->queueNamesOffset < methodOptionsEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if ((queueNamesEnd >= desc->methodOptionsOffset) && (queueNamesEnd < methodOptionsEnd)) {
		assert(false);
		return kIOReturnBadArgument;
	}

	if (desc->methodOptionsSize & ((2 * sizeof(uint64_t)) - 1)) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (sizeof(desc->name) == strnlen(desc->name, sizeof(desc->name))) {
		assert(false);
		return kIOReturnBadArgument;
	}
	if (sizeof(desc->superName) == strnlen(desc->superName, sizeof(desc->superName))) {
		assert(false);
		return kIOReturnBadArgument;
	}

	cls = OSTypeAlloc(OSUserMetaClass);
	assert(cls);
	if (!cls) {
		return kIOReturnNoMemory;
	}

	cls->description = (typeof(cls->description))IOMalloc(size);
	assert(cls->description);
	if (!cls->description) {
		assert(false);
		cls->release();
		return kIOReturnNoMemory;
	}
	bcopy(desc, cls->description, size);

	cls->methodCount = desc->methodOptionsSize / (2 * sizeof(uint64_t));
	cls->methods = IONew(uint64_t, 2 * cls->methodCount);
	if (!cls->methods) {
		assert(false);
		cls->release();
		return kIOReturnNoMemory;
	}

	methodOptions = (typeof(methodOptions))(((uintptr_t) desc) + desc->methodOptionsOffset);
	bcopy(methodOptions, cls->methods, 2 * cls->methodCount * sizeof(uint64_t));

	queueNames = (typeof(queueNames))(((uintptr_t) desc) + desc->queueNamesOffset);
	cls->queueNames = copyInStringArray(queueNames, desc->queueNamesSize);

	sym = OSSymbol::withCString(desc->name);
	assert(sym);
	if (!sym) {
		assert(false);
		cls->release();
		return kIOReturnNoMemory;
	}

	cls->name = sym;
	cls->meta = OSMetaClass::copyMetaClassWithName(sym);
	IOLockLock(fLock);
	cls->superMeta = OSDynamicCast(OSUserMetaClass, fClasses->getObject(desc->superName));
	if (fClasses->getObject(sym) != NULL) {
		/* class with this name exists */
		ret = kIOReturnBadArgument;
	} else {
		if (fClasses->setObject(sym, cls)) {
			*pCls = cls;
		} else {
			/* could not add class to fClasses */
			ret = kIOReturnNoMemory;
		}
	}
	IOLockUnlock(fLock);
	cls->release();
	return ret;
}

IOReturn
IOUserServer::setRootQueue(IODispatchQueue * queue)
{
	assert(!fRootQueue);
	if (fRootQueue) {
		return kIOReturnStillOpen;
	}
	queue->retain();
	fRootQueue = queue;

	return kIOReturnSuccess;
}

IOReturn
IOUserServer::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
	IOReturn ret = kIOReturnBadArgument;
	mach_port_name_t portname;

	switch (selector) {
	case kIOUserServerMethodRegisterClass:
	{
		OSUserMetaClass * cls;
		if (!args->structureInputSize) {
			return kIOReturnBadArgument;
		}
		if (args->scalarOutputCount != 2) {
			return kIOReturnBadArgument;
		}
		ret = registerClass((OSClassDescription *) args->structureInput, args->structureInputSize, &cls);
		if (kIOReturnSuccess == ret) {
			portname = iokit_make_send_right(fOwningTask, cls, IKOT_UEXT_OBJECT);
			assert(portname);
			args->scalarOutput[0] = portname;
			args->scalarOutput[1] = kOSObjectRPCRemote;
		}
		break;
	}
	case kIOUserServerMethodStart:
	{
		if (args->scalarOutputCount != 1) {
			return kIOReturnBadArgument;
		}
		portname = iokit_make_send_right(fOwningTask, this, IKOT_UEXT_OBJECT);
		assert(portname);
		args->scalarOutput[0] = portname;
		ret = kIOReturnSuccess;
		break;
	}
	default:
		break;
	}

	return ret;
}

IOExternalTrap *
IOUserServer::getTargetAndTrapForIndex( IOService **targetP, UInt32 index )
{
	static const IOExternalTrap trapTemplate[] = {
		{ NULL, (IOTrap) & IOUserServer::waitInterruptTrap},
	};
	if (index >= (sizeof(trapTemplate) / sizeof(IOExternalTrap))) {
		return NULL;
	}
	*targetP = this;
	return (IOExternalTrap *)&trapTemplate[index];
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserServer::serviceAttach(IOService * service, IOService * provider)
{
	IOReturn           ret;
	OSObjectUserVars * vars;
	OSObject         * prop;
	OSString         * str;
	OSSymbolConstPtr   bundleID;
	char               execPath[1024];

	vars = IONewZero(OSObjectUserVars, 1);
	service->reserved->uvars = vars;

	vars->userServer = this;
	vars->userServer->retain();
	IOLockLock(fLock);
	if (-1U == fServices->getNextIndexOfObject(service, 0)) {
		fServices->setObject(service);
	}
	IOLockUnlock(fLock);

	prop = service->copyProperty(gIOUserClassKey);
	str = OSDynamicCast(OSString, prop);
	if (str) {
		service->setName(str);
	}
	OSSafeReleaseNULL(prop);

	prop = service->copyProperty(gIOModuleIdentifierKey);
	bundleID = OSDynamicCast(OSSymbol, prop);
	if (bundleID) {
		execPath[0] = 0;
		bool ok = OSKext::copyUserExecutablePath(bundleID, execPath, sizeof(execPath));
		if (ok) {
			ret = LoadModule(execPath);
			if (kIODKLogSetup & gIODKDebug) {
				DKLOG("%s::LoadModule 0x%x %s\n", getName(), ret, execPath);
			}
		}
	}
	OSSafeReleaseNULL(prop);

	ret = kIOReturnSuccess;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define kDriverKitUCPrefix "com.apple.developer.driverkit.userclient-access."

IOReturn
IOUserServer::serviceNewUserClient(IOService * service, task_t owningTask, void * securityID,
    uint32_t type, OSDictionary * properties, IOUserClient ** handler)
{
	IOReturn           ret;
	IOUserClient     * uc;
	IOUserUserClient * userUC;
	OSDictionary     * entitlements;
	OSObject         * prop;
	OSObject         * bundleID;
	bool               ok;

	*handler = NULL;
	ret = service->NewUserClient(type, &uc);
	if (kIOReturnSuccess != ret) {
		return ret;
	}
	userUC = OSDynamicCast(IOUserUserClient, uc);
	if (!userUC) {
		uc->terminate();
		OSSafeReleaseNULL(uc);
		return kIOReturnUnsupported;
	}
	userUC->setTask(owningTask);

	if (!(kIODKDisableEntitlementChecking & gIODKDebug)) {
		bundleID = NULL;
		entitlements = NULL;
		if (fEntitlements && fEntitlements->getObject(gIODriverKitUserClientEntitlementAllowAnyKey)) {
			ok = true;
		} else {
			entitlements = IOUserClient::copyClientEntitlements(owningTask);
			bundleID = service->copyProperty(gIOModuleIdentifierKey);
			ok = (entitlements
			    && bundleID
			    && (prop = entitlements->getObject(gIODriverKitUserClientEntitlementsKey)));
			if (ok) {
				bool found __block = false;
				ok = prop->iterateObjects(^bool (OSObject * object) {
					found = object->isEqualTo(bundleID);
					return found;
				});
				ok = found;
			}
		}
		if (ok) {
			prop = userUC->copyProperty(gIOServiceDEXTEntitlementsKey);
			ok = checkEntitlements(entitlements, prop, NULL, NULL);
		}
		OSSafeReleaseNULL(bundleID);
		OSSafeReleaseNULL(entitlements);
		if (!ok) {
			DKLOG(DKS ":UC entitlements check failed\n", DKN(userUC));
			uc->terminate();
			OSSafeReleaseNULL(uc);
			return kIOReturnNotPermitted;
		}
	}

	*handler = userUC;

	return ret;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOPMPowerState
    sPowerStates[] = {
	{   .version                = kIOPMPowerStateVersion1,
	    .capabilityFlags        = 0,
	    .outputPowerCharacter   = 0,
	    .inputPowerRequirement  = 0},
	{   .version                = kIOPMPowerStateVersion1,
	    .capabilityFlags        = kIOPMLowPower,
	    .outputPowerCharacter   = kIOPMLowPower,
	    .inputPowerRequirement  = kIOPMLowPower},
	{   .version                = kIOPMPowerStateVersion1,
	    .capabilityFlags        = kIOPMPowerOn,
	    .outputPowerCharacter   = kIOPMPowerOn,
	    .inputPowerRequirement  = kIOPMPowerOn},
};

IOReturn
IOUserServer::setPowerState(unsigned long state, IOService * service)
{
	if (kIODKLogPM & gIODKDebug) {
		DKLOG(DKS "::setPowerState(%ld) %d\n", DKN(service), state, fSystemPowerAck);
	}
	return kIOPMAckImplied;
}

IOReturn
IOUserServer::powerStateWillChangeTo(IOPMPowerFlags flags, unsigned long state, IOService * service)
{
	IOReturn ret;

	if (service->reserved->uvars) {
		if (!fSystemOff && !(kIODKDisablePM & gIODKDebug)) {
			service->reserved->uvars->willPower = true;
			if (kIODKLogPM & gIODKDebug) {
				DKLOG(DKS "::powerStateWillChangeTo(%ld) 0x%qx, %d\n", DKN(service), state, fPowerStates, fSystemPowerAck);
			}
			ret = service->SetPowerState(flags);
			if (kIOReturnSuccess == ret) {
				return 20 * 1000 * 1000;
			}
		}
		service->reserved->uvars->willPower = false;
	}

	return kIOPMAckImplied;
}

IOReturn
IOUserServer::powerStateDidChangeTo(IOPMPowerFlags flags, unsigned long state, IOService * service)
{
	unsigned int idx;
	bool         pmAck;

	pmAck = false;
	IOLockLock(fLock);
	idx = fServices->getNextIndexOfObject(service, 0);
	if (-1U == idx) {
		IOLockUnlock(fLock);
		return kIOPMAckImplied;
	}
	assert(idx <= 63);

	if (state) {
		fPowerStates |= (1ULL << idx);
	} else {
		fPowerStates &= ~(1ULL << idx);
	}
	if (kIODKLogPM & gIODKDebug) {
		DKLOG(DKS "::powerStateDidChangeTo(%ld) 0x%qx, %d\n", DKN(service), state, fPowerStates, fSystemPowerAck);
	}
	if (!fPowerStates && (pmAck = fSystemPowerAck)) {
		fSystemPowerAck = false;
		fSystemOff      = true;
	}
	IOLockUnlock(fLock);

	if (pmAck) {
		IOServicePH::serverAck(this);
	}

	return kIOPMAckImplied;
}

kern_return_t
IMPL(IOService, SetPowerState)
{
	if (kIODKLogPM & gIODKDebug) {
		DKLOG(DKS "::SetPowerState(%d), %d\n", DKN(this), powerFlags, reserved->uvars->willPower);
	}
	if (reserved->uvars
	    && reserved->uvars->userServer
	    && reserved->uvars->willPower) {
		reserved->uvars->willPower = false;
		acknowledgePowerChange(reserved->uvars->userServer);
		return kIOReturnSuccess;
	}
	return kIOReturnNotReady;
}

kern_return_t
IMPL(IOService, ChangePowerState)
{
	switch (powerFlags) {
	case kIOServicePowerCapabilityOff:
		changePowerStateToPriv(0);
		break;
	case kIOServicePowerCapabilityLow:
		changePowerStateToPriv(1);
		break;
	case kIOServicePowerCapabilityOn:
		changePowerStateToPriv(2);
		break;
	default:
		return kIOReturnBadArgument;
	}

	return kIOReturnSuccess;
}

kern_return_t
IMPL(IOService, Create)
{
	OSObject       * inst;
	IOService      * service;
	OSString       * str;
	const OSSymbol * sym;
	OSObject       * prop;
	OSDictionary   * properties;
	kern_return_t    ret;

	if (provider != this) {
		return kIOReturnUnsupported;
	}

	ret = kIOReturnUnsupported;
	inst = NULL;
	service = NULL;

	prop = copyProperty(propertiesKey);
	properties = OSDynamicCast(OSDictionary, prop);
	assert(properties);
	if (properties) {
		str = OSDynamicCast(OSString, properties->getObject(gIOClassKey));
		assert(str);
		sym = OSSymbol::withString(str);
		if (sym) {
			inst = OSMetaClass::allocClassWithName(sym);
			service = OSDynamicCast(IOService, inst);
			if (service && service->init(properties) && service->attach(this)) {
				reserved->uvars->userServer->serviceAttach(service, this);
				service->reserved->uvars->started = true;
				ret = kIOReturnSuccess;
				*result = service;
			}
			OSSafeReleaseNULL(sym);
		}
	}

	OSSafeReleaseNULL(prop);
	if (kIOReturnSuccess != ret) {
		OSSafeReleaseNULL(inst);
	}

	return ret;
}

kern_return_t
IMPL(IOService, Terminate)
{
	IOUserServer * us;

	if (options) {
		return kIOReturnUnsupported;
	}

	us = (typeof(us))thread_iokit_tls_get(0);
	if (!reserved->uvars
	    || (reserved->uvars->userServer != us)) {
		return kIOReturnNotPermitted;
	}
	terminate(kIOServiceTerminateNeedWillTerminate);

	return kIOReturnSuccess;
}

kern_return_t
IMPL(IOService, NewUserClient)
{
	return kIOReturnError;
}

kern_return_t
IMPL(IOService, SearchProperty)
{
	OSObject * object;

	if (kIOServiceSearchPropertyParents & options) {
		options = kIORegistryIterateParents | kIORegistryIterateRecursively;
	} else {
		options = 0;
	}

	object = copyProperty(name, IORegistryEntry::getPlane(plane), options);
	*property = object;

	return object ? kIOReturnSuccess : kIOReturnNotFound;
}

kern_return_t
IMPL(IOService, CopyProviderProperties)
{
	IOReturn    ret;
	OSArray   * result;
	IOService * provider;

	result = OSArray::withCapacity(8);
	if (!result) {
		return kIOReturnNoMemory;
	}

	ret = kIOReturnSuccess;
	for (provider = this; provider; provider = provider->getProvider()) {
		OSObject     * obj;
		OSDictionary * props;

		obj = provider->copyProperty(gIOSupportedPropertiesKey);
		props = OSDynamicCast(OSDictionary, obj);
		if (!props) {
			OSSafeReleaseNULL(obj);
			props = provider->dictionaryWithProperties();
		}
		if (!props) {
			ret = kIOReturnNoMemory;
			break;
		}
		bool __block addClass = true;
		if (propertyKeys) {
			OSDictionary * retProps;
			retProps = OSDictionary::withCapacity(4);
			addClass = false;
			if (!retProps) {
				ret = kIOReturnNoMemory;
				break;
			}
			propertyKeys->iterateObjects(^bool (OSObject * _key) {
				OSString * key = OSDynamicCast(OSString, _key);
				if (gIOClassKey->isEqualTo(key)) {
				        addClass = true;
				        return false;
				}
				retProps->setObject(key, props->getObject(key));
				return false;
			});
			OSSafeReleaseNULL(props);
			props = retProps;
		}
		if (addClass) {
			OSArray * classes = OSArray::withCapacity(8);
			if (!classes) {
				ret = kIOReturnNoMemory;
				break;
			}
			for (const OSMetaClass * meta = provider->getMetaClass(); meta; meta = meta->getSuperClass()) {
				classes->setObject(meta->getClassNameSymbol());
			}
			props->setObject(gIOClassKey, classes);
			OSSafeReleaseNULL(classes);
		}
		bool ok = result->setObject(props);
		props->release();
		if (!ok) {
			ret = kIOReturnNoMemory;
			break;
		}
	}
	if (kIOReturnSuccess != ret) {
		OSSafeReleaseNULL(result);
	}
	*properties = result;
	return ret;
}

void
IOUserServer::systemPower(bool powerOff)
{
	OSArray * services;

	if (kIODKLogPM & gIODKDebug) {
		DKLOG("%s::powerOff(%d) 0x%qx\n", getName(), powerOff, fPowerStates);
	}

	IOLockLock(fLock);
	services = OSArray::withArray(fServices);

	if (powerOff) {
		fSystemPowerAck = (0 != fPowerStates);
		if (!fSystemPowerAck) {
			fSystemOff = true;
		}
		IOLockUnlock(fLock);

		if (!fSystemPowerAck) {
			IOServicePH::serverAck(this);
		} else {
			if (services) {
				services->iterateObjects(^bool (OSObject * obj) {
					IOService * service;
					service = (IOService *) obj;
					if (kIODKLogPM & gIODKDebug) {
					        DKLOG("changePowerStateWithOverrideTo(" DKS ", %d)\n", DKN(service), 0);
					}
					service->reserved->uvars->powerOverride = service->getPowerState();
					service->changePowerStateWithOverrideTo(0, 0);
					return false;
				});
			}
		}
	} else {
		fSystemOff = false;
		IOLockUnlock(fLock);
		if (services) {
			services->iterateObjects(^bool (OSObject * obj) {
				IOService * service;
				service = (IOService *) obj;
				if (-1U != service->reserved->uvars->powerOverride) {
				        if (kIODKLogPM & gIODKDebug) {
				                DKLOG("changePowerStateWithOverrideTo(" DKS ", %d)\n", DKN(service), service->reserved->uvars->powerOverride);
					}
				        service->changePowerStateWithOverrideTo(service->reserved->uvars->powerOverride, 0);
				        service->reserved->uvars->powerOverride = -1U;
				}
				return false;
			});
		}
	}
	OSSafeReleaseNULL(services);
}



IOReturn
IOUserServer::serviceStarted(IOService * service, IOService * provider, bool result)
{
	IOReturn    ret;
	IOService * pmProvider;

	DKLOG(DKS "::start(" DKS ") %s\n", DKN(service), DKN(provider), result ? "ok" : "fail");

	if (!result) {
		ret = kIOReturnSuccess;
		return ret;
	}

	if (!fRootNotifier) {
		ret = registerPowerDriver(this, sPowerStates, sizeof(sPowerStates) / sizeof(sPowerStates[0]));
		assert(kIOReturnSuccess == ret);
		IOServicePH::serverAdd(this);
		fRootNotifier = true;
	}

	if (!(kIODKDisablePM & gIODKDebug) && !service->pm_vars) {
		service->PMinit();
		ret = service->registerPowerDriver(this, sPowerStates, sizeof(sPowerStates) / sizeof(sPowerStates[0]));
		assert(kIOReturnSuccess == ret);

		pmProvider = service;
		while (pmProvider && !pmProvider->inPlane(gIOPowerPlane)) {
			pmProvider = pmProvider->getProvider();
		}
		if (pmProvider) {
			OSObject  * prop;
			OSString  * str;
			prop = pmProvider->copyProperty("non-removable");
			if (prop) {
				str = OSDynamicCast(OSString, prop);
				if (str && str->isEqualTo("yes")) {
					pmProvider = NULL;
				}
				prop->release();
			}
		}
		if (pmProvider) {
			IOLockLock(fLock);
			unsigned int idx = fServices->getNextIndexOfObject(service, 0);
			assert(idx <= 63);
			fPowerStates |= (1ULL << idx);
			IOLockUnlock(fLock);

			pmProvider->joinPMtree(service);
			service->reserved->uvars->userServerPM = true;
		}
	}

	service->registerInterestedDriver(this);
	service->reserved->uvars->started = true;

	return kIOReturnSuccess;
}


IOReturn
IOUserServer::serviceOpen(IOService * provider, IOService * client)
{
	OSObjectUserVars * uvars;

	uvars = client->reserved->uvars;
	if (!uvars->openProviders) {
		uvars->openProviders = OSArray::withObjects((const OSObject **) &provider, 1);
	} else if (-1U == uvars->openProviders->getNextIndexOfObject(client, 0)) {
		uvars->openProviders->setObject(provider);
	}

	return kIOReturnSuccess;
}

IOReturn
IOUserServer::serviceClose(IOService * provider, IOService * client)
{
	OSObjectUserVars * uvars;
	unsigned int       idx;

	uvars = client->reserved->uvars;
	if (!uvars->openProviders) {
		return kIOReturnNotOpen;
	}
	idx = uvars->openProviders->getNextIndexOfObject(client, 0);
	if (-1U == idx) {
		return kIOReturnNotOpen;
	}
	uvars->openProviders->removeObject(idx);

	return kIOReturnSuccess;
}


IOReturn
IOUserServer::serviceStop(IOService * service, IOService *)
{
	IOReturn           ret;
	uint32_t           idx, queueAlloc;
	OSObjectUserVars * uvars;

	IOLockLock(fLock);
	idx = fServices->getNextIndexOfObject(service, 0);
	if (-1U != idx) {
		fServices->removeObject(idx);
		uvars = service->reserved->uvars;
		uvars->stopped = true;
	}
	IOLockUnlock(fLock);

	if (-1U == idx) {
		return kIOReturnSuccess;
	}

	if (uvars->queueArray && uvars->userMeta) {
		queueAlloc = 1;
		if (uvars->userMeta->queueNames) {
			queueAlloc += uvars->userMeta->queueNames->count;
		}
		for (idx = 0; idx < queueAlloc; idx++) {
			OSSafeReleaseNULL(uvars->queueArray[idx]);
		}
		IOSafeDeleteNULL(uvars->queueArray, IODispatchQueue *, queueAlloc);
	}

	(void) service->deRegisterInterestedDriver(this);
	if (uvars->userServerPM) {
		service->PMstop();
	}

	ret = kIOReturnSuccess;
	return ret;
}

void
IOUserServer::serviceFree(IOService * service)
{
	OSObjectUserVars * uvars;

	uvars = service->reserved->uvars;
	if (!uvars) {
		return;
	}
	OSSafeReleaseNULL(uvars->userServer);
	IOSafeDeleteNULL(service->reserved->uvars, OSObjectUserVars, 1);
}

void
IOUserServer::serviceWillTerminate(IOService * client, IOService * provider, IOOptionBits options)
{
	IOReturn ret;
	bool     willTerminate;

	willTerminate = false;
	if (client->lockForArbitration(true)) {
		if (!client->reserved->uvars->serverDied
		    && !client->reserved->uvars->willTerminate) {
			client->reserved->uvars->willTerminate = true;
			willTerminate = true;
		}
		client->unlockForArbitration();
	}

	if (willTerminate) {
		ret = client->Stop(provider);
		if (kIOReturnSuccess != ret) {
			ret = client->IOService::Stop(provider);
		}
	}
}

void
IOUserServer::serviceDidTerminate(IOService * client, IOService * provider, IOOptionBits options, bool * defer)
{
	if (client->lockForArbitration(true)) {
		client->reserved->uvars->didTerminate = true;
		if (!client->reserved->uvars->serverDied
		    && !client->reserved->uvars->stopped) {
			*defer = true;
		}
		client->unlockForArbitration();
	}
}

void
IOUserServer::serviceDidStop(IOService * client, IOService * provider)
{
	bool complete;
	OSArray * closeArray;

	complete = false;
	closeArray = NULL;

	if (client->lockForArbitration(true)) {
		if (client->reserved->uvars
		    && client->reserved->uvars->willTerminate
		    && !client->reserved->uvars->stopped) {
			client->reserved->uvars->stopped = true;
			complete = client->reserved->uvars->didTerminate;
		}

		if (client->reserved->uvars) {
			closeArray = client->reserved->uvars->openProviders;
			client->reserved->uvars->openProviders = NULL;
		}
		client->unlockForArbitration();
		if (closeArray) {
			closeArray->iterateObjects(^bool (OSObject * obj) {
				IOService * toClose;
				toClose = OSDynamicCast(IOService, obj);
				if (toClose) {
				        DKLOG(DKS ":force close (" DKS ")\n", DKN(client), DKN(toClose));
				        toClose->close(client);
				}
				return false;
			});
			closeArray->release();
		}
	}
	if (complete) {
		bool defer = false;
		client->didTerminate(provider, 0, &defer);
	}
}

kern_return_t
IMPL(IOService, Stop)
{
	IOUserServer::serviceDidStop(this, provider);

	return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient

OSDefineMetaClassAndStructors(IOUserUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOUserUserClient::setTask(task_t task)
{
	task_reference(task);
	fTask = task;

	return kIOReturnSuccess;
}

void
IOUserUserClient::stop(IOService * provider)
{
	if (fTask) {
		task_deallocate(fTask);
		fTask = NULL;
	}
	super::stop(provider);
}

IOReturn
IOUserUserClient::clientClose(void)
{
	terminate(kIOServiceTerminateNeedWillTerminate);
	return kIOReturnSuccess;
}

IOReturn
IOUserUserClient::setProperties(OSObject * properties)
{
	IOReturn ret = kIOReturnUnsupported;
	return ret;
}

struct IOUserUserClientActionRef {
	OSAsyncReference64 asyncRef;
};

void
IMPL(IOUserClient, KernelCompletion)
{
	IOUserUserClientActionRef * ref;

	ref = (typeof(ref))action->GetReference();

	IOUserClient::sendAsyncResult64(ref->asyncRef, status, (io_user_reference_t *) asyncData, asyncDataCount);
}

kern_return_t
IMPL(IOUserClient, _ExternalMethod)
{
	return kIOReturnUnsupported;
}

IOReturn
IOUserUserClient::clientMemoryForType(UInt32 type,
    IOOptionBits * koptions,
    IOMemoryDescriptor ** kmemory)
{
	IOReturn             kr;
	uint64_t             options;
	IOMemoryDescriptor * memory;

	kr = CopyClientMemoryForType(type, &options, &memory);

	*koptions = 0;
	*kmemory  = NULL;
	if (kIOReturnSuccess != kr) {
		return kr;
	}

	if (kIOUserClientMemoryReadOnly & options) {
		*koptions |= kIOMapReadOnly;
	}
	*kmemory = memory;

	return kr;
}

IOReturn
IOUserUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
	IOReturn   kr;
	OSData   * structureInput;
	OSData   * structureOutput;
	size_t     copylen;
	uint64_t   structureOutputSize;
	OSAction                  * action;
	IOUserUserClientActionRef * ref;

	kr             = kIOReturnUnsupported;
	structureInput = NULL;
	action         = NULL;

	if (args->structureInputSize) {
		structureInput = OSData::withBytesNoCopy((void *) args->structureInput, args->structureInputSize);
	}

	if (MACH_PORT_NULL != args->asyncWakePort) {
		kr = CreateActionKernelCompletion(sizeof(IOUserUserClientActionRef), &action);
		assert(KERN_SUCCESS == kr);
		ref = (typeof(ref))action->GetReference();
		bcopy(args->asyncReference, &ref->asyncRef[0], args->asyncReferenceCount * sizeof(ref->asyncRef[0]));
	}

	if (args->structureVariableOutputData) {
		structureOutputSize = kIOUserClientVariableStructureSize;
	} else if (args->structureOutputDescriptor) {
		structureOutputSize = args->structureOutputDescriptor->getLength();
	} else {
		structureOutputSize = args->structureOutputSize;
	}

	kr = _ExternalMethod(selector, &args->scalarInput[0], args->scalarInputCount,
	    structureInput, args->structureInputDescriptor,
	    args->scalarOutput, &args->scalarOutputCount,
	    structureOutputSize, &structureOutput, args->structureOutputDescriptor,
	    action);

	OSSafeReleaseNULL(structureInput);
	OSSafeReleaseNULL(action);

	if (kIOReturnSuccess != kr) {
		return kr;
	}
	if (structureOutput) {
		if (args->structureVariableOutputData) {
			*args->structureVariableOutputData = structureOutput;
		} else {
			copylen = structureOutput->getLength();
			if (copylen > args->structureOutputSize) {
				kr = kIOReturnBadArgument;
			} else {
				bcopy((const void *) structureOutput->getBytesNoCopy(), args->structureOutput, copylen);
			}
			OSSafeReleaseNULL(structureOutput);
		}
	}

	return kr;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
