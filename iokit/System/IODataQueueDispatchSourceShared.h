typedef struct _IODataQueueEntry {
	uint32_t  size;
	uint8_t   data[0];
} IODataQueueEntry;

#define DATA_QUEUE_ENTRY_HEADER_SIZE sizeof(IODataQueueEntry)

typedef struct _IODataQueueMemory {
	volatile uint32_t   head;
	volatile uint32_t   tail;
	volatile uint8_t    needServicedCallback;
	volatile uint8_t    _resv[31];
	IODataQueueEntry  queue[0];
} IODataQueueMemory;

struct IODataQueueDispatchSource_IVars {
	IODataQueueMemory         * dataQueue;
	IODataQueueDispatchSource * source;
//    IODispatchQueue           * queue;
	IOMemoryDescriptor        * memory;
	OSAction                  * dataAvailableAction;
	OSAction                  * dataServicedAction;
	uint64_t                    options;
	uint32_t                    queueByteCount;

#if !KERNEL
	bool                        enable;
	bool                        canceled;
#endif
};

bool
IODataQueueDispatchSource::init()
{
	if (!super::init()) {
		return false;
	}

	ivars = IONewZero(IODataQueueDispatchSource_IVars, 1);
	ivars->source = this;

#if !KERNEL
	kern_return_t ret;

	ret = CopyMemory(&ivars->memory);
	assert(kIOReturnSuccess == ret);

	uint64_t address;
	uint64_t length;

	ret = ivars->memory->Map(0, 0, 0, 0, &address, &length);
	assert(kIOReturnSuccess == ret);
	ivars->dataQueue = (typeof(ivars->dataQueue))(uintptr_t) address;
	ivars->queueByteCount = length;
#endif

	return true;
}

kern_return_t
IODataQueueDispatchSource::CheckForWork_Impl(
	const IORPC rpc,
	bool synchronous)
{
	IOReturn ret = kIOReturnNotReady;

	return ret;
}

#if KERNEL

kern_return_t
IODataQueueDispatchSource::Create_Impl(
	uint64_t queueByteCount,
	IODispatchQueue * queue,
	IODataQueueDispatchSource ** source)
{
	IODataQueueDispatchSource * inst;
	IOBufferMemoryDescriptor  * bmd;

	if (3 & queueByteCount) {
		return kIOReturnBadArgument;
	}
	if (queueByteCount > UINT_MAX) {
		return kIOReturnBadArgument;
	}
	inst = OSTypeAlloc(IODataQueueDispatchSource);
	if (!inst) {
		return kIOReturnNoMemory;
	}
	if (!inst->init()) {
		inst->release();
		return kIOReturnError;
	}

	bmd = IOBufferMemoryDescriptor::withOptions(
		kIODirectionOutIn | kIOMemoryKernelUserShared,
		queueByteCount, page_size);
	if (!bmd) {
		inst->release();
		return kIOReturnNoMemory;
	}
	inst->ivars->memory         = bmd;
	inst->ivars->queueByteCount = ((uint32_t) queueByteCount);
	inst->ivars->options        = 0;
	inst->ivars->dataQueue      = (typeof(inst->ivars->dataQueue))bmd->getBytesNoCopy();

	*source = inst;

	return kIOReturnSuccess;
}

kern_return_t
IODataQueueDispatchSource::CopyMemory_Impl(
	IOMemoryDescriptor ** memory)
{
	kern_return_t ret;
	IOMemoryDescriptor * result;

	result = ivars->memory;
	if (result) {
		result->retain();
		ret = kIOReturnSuccess;
	} else {
		ret = kIOReturnNotReady;
	}
	*memory = result;

	return ret;
}

kern_return_t
IODataQueueDispatchSource::CopyDataAvailableHandler_Impl(
	OSAction ** action)
{
	kern_return_t ret;
	OSAction    * result;

	result = ivars->dataAvailableAction;
	if (result) {
		result->retain();
		ret = kIOReturnSuccess;
	} else {
		ret = kIOReturnNotReady;
	}
	*action = result;

	return ret;
}

kern_return_t
IODataQueueDispatchSource::CopyDataServicedHandler_Impl(
	OSAction ** action)
{
	kern_return_t ret;
	OSAction    * result;

	result = ivars->dataServicedAction;
	if (result) {
		result->retain();
		ret = kIOReturnSuccess;
	} else {
		ret = kIOReturnNotReady;
	}
	*action = result;
	return ret;
}

kern_return_t
IODataQueueDispatchSource::SetDataAvailableHandler_Impl(
	OSAction * action)
{
	IOReturn ret;
	OSAction * oldAction;

	oldAction = ivars->dataAvailableAction;
	if (oldAction && OSCompareAndSwapPtr(oldAction, NULL, &ivars->dataAvailableAction)) {
		oldAction->release();
	}
	if (action) {
		action->retain();
		ivars->dataAvailableAction = action;
		if (IsDataAvailable()) {
			DataAvailable(ivars->dataAvailableAction);
		}
	}
	ret = kIOReturnSuccess;

	return ret;
}

kern_return_t
IODataQueueDispatchSource::SetDataServicedHandler_Impl(
	OSAction * action)
{
	IOReturn ret;
	OSAction * oldAction;

	oldAction = ivars->dataServicedAction;
	if (oldAction && OSCompareAndSwapPtr(oldAction, NULL, &ivars->dataServicedAction)) {
		oldAction->release();
	}
	if (action) {
		action->retain();
		ivars->dataServicedAction = action;
	}
	ret = kIOReturnSuccess;

	return ret;
}

#endif /* KERNEL */

void
IODataQueueDispatchSource::SendDataAvailable(void)
{
	IOReturn ret;

	if (!ivars->dataAvailableAction) {
		ret = CopyDataAvailableHandler(&ivars->dataAvailableAction);
		if (kIOReturnSuccess != ret) {
			ivars->dataAvailableAction = NULL;
		}
	}
	if (ivars->dataAvailableAction) {
		DataAvailable(ivars->dataAvailableAction);
	}
}

void
IODataQueueDispatchSource::SendDataServiced(void)
{
	IOReturn ret;

	if (!ivars->dataServicedAction) {
		ret = CopyDataServicedHandler(&ivars->dataServicedAction);
		if (kIOReturnSuccess != ret) {
			ivars->dataServicedAction = NULL;
		}
	}
	if (ivars->dataServicedAction) {
		ivars->dataQueue->needServicedCallback = false;
		DataServiced(ivars->dataServicedAction);
	}
}

kern_return_t
IODataQueueDispatchSource::SetEnableWithCompletion_Impl(
	bool enable,
	IODispatchSourceCancelHandler handler)
{
	IOReturn ret;

#if !KERNEL
	ivars->enable = enable;
#endif

	ret = kIOReturnSuccess;
	return ret;
}

void
IODataQueueDispatchSource::free()
{
	OSSafeReleaseNULL(ivars->memory);
	OSSafeReleaseNULL(ivars->dataAvailableAction);
	OSSafeReleaseNULL(ivars->dataServicedAction);
	IOSafeDeleteNULL(ivars, IODataQueueDispatchSource_IVars, 1);
	super::free();
}

kern_return_t
IODataQueueDispatchSource::Cancel_Impl(
	IODispatchSourceCancelHandler handler)
{
	return kIOReturnSuccess;
}

bool
IODataQueueDispatchSource::IsDataAvailable(void)
{
	IODataQueueMemory *dataQueue = ivars->dataQueue;

	return dataQueue && (dataQueue->head != dataQueue->tail);
}

kern_return_t
IODataQueueDispatchSource::Peek(IODataQueueClientDequeueEntryBlock callback)
{
	IODataQueueEntry *  entry = NULL;
	IODataQueueMemory * dataQueue;
	uint32_t            callerDataSize;
	uint32_t            dataSize;
	uint32_t            headOffset;
	uint32_t            tailOffset;

	dataQueue = ivars->dataQueue;
	if (!dataQueue) {
		return kIOReturnNoMemory;
	}

	// Read head and tail with acquire barrier
	headOffset = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->head, __ATOMIC_RELAXED);
	tailOffset = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->tail, __ATOMIC_ACQUIRE);

	if (headOffset != tailOffset) {
		IODataQueueEntry *  head        = NULL;
		uint32_t            headSize    = 0;
		uint32_t            queueSize   = ivars->queueByteCount;

		if (headOffset > queueSize) {
			return kIOReturnError;
		}

		head     = (IODataQueueEntry *)((uintptr_t)dataQueue->queue + headOffset);
		callerDataSize = head->size;
		if (os_add_overflow(3, callerDataSize, &headSize)) {
			return kIOReturnError;
		}
		headSize &= ~3U;

		// Check if there's enough room before the end of the queue for a header.
		// If there is room, check if there's enough room to hold the header and
		// the data.

		if ((headOffset > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) ||
		    (headOffset + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize) ||
		    (headOffset + DATA_QUEUE_ENTRY_HEADER_SIZE > UINT32_MAX - headSize) ||
		    (headOffset + headSize + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize)) {
			// No room for the header or the data, wrap to the beginning of the queue.
			// Note: wrapping even with the UINT32_MAX checks, as we have to support
			// queueSize of UINT32_MAX
			entry = dataQueue->queue;
			callerDataSize  = entry->size;
			dataSize = entry->size;
			if (os_add_overflow(3, callerDataSize, &dataSize)) {
				return kIOReturnError;
			}
			dataSize &= ~3U;

			if ((dataSize > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) ||
			    (dataSize + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize)) {
				return kIOReturnError;
			}

			callback(&entry->data, callerDataSize);
			return kIOReturnSuccess;
		} else {
			callback(&head->data, callerDataSize);
			return kIOReturnSuccess;
		}
	}

	return kIOReturnUnderrun;
}

kern_return_t
IODataQueueDispatchSource::Dequeue(IODataQueueClientDequeueEntryBlock callback)
{
	kern_return_t ret;
	bool          sendDataServiced;

	sendDataServiced = false;
	ret = DequeueWithCoalesce(&sendDataServiced, callback);
	if (sendDataServiced) {
		SendDataServiced();
	}
	return ret;
}

kern_return_t
IODataQueueDispatchSource::DequeueWithCoalesce(bool * sendDataServiced,
    IODataQueueClientDequeueEntryBlock callback)
{
	IOReturn            retVal          = kIOReturnSuccess;
	IODataQueueEntry *  entry           = NULL;
	IODataQueueMemory * dataQueue;
	uint32_t            callerDataSize;
	uint32_t            dataSize        = 0;
	uint32_t            headOffset      = 0;
	uint32_t            tailOffset      = 0;
	uint32_t            newHeadOffset   = 0;

	dataQueue = ivars->dataQueue;
	if (!dataQueue) {
		return kIOReturnNoMemory;
	}

	// Read head and tail with acquire barrier
	headOffset = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->head, __ATOMIC_RELAXED);
	tailOffset = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->tail, __ATOMIC_ACQUIRE);

	if (headOffset != tailOffset) {
		IODataQueueEntry *  head        = NULL;
		uint32_t            headSize    = 0;
		uint32_t            queueSize   = ivars->queueByteCount;

		if (headOffset > queueSize) {
			return kIOReturnError;
		}

		head = (IODataQueueEntry *)((uintptr_t)dataQueue->queue + headOffset);
		callerDataSize = head->size;
		if (os_add_overflow(3, callerDataSize, &headSize)) {
			return kIOReturnError;
		}
		headSize &= ~3U;

		// we wrapped around to beginning, so read from there
		// either there was not even room for the header
		if ((headOffset > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) ||
		    (headOffset + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize) ||
		    // or there was room for the header, but not for the data
		    (headOffset + DATA_QUEUE_ENTRY_HEADER_SIZE > UINT32_MAX - headSize) ||
		    (headOffset + headSize + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize)) {
			// Note: we have to wrap to the beginning even with the UINT32_MAX checks
			// because we have to support a queueSize of UINT32_MAX.
			entry           = dataQueue->queue;
			callerDataSize  = entry->size;

			if (os_add_overflow(callerDataSize, 3, &dataSize)) {
				return kIOReturnError;
			}
			dataSize &= ~3U;
			if ((dataSize > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) ||
			    (dataSize + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize)) {
				return kIOReturnError;
			}
			newHeadOffset   = dataSize + DATA_QUEUE_ENTRY_HEADER_SIZE;
			// else it is at the end
		} else {
			entry = head;

			if ((headSize > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) ||
			    (headSize + DATA_QUEUE_ENTRY_HEADER_SIZE > UINT32_MAX - headOffset) ||
			    (headSize + DATA_QUEUE_ENTRY_HEADER_SIZE + headOffset > queueSize)) {
				return kIOReturnError;
			}
			newHeadOffset   = headOffset + headSize + DATA_QUEUE_ENTRY_HEADER_SIZE;
		}
	} else {
		// empty queue
		if (dataQueue->needServicedCallback) {
			*sendDataServiced = true;
		}
		return kIOReturnUnderrun;
	}

	callback(&entry->data, callerDataSize);
	if (dataQueue->needServicedCallback) {
		*sendDataServiced = true;
	}

	__c11_atomic_store((_Atomic uint32_t *)&dataQueue->head, newHeadOffset, __ATOMIC_RELEASE);

	if (newHeadOffset == tailOffset) {
		//
		// If we are making the queue empty, then we need to make sure
		// that either the enqueuer notices, or we notice the enqueue
		// that raced with our making of the queue empty.
		//
		__c11_atomic_thread_fence(__ATOMIC_SEQ_CST);
	}

	return retVal;
}

kern_return_t
IODataQueueDispatchSource::Enqueue(uint32_t callerDataSize,
    IODataQueueClientEnqueueEntryBlock callback)
{
	kern_return_t ret;
	bool          sendDataAvailable;

	sendDataAvailable = false;
	ret = EnqueueWithCoalesce(callerDataSize, &sendDataAvailable, callback);
	if (sendDataAvailable) {
		SendDataAvailable();
	}
	return ret;
}

kern_return_t
IODataQueueDispatchSource::EnqueueWithCoalesce(uint32_t callerDataSize,
    bool * sendDataAvailable,
    IODataQueueClientEnqueueEntryBlock callback)
{
	IODataQueueMemory * dataQueue;
	IODataQueueEntry *  entry;
	uint32_t            head;
	uint32_t            tail;
	uint32_t            newTail;
	uint32_t                        dataSize;
	uint32_t            queueSize;
	uint32_t            entrySize;
	IOReturn            retVal = kIOReturnSuccess;

	dataQueue = ivars->dataQueue;
	if (!dataQueue) {
		return kIOReturnNoMemory;
	}
	queueSize = ivars->queueByteCount;

	// Force a single read of head and tail
	tail = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->tail, __ATOMIC_RELAXED);
	head = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->head, __ATOMIC_ACQUIRE);

	if (os_add_overflow(callerDataSize, 3, &dataSize)) {
		return kIOReturnOverrun;
	}
	dataSize &= ~3U;

	// Check for overflow of entrySize
	if (os_add_overflow(DATA_QUEUE_ENTRY_HEADER_SIZE, dataSize, &entrySize)) {
		return kIOReturnOverrun;
	}

	// Check for underflow of (getQueueSize() - tail)
	if (queueSize < tail || queueSize < head) {
		return kIOReturnUnderrun;
	}

	newTail = tail;
	if (tail >= head) {
		// Is there enough room at the end for the entry?
		if ((entrySize <= (UINT32_MAX - tail)) &&
		    ((tail + entrySize) <= queueSize)) {
			entry = (IODataQueueEntry *)((uintptr_t)dataQueue->queue + tail);

			callback(&entry->data, callerDataSize);

			entry->size = callerDataSize;

			// The tail can be out of bound when the size of the new entry
			// exactly matches the available space at the end of the queue.
			// The tail can range from 0 to queueSize inclusive.

			newTail = tail + entrySize;
		} else if (head > entrySize) { // Is there enough room at the beginning?
			entry = (IODataQueueEntry *)((uintptr_t)dataQueue->queue);

			callback(&entry->data, callerDataSize);

			// Wrap around to the beginning, but do not allow the tail to catch
			// up to the head.

			entry->size = callerDataSize;

			// We need to make sure that there is enough room to set the size before
			// doing this. The user client checks for this and will look for the size
			// at the beginning if there isn't room for it at the end.

			if ((queueSize - tail) >= DATA_QUEUE_ENTRY_HEADER_SIZE) {
				((IODataQueueEntry *)((uintptr_t)dataQueue->queue + tail))->size = dataSize;
			}

			newTail = entrySize;
		} else {
			retVal = kIOReturnOverrun; // queue is full
		}
	} else {
		// Do not allow the tail to catch up to the head when the queue is full.
		// That's why the comparison uses a '>' rather than '>='.

		if ((head - tail) > entrySize) {
			entry = (IODataQueueEntry *)((uintptr_t)dataQueue->queue + tail);

			callback(&entry->data, callerDataSize);

			entry->size = callerDataSize;

			newTail = tail + entrySize;
		} else {
			retVal = kIOReturnOverrun; // queue is full
		}
	}

	// Send notification (via mach message) that data is available.

	if (retVal == kIOReturnSuccess) {
		// Publish the data we just enqueued
		__c11_atomic_store((_Atomic uint32_t *)&dataQueue->tail, newTail, __ATOMIC_RELEASE);

		if (tail != head) {
			//
			// The memory barrier below pairs with the one in dequeue
			// so that either our store to the tail cannot be missed by
			// the next dequeue attempt, or we will observe the dequeuer
			// making the queue empty.
			//
			// Of course, if we already think the queue is empty,
			// there's no point paying this extra cost.
			//
			__c11_atomic_thread_fence(__ATOMIC_SEQ_CST);
			head = __c11_atomic_load((_Atomic uint32_t *)&dataQueue->head, __ATOMIC_RELAXED);
		}

		if (tail == head) {
			// Send notification that data is now available.
			*sendDataAvailable = true;
			retVal = kIOReturnSuccess;
		}
	} else if (retVal == kIOReturnOverrun) {
		// ask to be notified of Dequeue()
		dataQueue->needServicedCallback = true;
		*sendDataAvailable = true;
	}

	return retVal;
}
