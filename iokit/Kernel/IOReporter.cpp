/*
 * Copyright (c) 2012-2013 Apple Computer, Inc.  All Rights Reserved.
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

#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOKernelReporters.h>
#include "IOReporterDefs.h"

#include <string.h>
#include <IOKit/IORegistryEntry.h>

#define super OSObject
OSDefineMetaClassAndStructors(IOReporter, OSObject);

// be careful to retain and release as necessary
static const OSSymbol *gIOReportNoChannelName = OSSymbol::withCString("_NO_NAME_4");

// * We might someday want an IOReportManager (vs. these static funcs)

/**************************************/
/***         STATIC METHODS         ***/
/**************************************/
IOReturn
IOReporter::configureAllReports(OSSet *reporters,
    IOReportChannelList *channelList,
    IOReportConfigureAction action,
    void *result,
    void *destination)
{
	IOReturn rval = kIOReturnError;
	OSCollectionIterator *iterator = NULL;

	if (reporters == NULL || channelList == NULL || result == NULL) {
		rval = kIOReturnBadArgument;
		goto finish;
	}

	switch (action) {
	case kIOReportGetDimensions:
	case kIOReportEnable:
	case kIOReportDisable:
	{
		OSObject * object;
		iterator = OSCollectionIterator::withCollection(reporters);

		while ((object = iterator->getNextObject())) {
			IOReporter *rep = OSDynamicCast(IOReporter, object);

			if (rep) {
				(void)rep->configureReport(channelList, action, result, destination);
			} else {
				rval = kIOReturnUnsupported; // kIOReturnNotFound?
				goto finish;
			}
		}

		break;
	}

	case kIOReportTraceOnChange:
	case kIOReportNotifyHubOnChange:
	default:
		rval = kIOReturnUnsupported;
		goto finish;
	}

	rval = kIOReturnSuccess;

finish:
	if (iterator) {
		iterator->release();
	}

	return rval;
}

// the duplication in these functions almost makes one want Objective-C SEL* ;)
IOReturn
IOReporter::updateAllReports(OSSet *reporters,
    IOReportChannelList *channelList,
    IOReportConfigureAction action,
    void *result,
    void *destination)
{
	IOReturn rval = kIOReturnError;
	OSCollectionIterator *iterator = NULL;

	if (reporters == NULL ||
	    channelList == NULL ||
	    result == NULL ||
	    destination == NULL) {
		rval = kIOReturnBadArgument;
		goto finish;
	}

	switch (action) {
	case kIOReportCopyChannelData:
	{
		OSObject * object;
		iterator = OSCollectionIterator::withCollection(reporters);

		while ((object = iterator->getNextObject())) {
			IOReporter *rep = OSDynamicCast(IOReporter, object);

			if (rep) {
				(void)rep->updateReport(channelList, action, result, destination);
			} else {
				rval = kIOReturnUnsupported; // kIOReturnNotFound?
				goto finish;
			}
		}

		break;
	}

	case kIOReportTraceChannelData:
	default:
		rval = kIOReturnUnsupported;
		goto finish;
	}

	rval = kIOReturnSuccess;

finish:
	if (iterator) {
		iterator->release();
	}

	return rval;
}


/**************************************/
/***       COMMON INIT METHODS      ***/
/**************************************/

bool
IOReporter::init(IOService *reportingService,
    IOReportChannelType channelType,
    IOReportUnit unit)
{
	bool success = false;

	// ::free() relies on these being initialized
	_reporterLock = NULL;
	_configLock = NULL;
	_elements = NULL;
	_enableCounts = NULL;
	_channelNames = NULL;

	if (channelType.report_format == kIOReportInvalidFormat) {
		IORLOG("init ERROR: Channel Type ill-defined");
		goto finish;
	}

	_driver_id = reportingService->getRegistryEntryID();
	if (_driver_id == 0) {
		IORLOG("init() ERROR: no registry ID");
		goto finish;
	}

	if (!super::init()) {
		return false;
	}

	_channelDimension = channelType.nelements;
	_channelType = channelType;
	// FIXME: need to look up dynamically
	if (unit == kIOReportUnitHWTicks) {
#if defined(__arm__) || defined(__arm64__)
		unit = kIOReportUnit24MHzTicks;
#elif defined(__i386__) || defined(__x86_64__)
		// Most, but not all Macs use 1GHz
		unit = kIOReportUnit1GHzTicks;
#else
#error kIOReportUnitHWTicks not defined
#endif
	}
	_unit = unit;

	// Allocate a reporter (data) lock
	_reporterLock = IOSimpleLockAlloc();
	if (!_reporterLock) {
		goto finish;
	}
	_reporterIsLocked = false;

	// Allocate a config lock
	_configLock = IOLockAlloc();
	if (!_configLock) {
		goto finish;
	}
	_reporterConfigIsLocked = false;

	// Allocate channel names array
	_channelNames = OSArray::withCapacity(1);
	if (!_channelNames) {
		goto finish;
	}

	// success
	success = true;

finish:
	return success;
}


/*******************************/
/***      PUBLIC METHODS     ***/
/*******************************/

// init() [possibly via init*()] must be called before free()
// to ensure that _<var> = NULL
void
IOReporter::free(void)
{
	OSSafeReleaseNULL(_channelNames);

	if (_configLock) {
		IOLockFree(_configLock);
	}
	if (_reporterLock) {
		IOSimpleLockFree(_reporterLock);
	}

	if (_elements) {
		PREFL_MEMOP_PANIC(_nElements, IOReportElement);
		IOFree(_elements, (size_t)_nElements * sizeof(IOReportElement));
	}
	if (_enableCounts) {
		PREFL_MEMOP_PANIC(_nChannels, int);
		IOFree(_enableCounts, (size_t)_nChannels * sizeof(int));
	}

	super::free();
}

/*
 #define TESTALLOC() do { \
 *   void *tbuf;                 \
 *   tbuf = IOMalloc(10);        \
 *   IOFree(tbuf, 10);           \
 *   IORLOG("%s:%d - _reporterIsLocked = %d & allocation successful", \
 *           __PRETTY_FUNCTION__, __LINE__, _reporterIsLocked); \
 *  } while (0);
 */
IOReturn
IOReporter::addChannel(uint64_t channelID,
    const char *channelName /* = NULL */)
{
	IOReturn res = kIOReturnError, kerr;
	const OSSymbol *symChannelName = NULL;
	int oldNChannels, newNChannels = 0, freeNChannels = 0;

	IORLOG("IOReporter::addChannel %llx", channelID);

	// protect instance variables (but not contents)
	lockReporterConfig();

	// FIXME: Check if any channel is already present and return error

	// addChannel() always adds one channel
	oldNChannels = _nChannels;
	if (oldNChannels < 0 || oldNChannels > INT_MAX - 1) {
		res = kIOReturnOverrun;
		goto finish;
	}
	newNChannels = oldNChannels + 1;
	freeNChannels = newNChannels;   // until swap success

	// Expand addChannel()-specific data structure
	if (_channelNames->ensureCapacity((unsigned)newNChannels) <
	    (unsigned)newNChannels) {
		res = kIOReturnNoMemory; goto finish;
	}
	if (channelName) {
		symChannelName = OSSymbol::withCString(channelName);
		if (!symChannelName) {
			res = kIOReturnNoMemory; goto finish;
		}
	} else {
		// grab a reference to our shared global
		symChannelName = gIOReportNoChannelName;
		symChannelName->retain();
	}

	// allocate new buffers into _swap* variables
	if ((kerr = handleSwapPrepare(newNChannels))) {
		// on error, channels are *not* swapped
		res = kerr; goto finish;
	}

	// exchange main and _swap* buffers with buffer contents protected
	// IOReporter::handleAddChannelSwap() also increments _nElements, etc
	lockReporter();
	res = handleAddChannelSwap(channelID, symChannelName);
	unlockReporter();
	// On failure, handleAddChannelSwap() leaves *new* buffers in _swap*.
	// On success, it's the old buffers, so we put the right size in here.
	if (res == kIOReturnSuccess) {
		freeNChannels = oldNChannels;
	}

finish:
	// free up not-in-use buffers (tracked by _swap*)
	handleSwapCleanup(freeNChannels);
	if (symChannelName) {
		symChannelName->release();
	}
	unlockReporterConfig();

	return res;
}


IOReportLegendEntry*
IOReporter::createLegend(void)
{
	IOReportLegendEntry *legendEntry = NULL;

	lockReporterConfig();

	legendEntry = handleCreateLegend();

	unlockReporterConfig();

	return legendEntry;
}


IOReturn
IOReporter::configureReport(IOReportChannelList *channelList,
    IOReportConfigureAction action,
    void *result,
    void *destination)
{
	IOReturn res = kIOReturnError;

	lockReporterConfig();

	res = handleConfigureReport(channelList, action, result, destination);

	unlockReporterConfig();

	return res;
}


IOReturn
IOReporter::updateReport(IOReportChannelList *channelList,
    IOReportConfigureAction action,
    void *result,
    void *destination)
{
	IOReturn res = kIOReturnError;

	lockReporter();

	res = handleUpdateReport(channelList, action, result, destination);

	unlockReporter();

	return res;
}


/*******************************/
/***    PROTECTED METHODS    ***/
/*******************************/


void
IOReporter::lockReporter()
{
	_interruptState = IOSimpleLockLockDisableInterrupt(_reporterLock);
	_reporterIsLocked = true;
}


void
IOReporter::unlockReporter()
{
	_reporterIsLocked = false;
	IOSimpleLockUnlockEnableInterrupt(_reporterLock, _interruptState);
}

void
IOReporter::lockReporterConfig()
{
	IOLockLock(_configLock);
	_reporterConfigIsLocked = true;
}

void
IOReporter::unlockReporterConfig()
{
	_reporterConfigIsLocked = false;
	IOLockUnlock(_configLock);
}


IOReturn
IOReporter::handleSwapPrepare(int newNChannels)
{
	IOReturn res = kIOReturnError;
	int newNElements;
	size_t newElementsSize, newECSize;

	// analyzer appeasement
	newElementsSize = newECSize = 0;

	//IORLOG("IOReporter::handleSwapPrepare");

	IOREPORTER_CHECK_CONFIG_LOCK();

	if (newNChannels < _nChannels) {
		panic("%s doesn't support shrinking", __func__);
	}
	if (newNChannels <= 0 || _channelDimension <= 0) {
		res = kIOReturnUnderrun;
		goto finish;
	}
	if (_swapElements || _swapEnableCounts) {
		panic("IOReporter::_swap* already in use");
	}

	// calculate the number of elements given #ch & the dimension of each
	if (newNChannels < 0 || newNChannels > INT_MAX / _channelDimension) {
		res = kIOReturnOverrun;
		goto finish;
	}
	newNElements = newNChannels * _channelDimension;

	// Allocate memory for the new array of report elements
	PREFL_MEMOP_FAIL(newNElements, IOReportElement);
	newElementsSize = (size_t)newNElements * sizeof(IOReportElement);
	_swapElements = (IOReportElement *)IOMalloc(newElementsSize);
	if (_swapElements == NULL) {
		res = kIOReturnNoMemory; goto finish;
	}
	memset(_swapElements, 0, newElementsSize);

	// Allocate memory for the new array of channel watch counts
	PREFL_MEMOP_FAIL(newNChannels, int);
	newECSize = (size_t)newNChannels * sizeof(int);
	_swapEnableCounts = (int *)IOMalloc(newECSize);
	if (_swapEnableCounts == NULL) {
		res = kIOReturnNoMemory; goto finish;
	}
	memset(_swapEnableCounts, 0, newECSize);

	// success
	res = kIOReturnSuccess;

finish:
	if (res) {
		if (_swapElements) {
			IOFree(_swapElements, newElementsSize);
			_swapElements = NULL;
		}
		if (_swapEnableCounts) {
			IOFree(_swapEnableCounts, newECSize);
			_swapEnableCounts = NULL;
		}
	}

	return res;
}


IOReturn
IOReporter::handleAddChannelSwap(uint64_t channel_id,
    const OSSymbol *symChannelName)
{
	IOReturn res = kIOReturnError;
	int cnt;
	int *tmpWatchCounts = NULL;
	IOReportElement *tmpElements = NULL;
	bool swapComplete = false;

	//IORLOG("IOReporter::handleSwap");

	IOREPORTER_CHECK_CONFIG_LOCK();
	IOREPORTER_CHECK_LOCK();

	if (!_swapElements || !_swapEnableCounts) {
		IORLOG("IOReporter::handleSwap ERROR swap variables uninitialized!");
		goto finish;
	}

	// Copy any existing elements to the new location
	//IORLOG("handleSwap (base) -> copying %u elements over...", _nChannels);
	if (_elements) {
		PREFL_MEMOP_PANIC(_nElements, IOReportElement);
		memcpy(_swapElements, _elements,
		    (size_t)_nElements * sizeof(IOReportElement));

		PREFL_MEMOP_PANIC(_nElements, int);
		memcpy(_swapEnableCounts, _enableCounts,
		    (size_t)_nChannels * sizeof(int));
	}

	// Update principal instance variables, keep old buffers for cleanup
	tmpElements = _elements;
	_elements = _swapElements;
	_swapElements = tmpElements;

	tmpWatchCounts = _enableCounts;
	_enableCounts = _swapEnableCounts;
	_swapEnableCounts = tmpWatchCounts;

	swapComplete = true;

	// but _nChannels & _nElements is still the old (one smaller) size

	// Initialize new element metadata (existing elements copied above)
	for (cnt = 0; cnt < _channelDimension; cnt++) {
		_elements[_nElements + cnt].channel_id = channel_id;
		_elements[_nElements + cnt].provider_id = _driver_id;
		_elements[_nElements + cnt].channel_type = _channelType;
		_elements[_nElements + cnt].channel_type.element_idx = cnt;

		//IOREPORTER_DEBUG_ELEMENT(_swapNElements + cnt);
	}

	// Store a channel name at the end
	if (!_channelNames->setObject((unsigned)_nChannels, symChannelName)) {
		// Should never happen because we ensured capacity in addChannel()
		res = kIOReturnNoMemory;
		goto finish;
	}

	// And update the metadata: addChannel() always adds just one channel
	_nChannels += 1;
	_nElements += _channelDimension;

	// success
	res = kIOReturnSuccess;

finish:
	if (res && swapComplete) {
		// unswap so new buffers get cleaned up instead of old
		tmpElements = _elements;
		_elements = _swapElements;
		_swapElements = tmpElements;

		tmpWatchCounts = _enableCounts;
		_enableCounts = _swapEnableCounts;
		_swapEnableCounts = tmpWatchCounts;
	}
	return res;
}

void
IOReporter::handleSwapCleanup(int swapNChannels)
{
	int swapNElements;

	if (!_channelDimension || swapNChannels > INT_MAX / _channelDimension) {
		panic("%s - can't free %d channels of dimension %d", __func__,
		    swapNChannels, _channelDimension);
	}
	swapNElements = swapNChannels * _channelDimension;

	IOREPORTER_CHECK_CONFIG_LOCK();

	// release buffers no longer used after swapping
	if (_swapElements) {
		PREFL_MEMOP_PANIC(swapNElements, IOReportElement);
		IOFree(_swapElements, (size_t)swapNElements * sizeof(IOReportElement));
		_swapElements = NULL;
	}
	if (_swapEnableCounts) {
		PREFL_MEMOP_PANIC(swapNChannels, int);
		IOFree(_swapEnableCounts, (size_t)swapNChannels * sizeof(int));
		_swapEnableCounts = NULL;
	}
}


// The reporter wants to know if its channels have observers.
// Eventually we'll add some sort of bool ::anyChannelsInUse() which
// clients can use to cull unused reporters after configureReport(disable).
IOReturn
IOReporter::handleConfigureReport(IOReportChannelList *channelList,
    IOReportConfigureAction action,
    void *result,
    void *destination)
{
	IOReturn res = kIOReturnError;
	int channel_index = 0;
	uint32_t chIdx;
	int *nElements, *nChannels;

	// Check on channelList and result because used below
	if (!channelList || !result) {
		goto finish;
	}

	//IORLOG("IOReporter::configureReport action %u for %u channels",
	//       action, channelList->nchannels);

	// Make sure channel is present, increase matching watch count, 'result'
	for (chIdx = 0; chIdx < channelList->nchannels; chIdx++) {
		if (getChannelIndex(channelList->channels[chIdx].channel_id,
		    &channel_index) == kIOReturnSuccess) {
			// IORLOG("reporter %p recognizes channel %lld", this, channelList->channels[chIdx].channel_id);

			switch (action) {
			case kIOReportEnable:
				nChannels = (int*)result;
				_enabled++;
				_enableCounts[channel_index]++;
				(*nChannels)++;
				break;

			case kIOReportDisable:
				nChannels = (int*)result;
				_enabled--;
				_enableCounts[channel_index]--;
				(*nChannels)++;
				break;

			case kIOReportGetDimensions:
				nElements = (int *)result;
				*nElements += _channelDimension;
				break;

			default:
				IORLOG("ERROR configureReport unknown action!");
				break;
			}
		}
	}

	// success
	res = kIOReturnSuccess;

finish:
	return res;
}


IOReturn
IOReporter::handleUpdateReport(IOReportChannelList *channelList,
    IOReportConfigureAction action,
    void *result,
    void *destination)
{
	IOReturn res = kIOReturnError;
	int *nElements = (int *)result;
	int channel_index = 0;
	uint32_t chIdx;
	IOBufferMemoryDescriptor *dest;

	if (!channelList || !result || !destination) {
		goto finish;
	}

	dest = OSDynamicCast(IOBufferMemoryDescriptor, (OSObject *)destination);
	if (dest == NULL) {
		// Invalid destination
		res = kIOReturnBadArgument;
		goto finish;
	}

	if (!_enabled) {
		goto finish;
	}

	for (chIdx = 0; chIdx < channelList->nchannels; chIdx++) {
		if (getChannelIndex(channelList->channels[chIdx].channel_id,
		    &channel_index) == kIOReturnSuccess) {
			//IORLOG("%s - found channel_id %llx @ index %d", __func__,
			//       channelList->channels[chIdx].channel_id,
			//       channel_index);

			switch (action) {
			case kIOReportCopyChannelData:
				res = updateChannelValues(channel_index);
				if (res) {
					IORLOG("ERROR: updateChannelValues() failed: %x", res);
					goto finish;
				}

				res = updateReportChannel(channel_index, nElements, dest);
				if (res) {
					IORLOG("ERROR: updateReportChannel() failed: %x", res);
					goto finish;
				}
				break;

			default:
				IORLOG("ERROR updateReport unknown action!");
				res = kIOReturnError;
				goto finish;
			}
		}
	}

	// success
	res = kIOReturnSuccess;

finish:
	return res;
}


IOReportLegendEntry*
IOReporter::handleCreateLegend(void)
{
	IOReportLegendEntry *legendEntry = NULL;
	OSArray *channelIDs;

	channelIDs = copyChannelIDs();

	if (channelIDs) {
		legendEntry = IOReporter::legendWith(channelIDs, _channelNames, _channelType, _unit);
		channelIDs->release();
	}

	return legendEntry;
}


IOReturn
IOReporter::setElementValues(int element_index,
    IOReportElementValues *values,
    uint64_t record_time /* = 0 */)
{
	IOReturn res = kIOReturnError;

	IOREPORTER_CHECK_LOCK();

	if (record_time == 0) {
		record_time = mach_absolute_time();
	}

	if (element_index >= _nElements || values == NULL) {
		res = kIOReturnBadArgument;
		goto finish;
	}

	memcpy(&_elements[element_index].values, values, sizeof(IOReportElementValues));

	_elements[element_index].timestamp = record_time;

	//IOREPORTER_DEBUG_ELEMENT(index);

	res = kIOReturnSuccess;

finish:
	return res;
}


const IOReportElementValues*
IOReporter::getElementValues(int element_index)
{
	IOReportElementValues *elementValues = NULL;

	IOREPORTER_CHECK_LOCK();

	if (element_index < 0 || element_index >= _nElements) {
		IORLOG("ERROR getElementValues out of bounds!");
		goto finish;
	}

	elementValues = &_elements[element_index].values;

finish:
	return elementValues;
}


IOReturn
IOReporter::updateChannelValues(int channel_index)
{
	return kIOReturnSuccess;
}


IOReturn
IOReporter::updateReportChannel(int channel_index,
    int *nElements,
    IOBufferMemoryDescriptor *destination)
{
	IOReturn res = kIOReturnError;
	int start_element_idx, chElems;
	size_t       size2cpy;

	res = kIOReturnBadArgument;
	if (!nElements || !destination) {
		goto finish;
	}
	if (channel_index > _nChannels) {
		goto finish;
	}

	IOREPORTER_CHECK_LOCK();

	res = kIOReturnOverrun;

	start_element_idx = channel_index * _channelDimension;
	if (start_element_idx >= _nElements) {
		goto finish;
	}

	chElems = _elements[start_element_idx].channel_type.nelements;

	// make sure we don't go beyond the end of _elements[_nElements-1]
	if (start_element_idx + chElems > _nElements) {
		goto finish;
	}

	PREFL_MEMOP_FAIL(chElems, IOReportElement);
	size2cpy = (size_t)chElems * sizeof(IOReportElement);

	// make sure there's space in the destination
	if (size2cpy > (destination->getCapacity() - destination->getLength())) {
		IORLOG("CRITICAL ERROR: Report Buffer Overflow (buffer cap %luB, length %luB, size2cpy %luB",
		    (unsigned long)destination->getCapacity(),
		    (unsigned long)destination->getLength(),
		    (unsigned long)size2cpy);
		goto finish;
	}

	destination->appendBytes(&_elements[start_element_idx], size2cpy);
	*nElements += chElems;

	res = kIOReturnSuccess;

finish:
	return res;
}


IOReturn
IOReporter::copyElementValues(int element_index,
    IOReportElementValues *elementValues)
{
	IOReturn res = kIOReturnError;

	if (!elementValues) {
		goto finish;
	}

	IOREPORTER_CHECK_LOCK();

	if (element_index >= _nElements) {
		IORLOG("ERROR getElementValues out of bounds!");
		res = kIOReturnBadArgument;
		goto finish;
	}

	memcpy(elementValues, &_elements[element_index].values, sizeof(IOReportElementValues));
	res = kIOReturnSuccess;

finish:
	return res;
}


IOReturn
IOReporter::getFirstElementIndex(uint64_t channel_id,
    int *index)
{
	IOReturn res = kIOReturnError;
	int channel_index = 0, element_index = 0;

	if (!index) {
		goto finish;
	}

	res = getChannelIndices(channel_id, &channel_index, &element_index);

	if (res == kIOReturnSuccess) {
		*index = element_index;
	}

finish:
	return res;
}


IOReturn
IOReporter::getChannelIndex(uint64_t channel_id,
    int *index)
{
	IOReturn res = kIOReturnError;
	int channel_index = 0, element_index = 0;

	if (!index) {
		goto finish;
	}

	res = getChannelIndices(channel_id, &channel_index, &element_index);

	if (res == kIOReturnSuccess) {
		*index = channel_index;
	}

finish:
	return res;
}


IOReturn
IOReporter::getChannelIndices(uint64_t channel_id,
    int *channel_index,
    int *element_index)
{
	IOReturn res = kIOReturnNotFound;
	int chIdx, elemIdx;

	if (!channel_index || !element_index) {
		goto finish;
	}

	for (chIdx = 0; chIdx < _nChannels; chIdx++) {
		elemIdx = chIdx * _channelDimension;
		if (elemIdx >= _nElements) {
			IORLOG("ERROR getChannelIndices out of bounds!");
			res = kIOReturnOverrun;
			goto finish;
		}

		if (channel_id == _elements[elemIdx].channel_id) {
			// The channel index does not care about the depth of elements...
			*channel_index = chIdx;
			*element_index = elemIdx;

			res = kIOReturnSuccess;
			goto finish;
		}
	}

finish:
	return res;
}

/********************************/
/***      PRIVATE METHODS     ***/
/********************************/


// copyChannelIDs relies on the caller to take lock
OSArray*
IOReporter::copyChannelIDs()
{
	int    cnt, cnt2;
	OSArray        *channelIDs = NULL;
	OSNumber       *tmpNum;

	channelIDs = OSArray::withCapacity((unsigned)_nChannels);

	if (!channelIDs) {
		goto finish;
	}

	for (cnt = 0; cnt < _nChannels; cnt++) {
		cnt2 = cnt * _channelDimension;

		// Encapsulate the Channel ID in OSNumber
		tmpNum = OSNumber::withNumber(_elements[cnt2].channel_id, 64);
		if (!tmpNum) {
			IORLOG("ERROR: Could not create array of channelIDs");
			channelIDs->release();
			channelIDs = NULL;
			goto finish;
		}

		channelIDs->setObject((unsigned)cnt, tmpNum);
		tmpNum->release();
	}

finish:
	return channelIDs;
}


// DO NOT REMOVE THIS METHOD WHICH IS THE MAIN LEGEND CREATION FUNCTION
/*static */ IOReportLegendEntry*
IOReporter::legendWith(OSArray *channelIDs,
    OSArray *channelNames,
    IOReportChannelType channelType,
    IOReportUnit unit)
{
	unsigned int            cnt, chCnt;
	uint64_t                type64;
	OSNumber                *tmpNum;
	const OSSymbol          *tmpSymbol;
	OSArray                 *channelLegendArray = NULL, *tmpChannelArray = NULL;
	OSDictionary            *channelInfoDict = NULL;
	IOReportLegendEntry     *legendEntry = NULL;

	// No need to check validity of channelNames because param is optional
	if (!channelIDs) {
		goto finish;
	}
	chCnt = channelIDs->getCount();

	channelLegendArray = OSArray::withCapacity(chCnt);

	for (cnt = 0; cnt < chCnt; cnt++) {
		tmpChannelArray = OSArray::withCapacity(3);

		// Encapsulate the Channel ID in OSNumber
		tmpChannelArray->setObject(kIOReportChannelIDIdx, channelIDs->getObject(cnt));

		// Encapsulate the Channel Type in OSNumber
		memcpy(&type64, &channelType, sizeof(type64));
		tmpNum = OSNumber::withNumber(type64, 64);
		if (!tmpNum) {
			goto finish;
		}
		tmpChannelArray->setObject(kIOReportChannelTypeIdx, tmpNum);
		tmpNum->release();

		// Encapsulate the Channel Name in OSSymbol
		// Use channelNames if provided
		if (channelNames != NULL) {
			tmpSymbol = OSDynamicCast(OSSymbol, channelNames->getObject(cnt));
			if (tmpSymbol && tmpSymbol != gIOReportNoChannelName) {
				tmpChannelArray->setObject(kIOReportChannelNameIdx, tmpSymbol);
			} // Else, skip and leave name field empty
		}

		channelLegendArray->setObject(cnt, tmpChannelArray);
		tmpChannelArray->release();
		tmpChannelArray = NULL;
	}

	// Stuff the legend entry only if we have channels...
	if (channelLegendArray->getCount() != 0) {
		channelInfoDict = OSDictionary::withCapacity(1);

		if (!channelInfoDict) {
			goto finish;
		}

		tmpNum = OSNumber::withNumber(unit, 64);
		if (tmpNum) {
			channelInfoDict->setObject(kIOReportLegendUnitKey, tmpNum);
			tmpNum->release();
		}

		legendEntry = OSDictionary::withCapacity(1);

		if (legendEntry) {
			legendEntry->setObject(kIOReportLegendChannelsKey, channelLegendArray);
			legendEntry->setObject(kIOReportLegendInfoKey, channelInfoDict);
		}
	}

finish:
	if (tmpChannelArray) {
		tmpChannelArray->release();
	}
	if (channelInfoDict) {
		channelInfoDict->release();
	}
	if (channelLegendArray) {
		channelLegendArray->release();
	}

	return legendEntry;
}
