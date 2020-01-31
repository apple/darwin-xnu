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

#define __STDC_LIMIT_MACROS     // what are the C++ equivalents?
#include <stdint.h>

#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOKernelReporters.h>
#include "IOReporterDefs.h"


#define super IOReporter
OSDefineMetaClassAndStructors(IOHistogramReporter, IOReporter);

/* static */
IOHistogramReporter*
IOHistogramReporter::with(IOService *reportingService,
    IOReportCategories categories,
    uint64_t channelID,
    const char *channelName,
    IOReportUnit unit,
    int nSegments,
    IOHistogramSegmentConfig *config)
{
	IOHistogramReporter *reporter = new IOHistogramReporter;

	const OSSymbol *tmpChannelName = NULL;

	if (reporter) {
		if (channelName) {
			tmpChannelName = OSSymbol::withCString(channelName);
		}

		if (reporter->initWith(reportingService, categories,
		    channelID, tmpChannelName,
		    unit, nSegments, config)) {
			return reporter;
		}
	}
	OSSafeReleaseNULL(reporter);
	OSSafeReleaseNULL(tmpChannelName);

	return 0;
}


bool
IOHistogramReporter::initWith(IOService *reportingService,
    IOReportCategories categories,
    uint64_t channelID,
    const OSSymbol *channelName,
    IOReportUnit unit,
    int nSegments,
    IOHistogramSegmentConfig *config)
{
	bool            result = false;
	IOReturn        res;    // for PREFL_MEMOP
	size_t          configSize, elementsSize, eCountsSize, boundsSize;
	int             cnt, cnt2, cnt3 = 0;
	int64_t        bucketBound = 0, previousBucketBound = 0;

	// analyzer appeasement
	configSize = elementsSize = eCountsSize = boundsSize = 0;

	IORLOG("IOHistogramReporter::initWith");

	// For now, this reporter is currently limited to a single channel
	_nChannels = 1;

	IOReportChannelType channelType = {
		.categories = categories,
		.report_format = kIOReportFormatHistogram,
		.nelements = 0, // Initialized when Config is unpacked
		.element_idx = 0
	};

	if (super::init(reportingService, channelType, unit) != true) {
		IORLOG("%s - ERROR: super::init failed", __func__);
		result = false;
		goto finish;
	}

	// Make sure to call this after the commit init phase
	if (channelName) {
		_channelNames->setObject(channelName);
	}

	_segmentCount = nSegments;
	if (_segmentCount == 0) {
		IORLOG("IOReportHistogram init ERROR. No configuration provided!");
		result = false;
		goto finish;
	}

	IORLOG("%s - %u segment(s)", __func__, _segmentCount);

	PREFL_MEMOP_FAIL(_segmentCount, IOHistogramSegmentConfig);
	configSize = (size_t)_segmentCount * sizeof(IOHistogramSegmentConfig);
	_histogramSegmentsConfig = (IOHistogramSegmentConfig*)IOMalloc(configSize);
	if (!_histogramSegmentsConfig) {
		goto finish;
	}
	memcpy(_histogramSegmentsConfig, config, configSize);

	// Find out how many elements are need to store the histogram
	for (cnt = 0; cnt < _segmentCount; cnt++) {
		_nElements += _histogramSegmentsConfig[cnt].segment_bucket_count;
		_channelDimension += _histogramSegmentsConfig[cnt].segment_bucket_count;

		IORLOG("\t\t bucket_base_width: %u | log_scale: %u | buckets: %u",
		    _histogramSegmentsConfig[cnt].base_bucket_width,
		    _histogramSegmentsConfig[cnt].scale_flag,
		    _histogramSegmentsConfig[cnt].segment_bucket_count);

		if (_histogramSegmentsConfig[cnt].scale_flag > 1
		    || _histogramSegmentsConfig[cnt].base_bucket_width == 0) {
			result = false;
			goto finish;
		}
	}

	// Update the channel type with discovered dimension
	_channelType.nelements = _channelDimension;

	IORLOG("%s - %u channel(s) of dimension %u",
	    __func__, _nChannels, _channelDimension);

	IORLOG("%s %d segments for a total dimension of %d elements",
	    __func__, _nChannels, _nElements);

	// Allocate memory for the array of report elements
	PREFL_MEMOP_FAIL(_nElements, IOReportElement);
	elementsSize = (size_t)_nElements * sizeof(IOReportElement);
	_elements = (IOReportElement *)IOMalloc(elementsSize);
	if (!_elements) {
		goto finish;
	}
	memset(_elements, 0, elementsSize);

	// Allocate memory for the array of element watch count
	PREFL_MEMOP_FAIL(_nElements, int);
	eCountsSize = (size_t)_nChannels * sizeof(int);
	_enableCounts = (int *)IOMalloc(eCountsSize);
	if (!_enableCounts) {
		goto finish;
	}
	memset(_enableCounts, 0, eCountsSize);

	lockReporter();
	for (cnt2 = 0; cnt2 < _channelDimension; cnt2++) {
		IOHistogramReportValues hist_values;
		if (copyElementValues(cnt2, (IOReportElementValues*)&hist_values)) {
			goto finish;
		}
		hist_values.bucket_min = kIOReportInvalidIntValue;
		hist_values.bucket_max = kIOReportInvalidIntValue;
		hist_values.bucket_sum = kIOReportInvalidIntValue;
		if (setElementValues(cnt2, (IOReportElementValues*)&hist_values)) {
			goto finish;
		}

		// Setup IOReporter's channel IDs
		_elements[cnt2].channel_id = channelID;

		// Setup IOReporter's reporting provider service
		_elements[cnt2].provider_id = _driver_id;

		// Setup IOReporter's channel type
		_elements[cnt2].channel_type = _channelType;
		_elements[cnt2].channel_type.element_idx = cnt2;

		//IOREPORTER_DEBUG_ELEMENT(cnt2);
	}
	unlockReporter();

	// Allocate memory for the bucket upper bounds
	PREFL_MEMOP_FAIL(_nElements, uint64_t);
	boundsSize = (size_t)_nElements * sizeof(uint64_t);
	_bucketBounds = (int64_t*)IOMalloc(boundsSize);
	if (!_bucketBounds) {
		goto finish;
	}
	memset(_bucketBounds, 0, boundsSize);
	_bucketCount = _nElements;

	for (cnt = 0; cnt < _segmentCount; cnt++) {
		if (_histogramSegmentsConfig[cnt].segment_bucket_count > INT_MAX
		    || _histogramSegmentsConfig[cnt].base_bucket_width > INT_MAX) {
			goto finish;
		}
		for (cnt2 = 0; cnt2 < (int)_histogramSegmentsConfig[cnt].segment_bucket_count; cnt2++) {
			if (cnt3 >= _nElements) {
				IORLOG("ERROR: _bucketBounds init");
				result = false;
				goto finish;
			}

			if (_histogramSegmentsConfig[cnt].scale_flag) {
				// FIXME: Could use pow() but not sure how to include math.h
				int64_t power = 1;
				int exponent = cnt2 + 1;
				while (exponent) {
					power *= _histogramSegmentsConfig[cnt].base_bucket_width;
					exponent--;
				}
				bucketBound = power;
			} else {
				bucketBound = _histogramSegmentsConfig[cnt].base_bucket_width *
				    ((unsigned)cnt2 + 1);
			}

			if (previousBucketBound >= bucketBound) {
				IORLOG("Histogram ERROR: bucket bound does not increase linearly (segment %u / bucket # %u)",
				    cnt, cnt2);
				result = false;
				goto finish;
			}

			_bucketBounds[cnt3] = bucketBound;
			// IORLOG("_bucketBounds[%u] = %llu", cnt3, bucketBound);
			previousBucketBound = _bucketBounds[cnt3];
			cnt3++;
		}
	}

	// success
	result = true;

finish:
	return result;
}


void
IOHistogramReporter::free(void)
{
	if (_bucketBounds) {
		PREFL_MEMOP_PANIC(_nElements, int64_t);
		IOFree(_bucketBounds, (size_t)_nElements * sizeof(int64_t));
	}
	if (_histogramSegmentsConfig) {
		PREFL_MEMOP_PANIC(_segmentCount, IOHistogramSegmentConfig);
		IOFree(_histogramSegmentsConfig,
		    (size_t)_segmentCount * sizeof(IOHistogramSegmentConfig));
	}

	super::free();
}


IOReportLegendEntry*
IOHistogramReporter::handleCreateLegend(void)
{
	IOReportLegendEntry     *rval = NULL, *legendEntry = NULL;
	OSData                  *tmpConfigData = NULL;
	OSDictionary            *tmpDict;   // no refcount

	legendEntry = super::handleCreateLegend();
	if (!legendEntry) {
		goto finish;
	}

	PREFL_MEMOP_PANIC(_segmentCount, IOHistogramSegmentConfig);
	tmpConfigData = OSData::withBytes(_histogramSegmentsConfig,
	    (unsigned)_segmentCount *
	    sizeof(IOHistogramSegmentConfig));
	if (!tmpConfigData) {
		goto finish;
	}

	tmpDict = OSDynamicCast(OSDictionary,
	    legendEntry->getObject(kIOReportLegendInfoKey));
	if (!tmpDict) {
		goto finish;
	}

	tmpDict->setObject(kIOReportLegendConfigKey, tmpConfigData);

	// success
	rval = legendEntry;

finish:
	if (tmpConfigData) {
		tmpConfigData->release();
	}
	if (!rval && legendEntry) {
		legendEntry->release();
	}

	return rval;
}

IOReturn
IOHistogramReporter::overrideBucketValues(unsigned int index,
    uint64_t bucket_hits,
    int64_t bucket_min,
    int64_t bucket_max,
    int64_t bucket_sum)
{
	IOReturn result;
	IOHistogramReportValues bucket;
	lockReporter();

	if (index >= (unsigned int)_bucketCount) {
		result = kIOReturnBadArgument;
		goto finish;
	}

	bucket.bucket_hits = bucket_hits;
	bucket.bucket_min = bucket_min;
	bucket.bucket_max = bucket_max;
	bucket.bucket_sum = bucket_sum;

	result = setElementValues(index, (IOReportElementValues *)&bucket);
finish:
	unlockReporter();
	return result;
}

int
IOHistogramReporter::tallyValue(int64_t value)
{
	int result = -1;
	int cnt = 0, element_index = 0;
	IOHistogramReportValues hist_values;

	lockReporter();

	// Iterate over _bucketCount minus one to make last bucket of infinite width
	for (cnt = 0; cnt < _bucketCount - 1; cnt++) {
		if (value <= _bucketBounds[cnt]) {
			break;
		}
	}

	element_index = cnt;

	if (copyElementValues(element_index, (IOReportElementValues *)&hist_values) != kIOReturnSuccess) {
		goto finish;
	}

	// init stats on first hit
	if (hist_values.bucket_hits == 0) {
		hist_values.bucket_min = hist_values.bucket_max = value;
		hist_values.bucket_sum = 0; // += is below
	}

	// update all values
	if (value < hist_values.bucket_min) {
		hist_values.bucket_min = value;
	} else if (value > hist_values.bucket_max) {
		hist_values.bucket_max = value;
	}
	hist_values.bucket_sum += value;
	hist_values.bucket_hits++;

	if (setElementValues(element_index, (IOReportElementValues *)&hist_values)
	    != kIOReturnSuccess) {
		goto finish;
	}

	// success!
	result = element_index;

finish:
	unlockReporter();
	return result;
}
