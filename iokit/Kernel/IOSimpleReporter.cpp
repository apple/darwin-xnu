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

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSSharedPtr.h>
#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOKernelReporters.h>
#include "IOReporterDefs.h"

#define super IOReporter
OSDefineMetaClassAndStructors(IOSimpleReporter, IOReporter);

/* static */
OSSharedPtr<IOSimpleReporter>
IOSimpleReporter::with(IOService *reportingService,
    IOReportCategories categories,
    IOReportUnit unit)
{
	OSSharedPtr<IOSimpleReporter> reporter;

	reporter = OSMakeShared<IOSimpleReporter>();
	if (!reporter) {
		return nullptr;
	}

	if (!reporter->initWith(reportingService, categories, unit)) {
		return nullptr;
	}

	return reporter;
}

bool
IOSimpleReporter::initWith(IOService *reportingService,
    IOReportCategories categories,
    IOReportUnit unit)
{
	// fully specify the channel type for the superclass
	IOReportChannelType channelType = {
		.categories = categories,
		.report_format = kIOReportFormatSimple,
		.nelements = 1,
		.element_idx = 0
	};

	return super::init(reportingService, channelType, unit);
}


IOReturn
IOSimpleReporter::setValue(uint64_t channel_id,
    int64_t value)
{
	IOReturn res = kIOReturnError;
	IOSimpleReportValues simple_values;
	int element_index = 0;

	lockReporter();

	if (getFirstElementIndex(channel_id, &element_index) != kIOReturnSuccess) {
		res = kIOReturnBadArgument;
		goto finish;
	}


	if (copyElementValues(element_index, (IOReportElementValues *)&simple_values) != kIOReturnSuccess) {
		res = kIOReturnBadArgument;
		goto finish;
	}

	simple_values.simple_value = value;
	res = setElementValues(element_index, (IOReportElementValues *)&simple_values);

finish:
	unlockReporter();
	return res;
}


IOReturn
IOSimpleReporter::incrementValue(uint64_t channel_id,
    int64_t increment)
{
	IOReturn res = kIOReturnError;
	IOSimpleReportValues simple_values;
	int element_index = 0;

	lockReporter();

	if (getFirstElementIndex(channel_id, &element_index) != kIOReturnSuccess) {
		res = kIOReturnBadArgument;
		goto finish;
	}

	if (copyElementValues(element_index, (IOReportElementValues *)&simple_values) != kIOReturnSuccess) {
		res = kIOReturnBadArgument;
		goto finish;
	}

	simple_values.simple_value += increment;

	res = setElementValues(element_index, (IOReportElementValues *)&simple_values);

finish:
	unlockReporter();
	return res;
}

int64_t
IOSimpleReporter::getValue(uint64_t channel_id)
{
	IOSimpleReportValues *values = NULL;
	int64_t simple_value = (int64_t)kIOReportInvalidValue;
	int index = 0;

	lockReporter();

	if (getFirstElementIndex(channel_id, &index) == kIOReturnSuccess) {
		values = (IOSimpleReportValues *)getElementValues(index);

		if (values != NULL) {
			simple_value = values->simple_value;
		}
	}

	unlockReporter();
	return simple_value;
}
