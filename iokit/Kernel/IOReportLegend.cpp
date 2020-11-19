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

#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOKernelReporters.h>


//#define IORDEBUG_LEGEND 1

#ifdef IORDEBUG_LEGEND
    #define IORLEGENDLOG(fmt, args...)      \
    do {                                    \
	IOLog("IOReportLegend | ");         \
	IOLog(fmt, ##args);                 \
	IOLog("\n");                        \
    } while(0)
#else
    #define IORLEGENDLOG(fmt, args...)
#endif


#define super OSObject
OSDefineMetaClassAndStructors(IOReportLegend, OSObject);

OSSharedPtr<IOReportLegend>
IOReportLegend::with(OSArray *legend)
{
	OSSharedPtr<IOReportLegend> iorLegend = OSMakeShared<IOReportLegend>();

	if (iorLegend) {
		if (legend != NULL) {
			if (iorLegend->initWith(legend) != kIOReturnSuccess) {
				return nullptr;
			}
		}

		return iorLegend;
	} else {
		return nullptr;
	}
}

/* must clean up everything if it fails */
IOReturn
IOReportLegend::initWith(OSArray *legend)
{
	if (legend) {
		_reportLegend = OSArray::withArray(legend);
	}

	if (_reportLegend == NULL) {
		return kIOReturnError;
	} else {
		return kIOReturnSuccess;
	}
}


void
IOReportLegend::free(void)
{
	super::free();
}


OSArray*
IOReportLegend::getLegend(void)
{
	return _reportLegend.get();
}

IOReturn
IOReportLegend::addReporterLegend(IOService *reportingService,
    IOReporter *reporter,
    const char *groupName,
    const char *subGroupName)
{
	IOReturn res = kIOReturnError;
	OSSharedPtr<IOReportLegend> legend;
	OSSharedPtr<OSObject> curLegend;

	// No need to check groupName and subGroupName because optional params
	if (!reportingService || !reporter) {
		goto finish;
	}

	// It's fine if the legend doesn't exist (IOReportLegend::with(NULL)
	// is how you make an empty legend).  If it's not an array, then
	// we're just going to replace it.
	curLegend = reportingService->copyProperty(kIOReportLegendKey);
	legend = IOReportLegend::with(OSDynamicCast(OSArray, curLegend.get()));
	if (!legend) {
		goto finish;
	}

	// Add the reporter's entries and update the service property.
	// The overwrite triggers a release of the old legend array.
	legend->addReporterLegend(reporter, groupName, subGroupName);
	reportingService->setProperty(kIOReportLegendKey, legend->getLegend());
	reportingService->setProperty(kIOReportLegendPublicKey, true);

	res = kIOReturnSuccess;

finish:
	return res;
}


IOReturn
IOReportLegend::addLegendEntry(IOReportLegendEntry *legendEntry,
    const char *groupName,
    const char *subGroupName)
{
	kern_return_t res = kIOReturnError;
	OSSharedPtr<const OSSymbol> tmpGroupName;
	OSSharedPtr<const OSSymbol> tmpSubGroupName;

	if (!legendEntry) {
		return res;
	}

	if (groupName) {
		tmpGroupName = OSSymbol::withCString(groupName);
	}

	if (subGroupName) {
		tmpSubGroupName = OSSymbol::withCString(subGroupName);
	}

	// It is ok to call appendLegendWith() if tmpGroups are NULL
	res = organizeLegend(legendEntry, tmpGroupName.get(), tmpSubGroupName.get());

	return res;
}


IOReturn
IOReportLegend::addReporterLegend(IOReporter *reporter,
    const char *groupName,
    const char *subGroupName)
{
	IOReturn res = kIOReturnError;
	OSSharedPtr<IOReportLegendEntry> legendEntry;

	if (reporter) {
		legendEntry = reporter->createLegend();

		if (legendEntry) {
			res = addLegendEntry(legendEntry.get(), groupName, subGroupName);
		}
	}

	return res;
}


IOReturn
IOReportLegend::organizeLegend(IOReportLegendEntry *legendEntry,
    const OSSymbol *groupName,
    const OSSymbol *subGroupName)
{
	if (!legendEntry) {
		return kIOReturnBadArgument;
	}

	if (!groupName && subGroupName) {
		return kIOReturnBadArgument;
	}

	IORLEGENDLOG("IOReportLegend::organizeLegend");
	// Legend is empty, enter first node
	if (_reportLegend == NULL) {
		IORLEGENDLOG("IOReportLegend::new legend creation");
		_reportLegend = OSArray::withCapacity(1);

		if (!_reportLegend) {
			return kIOReturnNoMemory;
		}
	}

	if (groupName) {
		legendEntry->setObject(kIOReportLegendGroupNameKey, groupName);
	}

	if (subGroupName) {
		legendEntry->setObject(kIOReportLegendSubGroupNameKey, subGroupName);
	}

	_reportLegend->setObject(legendEntry);

	// callers can now safely release legendEntry (it is part of _reportLegend)

	return kIOReturnSuccess;
}
