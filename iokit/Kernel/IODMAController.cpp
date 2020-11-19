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

#define IOKIT_ENABLE_SHARED_PTR

#include <IOKit/IODMAController.h>
#include <libkern/c++/OSSharedPtr.h>


#define super IOService
OSDefineMetaClassAndAbstractStructors(IODMAController, IOService);

OSSharedPtr<const OSSymbol>
IODMAController::createControllerName(UInt32 phandle)
{
#define CREATE_BUF_LEN 48
	char           buf[CREATE_BUF_LEN];

	snprintf(buf, CREATE_BUF_LEN, "IODMAController%08X", (uint32_t)phandle);

	return OSSymbol::withCString(buf);
}

IODMAController *
IODMAController::getController(IOService *provider, UInt32 dmaIndex)
{
	OSData          *dmaParentData;
	OSSharedPtr<const OSSymbol> dmaParentName;
	IODMAController *dmaController;

	// Find the name of the parent dma controller
	OSSharedPtr<OSObject> prop = provider->copyProperty("dma-parent");
	dmaParentData = OSDynamicCast(OSData, prop.get());
	if (dmaParentData == NULL) {
		return NULL;
	}

	if (dmaParentData->getLength() == sizeof(UInt32)) {
		dmaParentName = createControllerName(*(UInt32 *)dmaParentData->getBytesNoCopy());
	} else {
		if (dmaIndex >= dmaParentData->getLength() / sizeof(UInt32)) {
			panic("dmaIndex out of range");
		}
		dmaParentName = createControllerName(*(UInt32 *)dmaParentData->getBytesNoCopy(dmaIndex * sizeof(UInt32), sizeof(UInt32)));
	}
	if (dmaParentName == NULL) {
		return NULL;
	}

	// Wait for the parent dma controller
	dmaController = OSDynamicCast(IODMAController, IOService::waitForService( IOService::nameMatching(dmaParentName.get()).detach()));

	return dmaController;
}


bool
IODMAController::start(IOService *provider)
{
	if (!super::start(provider)) {
		return false;
	}

	_provider = provider;

	return true;
}


// protected

void
IODMAController::registerDMAController(IOOptionBits options)
{
	OSData *phandleData;

	OSSharedPtr<OSObject> prop = _provider->copyProperty("AAPL,phandle");
	phandleData = OSDynamicCast(OSData, prop.get());

	_dmaControllerName = createControllerName(*(UInt32 *)phandleData->getBytesNoCopy());

	setName(_dmaControllerName.get());

	registerService(options | ((options & kIOServiceAsynchronous) ? 0 : kIOServiceSynchronous));
}

void
IODMAController::completeDMACommand(IODMAEventSource *dmaES, IODMACommand *dmaCommand)
{
	dmaES->completeDMACommand(dmaCommand);
}

void
IODMAController::notifyDMACommand(IODMAEventSource *dmaES, IODMACommand *dmaCommand, IOReturn status, IOByteCount actualByteCount, AbsoluteTime timeStamp)
{
	dmaES->notifyDMACommand(dmaCommand, status, actualByteCount, timeStamp);
}


// private
