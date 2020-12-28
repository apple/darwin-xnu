/*
 * Copyright (c) 1998-2016 Apple Inc. All rights reserved.
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
#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IODMACommand.h>
#include <libkern/c++/OSData.h>
#include <libkern/OSDebug.h>
#include <mach_debug/zone_info.h>
#include "IOKitKernelInternal.h"

__BEGIN_DECLS
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
__END_DECLS

#define super IOService
OSDefineMetaClassAndAbstractStructors(IOMapper, IOService);

OSMetaClassDefineReservedUnused(IOMapper, 0);
OSMetaClassDefineReservedUnused(IOMapper, 1);
OSMetaClassDefineReservedUnused(IOMapper, 2);
OSMetaClassDefineReservedUnused(IOMapper, 3);
OSMetaClassDefineReservedUnused(IOMapper, 4);
OSMetaClassDefineReservedUnused(IOMapper, 5);
OSMetaClassDefineReservedUnused(IOMapper, 6);
OSMetaClassDefineReservedUnused(IOMapper, 7);
OSMetaClassDefineReservedUnused(IOMapper, 8);
OSMetaClassDefineReservedUnused(IOMapper, 9);
OSMetaClassDefineReservedUnused(IOMapper, 10);
OSMetaClassDefineReservedUnused(IOMapper, 11);
OSMetaClassDefineReservedUnused(IOMapper, 12);
OSMetaClassDefineReservedUnused(IOMapper, 13);
OSMetaClassDefineReservedUnused(IOMapper, 14);
OSMetaClassDefineReservedUnused(IOMapper, 15);

IOMapper * IOMapper::gSystem = (IOMapper *) IOMapper::kUnknown;

class IOMapperLock {
	IOLock *fWaitLock;
public:
	IOMapperLock()
	{
		fWaitLock = IOLockAlloc();
	}
	~IOMapperLock()
	{
		IOLockFree(fWaitLock);
	}

	void
	lock()
	{
		IOLockLock(fWaitLock);
	}
	void
	unlock()
	{
		IOLockUnlock(fWaitLock);
	}
	void
	sleep(void *event)
	{
		IOLockSleep(fWaitLock, event, THREAD_UNINT);
	}
	void
	wakeup(void *event)
	{
		IOLockWakeup(fWaitLock, event, false);
	}
};

static IOMapperLock sMapperLock;

bool
IOMapper::start(IOService *provider)
{
	OSObject * obj;
	if (!super::start(provider)) {
		return false;
	}

	if (!initHardware(provider)) {
		return false;
	}

	fPageSize = getPageSize();

	if (fIsSystem) {
		sMapperLock.lock();
		IOMapper::gSystem = this;
		sMapperLock.wakeup(&IOMapper::gSystem);
		sMapperLock.unlock();
	}

	if (provider) {
		obj = provider->getProperty("iommu-id");
		if (!obj) {
			obj = provider->getProperty("AAPL,phandle");
		}
		if (obj) {
			setProperty(gIOMapperIDKey, obj);
		}
	}
	return true;
}

void
IOMapper::free()
{
	super::free();
}

void
IOMapper::setMapperRequired(bool hasMapper)
{
	if (hasMapper) {
		IOMapper::gSystem = (IOMapper *) kHasMapper;
	} else {
		sMapperLock.lock();
		IOMapper::gSystem = (IOMapper *) kNoMapper;
		sMapperLock.unlock();
		sMapperLock.wakeup(&IOMapper::gSystem);
	}
}

void
IOMapper::waitForSystemMapper()
{
	sMapperLock.lock();
	while ((uintptr_t) IOMapper::gSystem & kWaitMask) {
		OSReportWithBacktrace("waitForSystemMapper");
		sMapperLock.sleep(&IOMapper::gSystem);
	}
	sMapperLock.unlock();
}

IOMapper *
IOMapper::copyMapperForDevice(IOService * device)
{
	return copyMapperForDeviceWithIndex(device, 0);
}

IOMapper *
IOMapper::copyMapperForDeviceWithIndex(IOService * device, unsigned int index)
{
	OSData *data;
	OSObject * obj;
	IOMapper * mapper = NULL;
	OSDictionary * matching;

	obj = device->copyProperty("iommu-parent");
	if (!obj) {
		return NULL;
	}

	if ((mapper = OSDynamicCast(IOMapper, obj))) {
		goto found;
	}

	if ((data = OSDynamicCast(OSData, obj))) {
		if (index >= data->getLength() / sizeof(UInt32)) {
			goto done;
		}

		data = OSData::withBytesNoCopy((UInt32 *)data->getBytesNoCopy() + index, sizeof(UInt32));
		if (!data) {
			goto done;
		}

		matching = IOService::propertyMatching(gIOMapperIDKey, data);
		data->release();
	} else {
		matching = IOService::propertyMatching(gIOMapperIDKey, obj);
	}

	if (matching) {
		mapper = OSDynamicCast(IOMapper, IOService::waitForMatchingService(matching));
		matching->release();
	}

done:
	if (obj) {
		obj->release();
	}
found:
	if (mapper) {
		if (!mapper->fAllocName) {
			char name[MACH_ZONE_NAME_MAX_LEN];
			char kmodname[KMOD_MAX_NAME];
			vm_tag_t tag;
			uint32_t kmodid;

			tag = IOMemoryTag(kernel_map);
			if (!(kmodid = vm_tag_get_kext(tag, &kmodname[0], KMOD_MAX_NAME))) {
				snprintf(kmodname, sizeof(kmodname), "%d", tag);
			}
			snprintf(name, sizeof(name), "%s.DMA.%s", kmodname, device->getName());
			mapper->fAllocName = kern_allocation_name_allocate(name, 16);
		}
	}

	return mapper;
}

__BEGIN_DECLS

// These are C accessors to the system mapper for non-IOKit clients
ppnum_t
IOMapperIOVMAlloc(unsigned pages)
{
	IOReturn ret;
	uint64_t dmaAddress, dmaLength;

	IOMapper::checkForSystemMapper();

	ret = kIOReturnUnsupported;
	if (IOMapper::gSystem) {
		ret = IOMapper::gSystem->iovmMapMemory(
			NULL, 0, ptoa_64(pages),
			(kIODMAMapReadAccess | kIODMAMapWriteAccess),
			NULL, NULL, NULL,
			&dmaAddress, &dmaLength);
	}

	if (kIOReturnSuccess == ret) {
		return atop_64(dmaAddress);
	}
	return 0;
}

void
IOMapperIOVMFree(ppnum_t addr, unsigned pages)
{
	if (IOMapper::gSystem) {
		IOMapper::gSystem->iovmUnmapMemory(NULL, NULL, ptoa_64(addr), ptoa_64(pages));
	}
}

ppnum_t
IOMapperInsertPage(ppnum_t addr, unsigned offset, ppnum_t page)
{
	if (!IOMapper::gSystem) {
		return page;
	}
	if (!addr) {
		panic("!addr");
	}
	IOMapper::gSystem->iovmInsert((kIODMAMapReadAccess | kIODMAMapWriteAccess),
	    ptoa_64(addr), ptoa_64(offset), ptoa_64(page), ptoa_64(1));
	return addr + offset;
}

/////////////////////////////////////////////////////////////////////////////
//
//
//	IOLib.h APIs
//
//
/////////////////////////////////////////////////////////////////////////////

#include <machine/machine_routines.h>

UInt8
IOMappedRead8(IOPhysicalAddress address)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		return (UInt8) ml_phys_read_byte_64(addr);
	} else {
		return (UInt8) ml_phys_read_byte((vm_offset_t) address);
	}
}

UInt16
IOMappedRead16(IOPhysicalAddress address)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		return (UInt16) ml_phys_read_half_64(addr);
	} else {
		return (UInt16) ml_phys_read_half((vm_offset_t) address);
	}
}

UInt32
IOMappedRead32(IOPhysicalAddress address)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		return (UInt32) ml_phys_read_word_64(addr);
	} else {
		return (UInt32) ml_phys_read_word((vm_offset_t) address);
	}
}

UInt64
IOMappedRead64(IOPhysicalAddress address)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		return (UInt64) ml_phys_read_double_64(addr);
	} else {
		return (UInt64) ml_phys_read_double((vm_offset_t) address);
	}
}

void
IOMappedWrite8(IOPhysicalAddress address, UInt8 value)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		ml_phys_write_byte_64(addr, value);
	} else {
		ml_phys_write_byte((vm_offset_t) address, value);
	}
}

void
IOMappedWrite16(IOPhysicalAddress address, UInt16 value)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		ml_phys_write_half_64(addr, value);
	} else {
		ml_phys_write_half((vm_offset_t) address, value);
	}
}

void
IOMappedWrite32(IOPhysicalAddress address, UInt32 value)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		ml_phys_write_word_64(addr, value);
	} else {
		ml_phys_write_word((vm_offset_t) address, value);
	}
}

void
IOMappedWrite64(IOPhysicalAddress address, UInt64 value)
{
	IOMapper::checkForSystemMapper();

	if (IOMapper::gSystem) {
		addr64_t addr = IOMapper::gSystem->mapToPhysicalAddress(address);
		ml_phys_write_double_64(addr, value);
	} else {
		ml_phys_write_double((vm_offset_t) address, value);
	}
}

__END_DECLS
