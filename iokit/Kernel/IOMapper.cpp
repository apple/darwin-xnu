/*
 * Copyright (c) 1998-2004 Apple Computer, Inc. All rights reserved.
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
#include <libkern/c++/OSData.h>

#include "IOCopyMapper.h"

__BEGIN_DECLS
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
__END_DECLS

#define super IOService
OSDefineMetaClassAndAbstractStructors(IOMapper, IOService);

OSMetaClassDefineReservedUsed(IOMapper, 0);
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
    IOMapperLock() { fWaitLock = IOLockAlloc(); };
    ~IOMapperLock() { IOLockFree(fWaitLock); };

    void lock()   { IOLockLock(fWaitLock); };
    void unlock() { IOLockUnlock(fWaitLock); };
    void sleep(void *event)  { IOLockSleep(fWaitLock, event, THREAD_UNINT); };
    void wakeup(void *event) { IOLockWakeup(fWaitLock, event, false); };
};

static IOMapperLock sMapperLock;

bool IOMapper::start(IOService *provider)
{
    if (!super::start(provider))
        return false;

    if (!initHardware(provider))
        return false;

    if (fIsSystem) { 
        sMapperLock.lock();
        IOMapper::gSystem = this;
        sMapperLock.wakeup(&IOMapper::gSystem);
        sMapperLock.unlock();
    }

    return true;
}

bool IOMapper::allocTable(IOByteCount size)
{
    assert(!fTable);

    fTableSize = size;
    fTableHandle = NewARTTable(size, &fTable, &fTablePhys);
    return fTableHandle != 0;
}

void IOMapper::free()
{
    if (fTableHandle) {
        FreeARTTable(fTableHandle, fTableSize);
        fTableHandle = 0;
    }

    super::free();
}

void IOMapper::setMapperRequired(bool hasMapper)
{
    if (hasMapper)
        IOMapper::gSystem = (IOMapper *) kHasMapper;
    else {
        sMapperLock.lock();
        IOMapper::gSystem = (IOMapper *) kNoMapper;
        sMapperLock.unlock();
        sMapperLock.wakeup(&IOMapper::gSystem);
    }
}

void IOMapper::waitForSystemMapper()
{
    sMapperLock.lock();
    while ((vm_address_t) IOMapper::gSystem & kWaitMask)
        sMapperLock.sleep(&IOMapper::gSystem);
    sMapperLock.unlock();
}

void IOMapper::iovmInsert(ppnum_t addr, IOItemCount offset,
                            ppnum_t *pageList, IOItemCount pageCount)
{
    while (pageCount--)
        iovmInsert(addr, offset++, *pageList++);
}

void IOMapper::iovmInsert(ppnum_t addr, IOItemCount offset,
                            upl_page_info_t *pageList, IOItemCount pageCount)
{
    for (IOItemCount i = 0; i < pageCount; i++)
        iovmInsert(addr, offset + i, pageList[i].phys_addr);
}

OSData * IOMapper::
NewARTTable(IOByteCount size, void ** virtAddrP, ppnum_t *physAddrP)
{
    if (!virtAddrP || !physAddrP)
	return 0;

    kern_return_t kr;
    vm_address_t address;

    size = round_page_32(size);
    kr = kmem_alloc_contig(kernel_map, &address, size, PAGE_MASK, 0, 0);
    if (kr)
        return 0;

    ppnum_t pagenum = pmap_find_phys(kernel_pmap, (addr64_t) address);
    if (pagenum)
	*physAddrP = pagenum;
    else {
	FreeARTTable((OSData *) address, size);
	address = 0;
    }

    *virtAddrP = (void *) address;

    return (OSData *) address;
}

void IOMapper::FreeARTTable(OSData *artHandle, IOByteCount size)
{
    vm_address_t address = (vm_address_t) artHandle;

    size = round_page_32(size);
    kmem_free(kernel_map, address, size);	// Just panic if address is 0
}

bool IOMapper::getBypassMask(addr64_t *maskP) const
{
    return false;
}

__BEGIN_DECLS

// These are C accessors to the system mapper for non-IOKit clients
ppnum_t IOMapperIOVMAlloc(unsigned pages)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem)
        return IOMapper::gSystem->iovmAlloc((IOItemCount) pages);
    else
        return 0;
}

void IOMapperIOVMFree(ppnum_t addr, unsigned pages)
{
    if (IOMapper::gSystem)
        IOMapper::gSystem->iovmFree(addr, (IOItemCount) pages);
}

ppnum_t IOMapperInsertPage(ppnum_t addr, unsigned offset, ppnum_t page)
{
    if (IOMapper::gSystem) {
        IOMapper::gSystem->iovmInsert(addr, (IOItemCount) offset, page);
        return addr + offset;
    }
    else
        return page;
}

void IOMapperInsertPPNPages(ppnum_t addr, unsigned offset,
                            ppnum_t *pageList, unsigned pageCount)
{
    if (!IOMapper::gSystem)
        panic("IOMapperInsertPPNPages no system mapper");
    else
        assert(!((vm_address_t) IOMapper::gSystem & 3));

    IOMapper::gSystem->
        iovmInsert(addr, (IOItemCount) offset, pageList, pageCount);
}

void IOMapperInsertUPLPages(ppnum_t addr, unsigned offset,
                            upl_page_info_t *pageList, unsigned pageCount)
{
    if (!IOMapper::gSystem)
        panic("IOMapperInsertUPLPages no system mapper");
    else
        assert(!((vm_address_t) IOMapper::gSystem & 3));

    IOMapper::gSystem->iovmInsert(addr,
                                 (IOItemCount) offset,
                                  pageList,
                                  (IOItemCount) pageCount);
}

/////////////////////////////////////////////////////////////////////////////
//
//
//	IOLib.h APIs
//
//
/////////////////////////////////////////////////////////////////////////////

#include <machine/machine_routines.h>

UInt8 IOMappedRead8(IOPhysicalAddress address)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        return (UInt8) ml_phys_read_byte_64(addr);
    }
    else
        return (UInt8) ml_phys_read_byte((vm_offset_t) address);
}

UInt16 IOMappedRead16(IOPhysicalAddress address)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        return (UInt16) ml_phys_read_half_64(addr);
    }
    else
        return (UInt16) ml_phys_read_half((vm_offset_t) address);
}

UInt32 IOMappedRead32(IOPhysicalAddress address)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
	return (UInt32) ml_phys_read_word_64(addr);
    }
    else
        return (UInt32) ml_phys_read_word((vm_offset_t) address);
}

UInt64 IOMappedRead64(IOPhysicalAddress address)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        return (UInt64) ml_phys_read_double_64(addr);
    }
    else
        return (UInt64) ml_phys_read_double((vm_offset_t) address);
}

void IOMappedWrite8(IOPhysicalAddress address, UInt8 value)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        ml_phys_write_byte_64(addr, value);
    }
    else
        ml_phys_write_byte((vm_offset_t) address, value);
}

void IOMappedWrite16(IOPhysicalAddress address, UInt16 value)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        ml_phys_write_half_64(addr, value);
    }
    else
        ml_phys_write_half((vm_offset_t) address, value);
}

void IOMappedWrite32(IOPhysicalAddress address, UInt32 value)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        ml_phys_write_word_64(addr, value);
    }
    else
        ml_phys_write_word((vm_offset_t) address, value);
}

void IOMappedWrite64(IOPhysicalAddress address, UInt64 value)
{
    IOMapper::checkForSystemMapper();

    if (IOMapper::gSystem) {
        addr64_t addr = IOMapper::gSystem->mapAddr(address);
        ml_phys_write_double_64(addr, value);
    }
    else
        ml_phys_write_double((vm_offset_t) address, value);
}

mach_vm_address_t IOMallocPhysical(mach_vm_size_t size, mach_vm_address_t mask)
{
    mach_vm_address_t address = 0;
    if (gIOCopyMapper)
    {
	address = ptoa_64(gIOCopyMapper->iovmAlloc(atop_64(round_page(size))));
    }
    return (address);
}

void IOFreePhysical(mach_vm_address_t address, mach_vm_size_t size)
{
    if (gIOCopyMapper)
    {
	gIOCopyMapper->iovmFree(atop_64(address), atop_64(round_page(size)));
    }
}


__END_DECLS
