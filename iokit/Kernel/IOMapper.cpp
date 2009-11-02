/*
 * Copyright (c) 1998-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <libkern/c++/OSData.h>

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

struct ARTTableData {
    void *v;
    upl_t u[0];
};
#define getARTDataP(data) ((ARTTableData *) (data)->getBytesNoCopy())

OSData *
IOMapper::NewARTTable(IOByteCount size,
                      void ** virtAddrP, ppnum_t *physAddrP)
{
    OSData *ret;
    kern_return_t kr;
    vm_address_t startUpl;
    ARTTableData *dataP;
    unsigned int dataSize;
    upl_page_info_t *pl = 0;

    // Each UPL can deal with about one meg at the moment
    size = round_page_32(size);
    dataSize = sizeof(ARTTableData) + sizeof(upl_t) * size / (1024 * 1024);
    ret = OSData::withCapacity(dataSize);
    if (!ret)
        return 0;

    // Append 0's to the buffer, in-other-words reset to nulls.
    ret->appendBytes(NULL, sizeof(ARTTableData));
    dataP = getARTDataP(ret);

    kr = kmem_alloc_contig(kernel_map, &startUpl, size, PAGE_MASK, 0);
    if (kr)
        return 0;

    dataP->v = (void *) startUpl;

    do {
        upl_t iopl;
        int upl_flags = UPL_SET_INTERNAL | UPL_SET_LITE
                      | UPL_SET_IO_WIRE | UPL_COPYOUT_FROM;
        vm_size_t iopl_size = size;

        kr = vm_map_get_upl(kernel_map,
                            (vm_map_offset_t)startUpl,
                            &iopl_size,
                            &iopl,
                            0,
                            0,
                            &upl_flags,
                            0);
        if (kr) {
            panic("IOMapper:vm_map_get_upl returned 0x%x\n");
            goto bail;
        }

        if (!ret->appendBytes(&iopl, sizeof(upl_t)))
            goto bail;
            
        startUpl += iopl_size;
        size -= iopl_size;
    } while(size);

    // Need to re-establish the dataP as the OSData may have grown.
    dataP = getARTDataP(ret);

    // Now grab the page entry of the first page and get its phys addr
    pl = UPL_GET_INTERNAL_PAGE_LIST(dataP->u[0]);
    *physAddrP = pl->phys_addr;
    *virtAddrP = dataP->v;

    return ret;

bail:
    FreeARTTable(ret, size);
    return 0;
}

void IOMapper::FreeARTTable(OSData *artHandle, IOByteCount size)
{
    assert(artHandle);

    ARTTableData *dataP = getARTDataP(artHandle);

    int numupls = ((artHandle->getLength() - sizeof(*dataP)) / sizeof(upl_t));
    for (int i = 0; i < numupls; i++) {
        upl_abort(dataP->u[i], 0);
        upl_deallocate(dataP->u[i]);
    }

    if (dataP->v) {
        size = round_page_32(size);
        kmem_free(kernel_map, (vm_address_t) dataP->v, size);
    }
    artHandle->release();
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

__END_DECLS
