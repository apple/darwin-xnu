/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
// 45678901234567890123456789012345678901234567890123456789012345678901234567890

#include "IOCopyMapper.h"
#include <sys/sysctl.h>

#if 0
#define DEBG(fmt, args...)  	{ kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)  	{}
#endif

extern "C" {
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern void ml_get_bouncepool_info(
			       vm_offset_t *phys_addr,
			       vm_size_t   *size);
extern unsigned int vm_lopage_max_count;
extern unsigned int vm_himemory_mode;
}

#define super IOMapper

OSDefineMetaClassAndStructors(IOCopyMapper, IOMapper);

// Remember no value can be bigger than 31 bits as the sign bit indicates
// that this entry is valid to the hardware and that would be bad if it wasn't
typedef struct FreeDARTEntry {
#if __BIG_ENDIAN__
    unsigned int
    /* bool */	    fValid : 1,
    /* bool */	    fInUse : 1,	// Allocated but not inserted yet
    /* bool */		   : 5,	// Align size on nibble boundary for debugging
    /* uint */	    fSize  : 5,
    /* uint */	           : 2,
    /* uint */	    fNext  :18;	// offset of FreeDARTEntry's

#elif __LITTLE_ENDIAN__
    unsigned int
    /* uint */	    fNext  :18,	// offset of FreeDARTEntry's
    /* uint */	           : 2,
    /* uint */	    fSize  : 5,
    /* bool */		   : 5,	// Align size on nibble boundary for debugging
    /* bool */	    fInUse : 1,	// Allocated but not inserted yet
    /* bool */	    fValid : 1;
#endif
#if __BIG_ENDIAN__
    unsigned int
    /* uint */	           :14,
    /* uint */	    fPrev  :18;	// offset of FreeDARTEntry's

#elif __LITTLE_ENDIAN__
    unsigned int
    /* uint */	    fPrev  :18,	// offset of FreeDARTEntry's
    /* uint */	           :14;
#endif
} FreeDARTEntry;

typedef struct ActiveDARTEntry {
#if __BIG_ENDIAN__
    unsigned int
    /* bool */	    fValid : 1,	// Must be set to one if valid
    /* uint */	    fPPNum :31;	// ppnum_t page of translation
#define ACTIVEDARTENTRY(page)	{ true, page }

#elif __LITTLE_ENDIAN__
    unsigned int
    /* uint */	    fPPNum :31,	// ppnum_t page of translation
    /* bool */	    fValid : 1;	// Must be set to one if valid
#define ACTIVEDARTENTRY(page)	{ page, true }

#endif
};

#define kActivePerFree (sizeof(freeDART[0]) / sizeof(ActiveDARTEntry))

static SYSCTL_UINT(_kern, OID_AUTO, copyregionmax, 
				CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
				 NULL, 0, "");

static SYSCTL_UINT(_kern, OID_AUTO, lowpagemax, 
				CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
				&vm_lopage_max_count, 0, "");

static SYSCTL_UINT(_kern, OID_AUTO, himemorymode, 
				CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, 
				&vm_himemory_mode, 0, "");

bool IOCopyMapper::initHardware(IOService * provider)
{
    UInt32 dartSizePages = 0;

    vm_offset_t phys_addr;
    vm_size_t   size;
    ml_get_bouncepool_info(&phys_addr, &size);

    if (!size)
	return (false);

    fBufferPage = atop_32(phys_addr);
    dartSizePages = (atop_32(size) + kTransPerPage - 1) / kTransPerPage;

    fTableLock = IOLockAlloc();

    if (!fTableLock)
	return false;

    if (!allocTable(dartSizePages * kMapperPage))
	return false;

    UInt32 canMapPages = dartSizePages * kTransPerPage;
    fMapperRegionSize = canMapPages;
    for (fNumZones = 0; canMapPages; fNumZones++)
	canMapPages >>= 1;
    fNumZones -= 3; // correct for overshoot and minumum 16K pages allocation

    invalidateDART(0, fMapperRegionSize);

    breakUp(0, fNumZones, 0);
    ((FreeDARTEntry *) fTable)->fInUse = true;
    
    fMapperRegionUsed    = kMinZoneSize;
    fMapperRegionMaxUsed = fMapperRegionUsed;

    sysctl__kern_copyregionmax.oid_arg1 = &fMapperRegionMaxUsed;

    sysctl_register_oid(&sysctl__kern_copyregionmax);
    sysctl_register_oid(&sysctl__kern_lowpagemax);
    sysctl_register_oid(&sysctl__kern_himemorymode);

    fDummyPage = IOMallocAligned(0x1000, 0x1000);
    fDummyPageNumber =
	pmap_find_phys(kernel_pmap, (addr64_t) (uintptr_t) fDummyPage);

    return true;
}

void IOCopyMapper::free()
{
    if (fDummyPage) {
	IOFreeAligned(fDummyPage, 0x1000);
	fDummyPage = 0;
	fDummyPageNumber = 0;
    }

    if (fTableLock) {
	IOLockFree(fTableLock);
	fTableLock = 0;
    }

    super::free();
}

// Must be called while locked
void IOCopyMapper::breakUp(unsigned startIndex, unsigned endIndex, unsigned freeInd)
{
    unsigned int zoneSize;
    FreeDARTEntry *freeDART = (FreeDARTEntry *) fTable;

    do {
	// Need to break up bigger blocks of memory till we get one in our 
	// desired zone.
	endIndex--;
	zoneSize = (kMinZoneSize/2 << endIndex);
	ppnum_t tail = freeInd + zoneSize;

	DEBG("breakup z %d start %x tail %x\n", endIndex, freeInd, tail);

	// By definition free lists must be empty
	fFreeLists[endIndex] = tail;
	freeDART[tail].fSize = endIndex;
	freeDART[tail].fNext = freeDART[tail].fPrev = 0;
    } while (endIndex != startIndex);
    freeDART[freeInd].fSize = endIndex;
}

// Zero is never a valid page to return
ppnum_t IOCopyMapper::iovmAlloc(IOItemCount pages)
{
    unsigned int zone, zoneSize, z, cnt;
    ppnum_t next, ret = 0;
    FreeDARTEntry *freeDART = (FreeDARTEntry *) fTable;

    // Can't alloc anything of less than minumum
    if (pages < kMinZoneSize)
	pages = kMinZoneSize;

    // Can't alloc anything bigger than 1/2 table
    if (pages >= fMapperRegionSize/2)
    {
	panic("iovmAlloc 0x%x", pages);
	return 0;
    }

    // Find the appropriate zone for this allocation
    for (zone = 0, zoneSize = kMinZoneSize; pages > zoneSize; zone++)
	zoneSize <<= 1;

    {
	IOLockLock(fTableLock);

	for (;;) {
	    for (z = zone; z < fNumZones; z++) {
		if ( (ret = fFreeLists[z]) )
		    break;
	    }
	    if (ret)
		break;

	    fFreeSleepers++;
	    IOLockSleep(fTableLock, fFreeLists, THREAD_UNINT);
	    fFreeSleepers--;
	}

	// If we didn't find a entry in our size then break up the free block
	// that we did find.
	if (zone != z)
	{
	    DEBG("breakup %d, %d, 0x%x\n", zone, z, ret);
	    breakUp(zone, z, ret);
	}

	freeDART[ret].fInUse = true;	// Mark entry as In Use
	next = freeDART[ret].fNext;
	DEBG("va:  0x%x, %d, ret %x next %x\n", (ret * kActivePerFree) + fBufferPage, pages, ret, next);

	fFreeLists[z] = next;
	if (next)
	    freeDART[next].fPrev = 0;

	// ret is free list offset not page offset;
	ret *= kActivePerFree;

	ActiveDARTEntry pageEntry = ACTIVEDARTENTRY(fDummyPageNumber);
	for (cnt = 0; cnt < pages; cnt++) {
	    ActiveDARTEntry *activeDART = &fMappings[ret + cnt];
	    *activeDART = pageEntry;
	}

	fMapperRegionUsed += pages;
	if (fMapperRegionUsed > fMapperRegionMaxUsed)
	    fMapperRegionMaxUsed = fMapperRegionUsed;

	IOLockUnlock(fTableLock);
    }

    if (ret)
	ret += fBufferPage;

    return ret;
}


void IOCopyMapper::invalidateDART(ppnum_t pnum, IOItemCount size)
{
    bzero((void *) &fMappings[pnum], size * sizeof(fMappings[0]));
}

void IOCopyMapper::iovmFree(ppnum_t addr, IOItemCount pages)
{
    unsigned int zone, zoneSize, z;
    FreeDARTEntry *freeDART = (FreeDARTEntry *) fTable;

    if (addr < fBufferPage)
	IOPanic("addr < fBufferPage");
    addr -= fBufferPage;

    // Can't free anything of less than minumum
    if (pages < kMinZoneSize)
	pages = kMinZoneSize;

    // Can't free anything bigger than 1/2 table
    if (pages >= fMapperRegionSize/2)
	return;

    // Find the appropriate zone for this allocation
    for (zone = 0, zoneSize = kMinZoneSize; pages > zoneSize; zone++)
	zoneSize <<= 1;

    // Grab lock that protects the dart
    IOLockLock(fTableLock);

    invalidateDART(addr, pages);

    addr /= kActivePerFree;

    // We are freeing a block, check to see if pairs are available for 
    // coalescing.  We will walk up the entire chain if we can.
    for (z = zone; z < fNumZones; z++) {
	ppnum_t pair = addr ^ (kMinZoneSize/2 << z);	// Find pair address
	if (freeDART[pair].fValid || freeDART[pair].fInUse || (freeDART[pair].fSize != z))
	    break;

	// The paired alloc entry is free if we are here
	ppnum_t next = freeDART[pair].fNext;
	ppnum_t prev = freeDART[pair].fPrev;

	// Remove the pair from its freeList
	if (prev)
	    freeDART[prev].fNext = next;
	else
	    fFreeLists[z] = next;

	if (next)
	    freeDART[next].fPrev = prev;

	// Sort the addr and the pair
	if (addr > pair)
	    addr = pair;
    }

    DEBG("vf:  0x%x, %d, z %d, head %x, new %x\n", addr * kActivePerFree + fBufferPage, pages, z, fFreeLists[z], addr);

    // Add the allocation entry into it's free list and re-init it
    freeDART[addr].fSize = z;
    freeDART[addr].fNext = fFreeLists[z];
    if (fFreeLists[z])
	freeDART[fFreeLists[z]].fPrev = addr;
    freeDART[addr].fPrev = 0;
    fFreeLists[z] = addr;

    fMapperRegionUsed -= pages;

    if (fFreeSleepers)
	IOLockWakeup(fTableLock, fFreeLists, /* oneThread */ false);

    IOLockUnlock(fTableLock);
}

addr64_t IOCopyMapper::mapAddr(IOPhysicalAddress addr)
{
    if (addr < ptoa_32(fBufferPage))
    {
	return (addr64_t) addr;	// Not mapped by us anyway
    }

    addr -= ptoa_32(fBufferPage);
    if (addr >= ptoa_32(fMapperRegionSize))
    {
	return (addr64_t) addr;	// Not mapped by us anyway
    }
    else
    {
	ActiveDARTEntry *activeDART = (ActiveDARTEntry *) fTable;
	UInt offset = addr & PAGE_MASK;

	ActiveDARTEntry mappedPage = activeDART[atop_32(addr)];
	if (mappedPage.fValid)
    {
	    return (ptoa_64(mappedPage.fPPNum) | offset);
	}

	panic("%s::mapAddr(0x%08lx) not mapped for I/O\n", getName(), addr);
	return 0;
    }
}

void IOCopyMapper::iovmInsert(ppnum_t addr, IOItemCount offset, ppnum_t page)
{
    addr -= fBufferPage;
    addr += offset;	// Add the offset page to the base address

    ActiveDARTEntry *activeDART = &fMappings[addr];
    ActiveDARTEntry entry = ACTIVEDARTENTRY(page);
    *activeDART = entry;
}

void IOCopyMapper::iovmInsert(ppnum_t addr, IOItemCount offset,
	ppnum_t *pageList, IOItemCount pageCount)
{
    addr -= fBufferPage;
    addr += offset;	// Add the offset page to the base address

    IOItemCount i;
    ActiveDARTEntry *activeDART = &fMappings[addr];

    for (i = 0; i < pageCount; i++)
    {
	ActiveDARTEntry entry = ACTIVEDARTENTRY(pageList[i]);
	activeDART[i] = entry;
    }
}

void IOCopyMapper::iovmInsert(ppnum_t addr, IOItemCount offset,
	upl_page_info_t *pageList, IOItemCount pageCount)
{
    addr -= fBufferPage;
    addr += offset;	// Add the offset page to the base address

    IOItemCount i;
    ActiveDARTEntry *activeDART = &fMappings[addr];

    for (i = 0; i < pageCount; i++)
    {
	ActiveDARTEntry entry = ACTIVEDARTENTRY(pageList[i].phys_addr);
	activeDART[i] = entry;
    }
}


