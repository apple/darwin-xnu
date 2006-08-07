/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
// 45678901234567890123456789012345678901234567890123456789012345678901234567890

#include <libkern/OSAtomic.h>

#include <IOKit/IOLocks.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMapper.h>

// General constants about all VART/DART style Address Re-Mapping Tables
#define kMapperPage	    (4 * 1024)
#define kTransPerPage	    (kMapperPage / sizeof(ppnum_t))

#define kMinZoneSize	    4		// Minimum Zone size in pages
#define kMaxNumZones	    (31 - 14)	// 31 bit mapped in 16K super pages

class IOCopyMapper : public IOMapper
{
    OSDeclareDefaultStructors(IOCopyMapper);

// alias the fTable variable into our mappings table
#define fMappings	((ActiveDARTEntry *) super::fTable)

private:

    UInt32		fFreeLists[kMaxNumZones];

    IOLock		*fTableLock;

    void		*fDummyPage;

    UInt32		 fNumZones;
    UInt32		 fMapperRegionSize;
    UInt32		 fMapperRegionUsed;
    UInt32		 fMapperRegionMaxUsed;
    UInt32		 fFreeSleepers;
    ppnum_t		 fDummyPageNumber;
    ppnum_t		 fBufferPage;

    // Internal functions

    void breakUp(unsigned start, unsigned end, unsigned freeInd);
    void invalidateDART(ppnum_t pnum, IOItemCount size);
    void tlbInvalidate(ppnum_t pnum, IOItemCount size);

    virtual void free();

    virtual bool initHardware(IOService * provider);
public:
    virtual ppnum_t iovmAlloc(IOItemCount pages);
    virtual void iovmFree(ppnum_t addr, IOItemCount pages);

    virtual void iovmInsert(ppnum_t addr, IOItemCount offset, ppnum_t page);
    virtual void iovmInsert(ppnum_t addr, IOItemCount offset,
                            ppnum_t *pageList, IOItemCount pageCount);
    virtual void iovmInsert(ppnum_t addr, IOItemCount offset,
                            upl_page_info_t *pageList, IOItemCount pageCount);

    virtual addr64_t mapAddr(IOPhysicalAddress addr);
};

extern IOCopyMapper * gIOCopyMapper;
