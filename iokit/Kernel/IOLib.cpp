/* 
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * HISTORY
 *
 * 17-Apr-91   Portions from libIO.m, Doug Mitchell at NeXT.
 * 17-Nov-98   cpp
 *
 */

#include <IOKit/system.h>
#include <mach/sync_policy.h>
#include <machine/machine_routines.h>
#include <vm/vm_kern.h>
#include <libkern/c++/OSCPPDebug.h>

#include <IOKit/assert.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOLib.h> 
#include <IOKit/IOLocks.h> 
#include <IOKit/IOMapper.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOKitDebug.h> 

#include "IOKitKernelInternal.h"

#ifdef IOALLOCDEBUG
#include <libkern/OSDebug.h>
#include <sys/sysctl.h>
#endif

#include "libkern/OSAtomic.h"
#include <libkern/c++/OSKext.h>
#include <IOKit/IOStatisticsPrivate.h>
#include <os/log_private.h>
#include <sys/msgbuf.h>
#include <console/serial_protos.h>

#if IOKITSTATS

#define IOStatisticsAlloc(type, size) \
do { \
	IOStatistics::countAlloc(type, size); \
} while (0)

#else

#define IOStatisticsAlloc(type, size)

#endif /* IOKITSTATS */


#define TRACK_ALLOC	(IOTRACKING && (kIOTracking & gIOKitDebug))


extern "C"
{


mach_timespec_t IOZeroTvalspec = { 0, 0 };

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);

extern int
__doprnt(
	const char		*fmt,
	va_list			argp,
	void			(*putc)(int, void *),
	void                    *arg,
	int			radix,
	int			is_log);

extern void cons_putc_locked(char);
extern void bsd_log_lock(void);
extern void bsd_log_unlock(void);


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

lck_grp_t	*IOLockGroup;

/*
 * Global variables for use by iLogger
 * These symbols are for use only by Apple diagnostic code.
 * Binary compatibility is not guaranteed for kexts that reference these symbols.
 */

void *_giDebugLogInternal	= NULL;
void *_giDebugLogDataInternal	= NULL;
void *_giDebugReserved1		= NULL;
void *_giDebugReserved2		= NULL;

iopa_t gIOBMDPageAllocator;

/*
 * Static variables for this module.
 */

static queue_head_t gIOMallocContiguousEntries;
static lck_mtx_t *  gIOMallocContiguousEntriesLock;

#if __x86_64__
enum { kIOMaxPageableMaps    = 8 };
enum { kIOPageableMapSize    = 512 * 1024 * 1024 };
enum { kIOPageableMaxMapSize = 512 * 1024 * 1024 };
#else
enum { kIOMaxPageableMaps    = 16 };
enum { kIOPageableMapSize    = 96 * 1024 * 1024 };
enum { kIOPageableMaxMapSize = 96 * 1024 * 1024 };
#endif

typedef struct {
    vm_map_t		map;
    vm_offset_t	address;
    vm_offset_t	end;
} IOMapData;

static struct {
    UInt32	count;
    UInt32	hint;
    IOMapData	maps[ kIOMaxPageableMaps ];
    lck_mtx_t *	lock;
} gIOKitPageableSpace;

static iopa_t gIOPageablePageAllocator;

uint32_t  gIOPageAllocChunkBytes;

#if IOTRACKING
IOTrackingQueue * gIOMallocTracking;
IOTrackingQueue * gIOWireTracking;
IOTrackingQueue * gIOMapTracking;
#endif /* IOTRACKING */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOLibInit(void)
{
    kern_return_t ret;

    static bool libInitialized;

    if(libInitialized)
        return;	

    IOLockGroup = lck_grp_alloc_init("IOKit", LCK_GRP_ATTR_NULL);

#if IOTRACKING
    IOTrackingInit();
    gIOMallocTracking = IOTrackingQueueAlloc(kIOMallocTrackingName, 0, 0, 0,
						 kIOTrackingQueueTypeAlloc,
						 37);
    gIOWireTracking   = IOTrackingQueueAlloc(kIOWireTrackingName,   0, 0, page_size, 0, 0);

    size_t mapCaptureSize = (kIOTracking & gIOKitDebug) ? page_size : (1024*1024);
    gIOMapTracking    = IOTrackingQueueAlloc(kIOMapTrackingName,    0, 0, mapCaptureSize,
						 kIOTrackingQueueTypeDefaultOn
						 | kIOTrackingQueueTypeMap
						 | kIOTrackingQueueTypeUser,
					     0);
#endif

    gIOKitPageableSpace.maps[0].address = 0;
    ret = kmem_suballoc(kernel_map,
                    &gIOKitPageableSpace.maps[0].address,
                    kIOPageableMapSize,
                    TRUE,
                    VM_FLAGS_ANYWHERE,
		    VM_MAP_KERNEL_FLAGS_NONE,
		    VM_KERN_MEMORY_IOKIT,
                    &gIOKitPageableSpace.maps[0].map);
    if (ret != KERN_SUCCESS)
        panic("failed to allocate iokit pageable map\n");

    gIOKitPageableSpace.lock 		= lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
    gIOKitPageableSpace.maps[0].end	= gIOKitPageableSpace.maps[0].address + kIOPageableMapSize;
    gIOKitPageableSpace.hint		= 0;
    gIOKitPageableSpace.count		= 1;

    gIOMallocContiguousEntriesLock 	= lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
    queue_init( &gIOMallocContiguousEntries );

    gIOPageAllocChunkBytes = PAGE_SIZE/64;
    assert(sizeof(iopa_page_t) <= gIOPageAllocChunkBytes);
    iopa_init(&gIOBMDPageAllocator);
    iopa_init(&gIOPageablePageAllocator);


    libInitialized = true;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static uint32_t 
log2up(uint32_t size)
{
    if (size <= 1) size = 0;
    else size = 32 - __builtin_clz(size - 1);
    return (size);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOThread IOCreateThread(IOThreadFunc fcn, void *arg)
{
	kern_return_t	result;
	thread_t		thread;

	result = kernel_thread_start((thread_continue_t)fcn, arg, &thread);
	if (result != KERN_SUCCESS)
		return (NULL);

	thread_deallocate(thread);

	return (thread);
}


void IOExitThread(void)
{
    (void) thread_terminate(current_thread());
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if IOTRACKING
struct IOLibMallocHeader
{
    IOTrackingAddress tracking;
};
#endif

#if IOTRACKING
#define sizeofIOLibMallocHeader	(sizeof(IOLibMallocHeader) - (TRACK_ALLOC ? 0 : sizeof(IOTrackingAddress)))
#else
#define sizeofIOLibMallocHeader	(0)
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void * IOMalloc(vm_size_t size)
{
    void * address;
    vm_size_t allocSize;

    allocSize = size + sizeofIOLibMallocHeader;
#if IOTRACKING
    if (sizeofIOLibMallocHeader && (allocSize <= size)) return (NULL);	// overflow
#endif
    address = kalloc_tag_bt(allocSize, VM_KERN_MEMORY_IOKIT);

    if ( address ) {
#if IOTRACKING
	if (TRACK_ALLOC) {
	    IOLibMallocHeader * hdr;
	    hdr = (typeof(hdr)) address;
	    bzero(&hdr->tracking, sizeof(hdr->tracking));
	    hdr->tracking.address = ~(((uintptr_t) address) + sizeofIOLibMallocHeader);
	    hdr->tracking.size    = size;
	    IOTrackingAdd(gIOMallocTracking, &hdr->tracking.tracking, size, true, VM_KERN_MEMORY_NONE);
	}
#endif
	address = (typeof(address)) (((uintptr_t) address) + sizeofIOLibMallocHeader);

#if IOALLOCDEBUG
    OSAddAtomic(size, &debug_iomalloc_size);
#endif
	IOStatisticsAlloc(kIOStatisticsMalloc, size);
    }

    return address;
}

void IOFree(void * inAddress, vm_size_t size)
{
    void * address;

    if ((address = inAddress))
    {
	address = (typeof(address)) (((uintptr_t) address) - sizeofIOLibMallocHeader);
	
#if IOTRACKING
	if (TRACK_ALLOC)
	{
	    IOLibMallocHeader * hdr;
	    struct ptr_reference{ void * ptr; };
	    volatile struct ptr_reference ptr;

            // we're about to block in IOTrackingRemove(), make sure the original pointer
            // exists in memory or a register for leak scanning to find
            ptr.ptr = inAddress;

	    hdr = (typeof(hdr)) address;
            if (size != hdr->tracking.size)
	    {
		OSReportWithBacktrace("bad IOFree size 0x%lx should be 0x%lx", size, hdr->tracking.size);
		size = hdr->tracking.size;
	    }
	    IOTrackingRemove(gIOMallocTracking, &hdr->tracking.tracking, size);
            ptr.ptr = NULL;
	}
#endif

	kfree(address, size + sizeofIOLibMallocHeader);
#if IOALLOCDEBUG
    OSAddAtomic(-size, &debug_iomalloc_size);
#endif
	IOStatisticsAlloc(kIOStatisticsFree, size);
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

vm_tag_t 
IOMemoryTag(vm_map_t map)
{
    vm_tag_t tag;

    if (!vm_kernel_map_is_kernel(map)) return (VM_MEMORY_IOKIT);

    tag = vm_tag_bt();
    if (tag == VM_KERN_MEMORY_NONE) tag = VM_KERN_MEMORY_IOKIT;

    return (tag);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOLibPageMallocHeader
{
    mach_vm_size_t    allocationSize;
    mach_vm_address_t allocationAddress;
#if IOTRACKING
    IOTrackingAddress tracking;
#endif
};

#if IOTRACKING
#define sizeofIOLibPageMallocHeader	(sizeof(IOLibPageMallocHeader) - (TRACK_ALLOC ? 0 : sizeof(IOTrackingAddress)))
#else
#define sizeofIOLibPageMallocHeader	(sizeof(IOLibPageMallocHeader))
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void * IOMallocAligned(vm_size_t size, vm_size_t alignment)
{
    kern_return_t	    kr;
    vm_offset_t		    address;
    vm_offset_t		    allocationAddress;
    vm_size_t		    adjustedSize;
    uintptr_t		    alignMask;
    IOLibPageMallocHeader * hdr;

    if (size == 0)
        return 0;

    alignment = (1UL << log2up(alignment));
    alignMask = alignment - 1;
    adjustedSize = size + sizeofIOLibPageMallocHeader;

    if (size > adjustedSize) {
	    address = 0;    /* overflow detected */
    }
    else if (adjustedSize >= page_size) {

        kr = kernel_memory_allocate(kernel_map, &address,
					size, alignMask, 0, IOMemoryTag(kernel_map));
	if (KERN_SUCCESS != kr)	address = 0;
#if IOTRACKING
	else if (TRACK_ALLOC) IOTrackingAlloc(gIOMallocTracking, address, size);
#endif

    } else {

	adjustedSize += alignMask;

	if (adjustedSize >= page_size) {

	    kr = kernel_memory_allocate(kernel_map, &allocationAddress,
					    adjustedSize, 0, 0, IOMemoryTag(kernel_map));
	    if (KERN_SUCCESS != kr) allocationAddress = 0;

	} else
	    allocationAddress = (vm_address_t) kalloc_tag_bt(adjustedSize, VM_KERN_MEMORY_IOKIT);

        if (allocationAddress) {
            address = (allocationAddress + alignMask + sizeofIOLibPageMallocHeader)
                    & (~alignMask);

	    hdr = (typeof(hdr))(address - sizeofIOLibPageMallocHeader);
	    hdr->allocationSize    = adjustedSize;
	    hdr->allocationAddress = allocationAddress;
#if IOTRACKING
	    if (TRACK_ALLOC) {
	        bzero(&hdr->tracking, sizeof(hdr->tracking));
	        hdr->tracking.address = ~address;
	        hdr->tracking.size = size;
	        IOTrackingAdd(gIOMallocTracking, &hdr->tracking.tracking, size, true, VM_KERN_MEMORY_NONE);
	    }
#endif
	} else
	    address = 0;
    }

    assert(0 == (address & alignMask));

    if( address) {
#if IOALLOCDEBUG
		OSAddAtomic(size, &debug_iomalloc_size);
#endif
    	IOStatisticsAlloc(kIOStatisticsMallocAligned, size);
	}

    return (void *) address;
}

void IOFreeAligned(void * address, vm_size_t size)
{
    vm_address_t	    allocationAddress;
    vm_size_t	            adjustedSize;
    IOLibPageMallocHeader * hdr;

    if( !address)
	return;

    assert(size);

    adjustedSize = size + sizeofIOLibPageMallocHeader;
    if (adjustedSize >= page_size) {
#if IOTRACKING
	if (TRACK_ALLOC) IOTrackingFree(gIOMallocTracking, (uintptr_t) address, size);
#endif
        kmem_free( kernel_map, (vm_offset_t) address, size);

    } else {
        hdr = (typeof(hdr)) (((uintptr_t)address) - sizeofIOLibPageMallocHeader);
      	adjustedSize = hdr->allocationSize;
        allocationAddress = hdr->allocationAddress;

#if IOTRACKING
	if (TRACK_ALLOC)
	{
            if (size != hdr->tracking.size)
	    {
		OSReportWithBacktrace("bad IOFreeAligned size 0x%lx should be 0x%lx", size, hdr->tracking.size);
		size = hdr->tracking.size;
	    }
	    IOTrackingRemove(gIOMallocTracking, &hdr->tracking.tracking, size);
	}
#endif
	if (adjustedSize >= page_size) {
	    kmem_free( kernel_map, allocationAddress, adjustedSize);
	} else {
	    kfree((void *)allocationAddress, adjustedSize);
	}
    }

#if IOALLOCDEBUG
    OSAddAtomic(-size, &debug_iomalloc_size);
#endif

    IOStatisticsAlloc(kIOStatisticsFreeAligned, size);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOKernelFreePhysical(mach_vm_address_t address, mach_vm_size_t size)
{
    mach_vm_address_t       allocationAddress;
    mach_vm_size_t          adjustedSize;
    IOLibPageMallocHeader * hdr;

    if (!address)
	return;

    assert(size);

    adjustedSize = (2 * size) + sizeofIOLibPageMallocHeader;
    if (adjustedSize >= page_size) {
#if IOTRACKING
	if (TRACK_ALLOC) IOTrackingFree(gIOMallocTracking, address, size);
#endif
	kmem_free( kernel_map, (vm_offset_t) address, size);

    } else {

        hdr = (typeof(hdr)) (((uintptr_t)address) - sizeofIOLibPageMallocHeader);
      	adjustedSize = hdr->allocationSize;
        allocationAddress = hdr->allocationAddress;
#if IOTRACKING
	if (TRACK_ALLOC) IOTrackingRemove(gIOMallocTracking, &hdr->tracking.tracking, size);
#endif
	kfree((void *)allocationAddress, adjustedSize);
    }

    IOStatisticsAlloc(kIOStatisticsFreeContiguous, size);
#if IOALLOCDEBUG
    OSAddAtomic(-size, &debug_iomalloc_size);
#endif
}

#if __arm__ || __arm64__
extern unsigned long gPhysBase, gPhysSize;
#endif

mach_vm_address_t
IOKernelAllocateWithPhysicalRestrict(mach_vm_size_t size, mach_vm_address_t maxPhys, 
			                mach_vm_size_t alignment, bool contiguous)
{
    kern_return_t	    kr;
    mach_vm_address_t	    address;
    mach_vm_address_t	    allocationAddress;
    mach_vm_size_t	    adjustedSize;
    mach_vm_address_t	    alignMask;
    IOLibPageMallocHeader * hdr;

    if (size == 0)
	return (0);
    if (alignment == 0) 
        alignment = 1;

    alignMask = alignment - 1;
    adjustedSize = (2 * size) + sizeofIOLibPageMallocHeader;
    if (adjustedSize < size) return (0);

    contiguous = (contiguous && (adjustedSize > page_size))
                   || (alignment > page_size);

    if (contiguous || maxPhys)
    {
        int options = 0;
	vm_offset_t virt;

	adjustedSize = size;
        contiguous = (contiguous && (adjustedSize > page_size))
                           || (alignment > page_size);

	if (!contiguous)
	{
#if __arm__ || __arm64__
	    if (maxPhys >= (mach_vm_address_t)(gPhysBase + gPhysSize))
	    {
	    	maxPhys = 0;
	    }
	    else
#endif
	    if (maxPhys <= 0xFFFFFFFF)
	    {
		maxPhys = 0;
		options |= KMA_LOMEM;
	    }
	    else if (gIOLastPage && (atop_64(maxPhys) > gIOLastPage))
	    {
		maxPhys = 0;
	    }
	}
	if (contiguous || maxPhys)
	{
	    kr = kmem_alloc_contig(kernel_map, &virt, size,
				   alignMask, atop(maxPhys), atop(alignMask), 0, IOMemoryTag(kernel_map));
	}
	else
	{
	    kr = kernel_memory_allocate(kernel_map, &virt,
					size, alignMask, options, IOMemoryTag(kernel_map));
	}
	if (KERN_SUCCESS == kr)
	{
	    address = virt;
#if IOTRACKING
	    if (TRACK_ALLOC) IOTrackingAlloc(gIOMallocTracking, address, size);
#endif
	}
	else
	    address = 0;
    }
    else
    {
	adjustedSize += alignMask;
        if (adjustedSize < size) return (0);
        allocationAddress = (mach_vm_address_t) kalloc_tag_bt(adjustedSize, VM_KERN_MEMORY_IOKIT);

        if (allocationAddress) {


            address = (allocationAddress + alignMask + sizeofIOLibPageMallocHeader)
                    & (~alignMask);

            if (atop_32(address) != atop_32(address + size - 1))
                address = round_page(address);

	    hdr = (typeof(hdr))(address - sizeofIOLibPageMallocHeader);
	    hdr->allocationSize    = adjustedSize;
	    hdr->allocationAddress = allocationAddress;
#if IOTRACKING
	    if (TRACK_ALLOC) {
	        bzero(&hdr->tracking, sizeof(hdr->tracking));
	        hdr->tracking.address = ~address;
	        hdr->tracking.size    = size;
	        IOTrackingAdd(gIOMallocTracking, &hdr->tracking.tracking, size, true, VM_KERN_MEMORY_NONE);
	    }
#endif
	} else
	    address = 0;
    }

    if (address) {
    IOStatisticsAlloc(kIOStatisticsMallocContiguous, size);
#if IOALLOCDEBUG
    OSAddAtomic(size, &debug_iomalloc_size);
#endif
    }

    return (address);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct _IOMallocContiguousEntry
{
    mach_vm_address_t	       virtualAddr;
    IOBufferMemoryDescriptor * md;
    queue_chain_t	       link;
};
typedef struct _IOMallocContiguousEntry _IOMallocContiguousEntry;

void * IOMallocContiguous(vm_size_t size, vm_size_t alignment,
			   IOPhysicalAddress * physicalAddress)
{
    mach_vm_address_t	address = 0;

    if (size == 0)
	return 0;
    if (alignment == 0) 
	alignment = 1;

    /* Do we want a physical address? */
    if (!physicalAddress)
    {
	address = IOKernelAllocateWithPhysicalRestrict(size, 0 /*maxPhys*/, alignment, true);
    }
    else do
    {
	IOBufferMemoryDescriptor * bmd;
	mach_vm_address_t          physicalMask;
	vm_offset_t		   alignMask;

	alignMask = alignment - 1;
	physicalMask = (0xFFFFFFFF ^ alignMask);

	bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
		kernel_task, kIOMemoryPhysicallyContiguous, size, physicalMask);
	if (!bmd)
	    break;
	
	_IOMallocContiguousEntry *
	entry = IONew(_IOMallocContiguousEntry, 1);
	if (!entry)
	{
	    bmd->release();
	    break;
	}
	entry->virtualAddr = (mach_vm_address_t) bmd->getBytesNoCopy();
	entry->md          = bmd;
	lck_mtx_lock(gIOMallocContiguousEntriesLock);
	queue_enter( &gIOMallocContiguousEntries, entry, 
		    _IOMallocContiguousEntry *, link );
	lck_mtx_unlock(gIOMallocContiguousEntriesLock);

	address          = (mach_vm_address_t) entry->virtualAddr;
	*physicalAddress = bmd->getPhysicalAddress();
    }
    while (false);

    return (void *) address;
}

void IOFreeContiguous(void * _address, vm_size_t size)
{
    _IOMallocContiguousEntry * entry;
    IOMemoryDescriptor *       md = NULL;

    mach_vm_address_t address = (mach_vm_address_t) _address;

    if( !address)
	return;

    assert(size);

    lck_mtx_lock(gIOMallocContiguousEntriesLock);
    queue_iterate( &gIOMallocContiguousEntries, entry,
		    _IOMallocContiguousEntry *, link )
    {
	if( entry->virtualAddr == address ) {
	    md   = entry->md;
	    queue_remove( &gIOMallocContiguousEntries, entry,
			    _IOMallocContiguousEntry *, link );
	    break;
	}
    }
    lck_mtx_unlock(gIOMallocContiguousEntriesLock);

    if (md)
    {
	md->release();
	IODelete(entry, _IOMallocContiguousEntry, 1);
    }
    else
    {
	IOKernelFreePhysical((mach_vm_address_t) address, size);
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t IOIteratePageableMaps(vm_size_t size,
                    IOIteratePageableMapsCallback callback, void * ref)
{
    kern_return_t	kr = kIOReturnNotReady;
    vm_size_t		segSize;
    UInt32		attempts;
    UInt32		index;
    vm_offset_t		min;
    vm_map_t		map;

    if (size > kIOPageableMaxMapSize)
        return( kIOReturnBadArgument );

    do {
        index = gIOKitPageableSpace.hint;
        attempts = gIOKitPageableSpace.count;
        while( attempts--) {
            kr = (*callback)(gIOKitPageableSpace.maps[index].map, ref);
            if( KERN_SUCCESS == kr) {
                gIOKitPageableSpace.hint = index;
                break;
            }
            if( index)
                index--;
            else
                index = gIOKitPageableSpace.count - 1;
        }
        if (KERN_NO_SPACE != kr)
            break;

        lck_mtx_lock( gIOKitPageableSpace.lock );

        index = gIOKitPageableSpace.count;
        if( index >= (kIOMaxPageableMaps - 1)) {
            lck_mtx_unlock( gIOKitPageableSpace.lock );
            break;
        }

        if( size < kIOPageableMapSize)
            segSize = kIOPageableMapSize;
        else
            segSize = size;

        min = 0;
        kr = kmem_suballoc(kernel_map,
                    &min,
                    segSize,
                    TRUE,
                    VM_FLAGS_ANYWHERE,
		    VM_MAP_KERNEL_FLAGS_NONE,
		    VM_KERN_MEMORY_IOKIT,
                    &map);
        if( KERN_SUCCESS != kr) {
            lck_mtx_unlock( gIOKitPageableSpace.lock );
            break;
        }

        gIOKitPageableSpace.maps[index].map 	= map;
        gIOKitPageableSpace.maps[index].address = min;
        gIOKitPageableSpace.maps[index].end 	= min + segSize;
        gIOKitPageableSpace.hint 		= index;
        gIOKitPageableSpace.count 		= index + 1;

        lck_mtx_unlock( gIOKitPageableSpace.lock );

    } while( true );

    return kr;
}

struct IOMallocPageableRef
{
    vm_offset_t address;
    vm_size_t	size;
    vm_tag_t    tag;
};

static kern_return_t IOMallocPageableCallback(vm_map_t map, void * _ref)
{
    struct IOMallocPageableRef * ref = (struct IOMallocPageableRef *) _ref;
    kern_return_t	         kr;

    kr = kmem_alloc_pageable( map, &ref->address, ref->size, ref->tag );

    return( kr );
}

static void * IOMallocPageablePages(vm_size_t size, vm_size_t alignment, vm_tag_t tag)
{
    kern_return_t	       kr = kIOReturnNotReady;
    struct IOMallocPageableRef ref;

    if (alignment > page_size)
        return( 0 );
    if (size > kIOPageableMaxMapSize)
        return( 0 );

    ref.size = size;
    ref.tag  = tag;
    kr = IOIteratePageableMaps( size, &IOMallocPageableCallback, &ref );
    if( kIOReturnSuccess != kr)
        ref.address = 0;

    return( (void *) ref.address );
}

vm_map_t IOPageableMapForAddress( uintptr_t address )
{
    vm_map_t	map = 0;
    UInt32	index;
    
    for( index = 0; index < gIOKitPageableSpace.count; index++) {
        if( (address >= gIOKitPageableSpace.maps[index].address)
         && (address < gIOKitPageableSpace.maps[index].end) ) {
            map = gIOKitPageableSpace.maps[index].map;
            break;
        }
    }
    if( !map)
        panic("IOPageableMapForAddress: null");

    return( map );
}

static void IOFreePageablePages(void * address, vm_size_t size)
{
    vm_map_t map;
    
    map = IOPageableMapForAddress( (vm_address_t) address);
    if( map)
        kmem_free( map, (vm_offset_t) address, size);
}

static uintptr_t IOMallocOnePageablePage(iopa_t * a)
{
    return ((uintptr_t) IOMallocPageablePages(page_size, page_size, VM_KERN_MEMORY_IOKIT));
}

void * IOMallocPageable(vm_size_t size, vm_size_t alignment)
{
    void * addr;

    if (size >= (page_size - 4*gIOPageAllocChunkBytes)) addr = IOMallocPageablePages(size, alignment, IOMemoryTag(kernel_map));
    else                   addr = ((void * ) iopa_alloc(&gIOPageablePageAllocator, &IOMallocOnePageablePage, size, alignment));

    if (addr) {
#if IOALLOCDEBUG
	   OSAddAtomicLong(size, &debug_iomallocpageable_size);
#endif
       IOStatisticsAlloc(kIOStatisticsMallocPageable, size);
    }

    return (addr);
}

void IOFreePageable(void * address, vm_size_t size)
{
#if IOALLOCDEBUG
	OSAddAtomicLong(-size, &debug_iomallocpageable_size);
#endif
    IOStatisticsAlloc(kIOStatisticsFreePageable, size);

    if (size < (page_size - 4*gIOPageAllocChunkBytes))
    {
	address = (void *) iopa_free(&gIOPageablePageAllocator, (uintptr_t) address, size);
	size = page_size;
    }
    if (address) IOFreePageablePages(address, size);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" void 
iopa_init(iopa_t * a)
{
    bzero(a, sizeof(*a));
    a->lock = IOLockAlloc();
    queue_init(&a->list);
}

static uintptr_t
iopa_allocinpage(iopa_page_t * pa, uint32_t count, uint64_t align)
{
    uint32_t n, s;
    uint64_t avail = pa->avail;

    assert(avail);

    // find strings of count 1 bits in avail
    for (n = count; n > 1; n -= s)
    {
    	s = n >> 1;
    	avail = avail & (avail << s);
    }
    // and aligned
    avail &= align;

    if (avail)
    {
	n = __builtin_clzll(avail);
	pa->avail &= ~((-1ULL << (64 - count)) >> n);
	if (!pa->avail && pa->link.next)
	{
	    remque(&pa->link);
	    pa->link.next = 0;
	}
	return (n * gIOPageAllocChunkBytes + trunc_page((uintptr_t) pa));
    }

    return (0);
}

uintptr_t 
iopa_alloc(iopa_t * a, iopa_proc_t alloc, vm_size_t bytes, uint32_t balign)
{
    static const uint64_t align_masks[] = {
	0xFFFFFFFFFFFFFFFF,
	0xAAAAAAAAAAAAAAAA,
	0x8888888888888888,
	0x8080808080808080,
	0x8000800080008000,
	0x8000000080000000,
	0x8000000000000000,
    };
    iopa_page_t * pa;
    uintptr_t     addr = 0;
    uint32_t      count;
    uint64_t      align;

    if (!bytes) bytes = 1;
    count = (bytes + gIOPageAllocChunkBytes - 1) / gIOPageAllocChunkBytes;
    align = align_masks[log2up((balign + gIOPageAllocChunkBytes - 1) / gIOPageAllocChunkBytes)];

    IOLockLock(a->lock);
    __IGNORE_WCASTALIGN(pa = (typeof(pa)) queue_first(&a->list));
    while (!queue_end(&a->list, &pa->link))
    {
	addr = iopa_allocinpage(pa, count, align);
	if (addr)
	{
	    a->bytecount += bytes;
	    break;
	}
	__IGNORE_WCASTALIGN(pa = (typeof(pa)) queue_next(&pa->link));
    }
    IOLockUnlock(a->lock);

    if (!addr)
    {
	addr = alloc(a);
	if (addr)
	{
	    pa = (typeof(pa)) (addr + page_size - gIOPageAllocChunkBytes);
	    pa->signature = kIOPageAllocSignature;
	    pa->avail     = -2ULL;

	    addr = iopa_allocinpage(pa, count, align);
	    IOLockLock(a->lock);
	    if (pa->avail) enqueue_head(&a->list, &pa->link);
	    a->pagecount++;
	    if (addr) a->bytecount += bytes;
	    IOLockUnlock(a->lock);
	}
    }

    assert((addr & ((1 << log2up(balign)) - 1)) == 0);
    return (addr);
}

uintptr_t 
iopa_free(iopa_t * a, uintptr_t addr, vm_size_t bytes)
{
    iopa_page_t * pa;
    uint32_t      count;
    uintptr_t     chunk;

    if (!bytes) bytes = 1;

    chunk = (addr & page_mask);
    assert(0 == (chunk & (gIOPageAllocChunkBytes - 1)));

    pa = (typeof(pa)) (addr | (page_size - gIOPageAllocChunkBytes));
    assert(kIOPageAllocSignature == pa->signature);

    count = (bytes + gIOPageAllocChunkBytes - 1) / gIOPageAllocChunkBytes;
    chunk /= gIOPageAllocChunkBytes;

    IOLockLock(a->lock);
    if (!pa->avail)
    {
	assert(!pa->link.next);
	enqueue_tail(&a->list, &pa->link);
    }
    pa->avail |= ((-1ULL << (64 - count)) >> chunk);
    if (pa->avail != -2ULL) pa = 0;
    else
    {
        remque(&pa->link);
        pa->link.next = 0;
        pa->signature = 0;
	a->pagecount--;
	// page to free
	pa = (typeof(pa)) trunc_page(pa);
    }
    a->bytecount -= bytes;
    IOLockUnlock(a->lock);

    return ((uintptr_t) pa);
}
    
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOSetProcessorCacheMode( task_t task, IOVirtualAddress address,
				  IOByteCount length, IOOptionBits cacheMode )
{
    IOReturn	ret = kIOReturnSuccess;
    ppnum_t	pagenum;

    if( task != kernel_task)
	return( kIOReturnUnsupported );
    if ((address | length) & PAGE_MASK)
    {
//	OSReportWithBacktrace("IOSetProcessorCacheMode(0x%x, 0x%x, 0x%x) fails\n", address, length, cacheMode);
	return( kIOReturnUnsupported );
    }
    length = round_page(address + length) - trunc_page( address );
    address = trunc_page( address );

    // make map mode
    cacheMode = (cacheMode << kIOMapCacheShift) & kIOMapCacheMask;

    while( (kIOReturnSuccess == ret) && (length > 0) ) {

	// Get the physical page number
	pagenum = pmap_find_phys(kernel_pmap, (addr64_t)address);
	if( pagenum) {
            ret = IOUnmapPages( get_task_map(task), address, page_size );
	    ret = IOMapPages( get_task_map(task), address, ptoa_64(pagenum), page_size, cacheMode );
	} else
	    ret = kIOReturnVMError;

	address += page_size;
	length -= page_size;
    }

    return( ret );
}


IOReturn IOFlushProcessorCache( task_t task, IOVirtualAddress address,
				  IOByteCount length )
{
    if( task != kernel_task)
	return( kIOReturnUnsupported );

    flush_dcache64( (addr64_t) address, (unsigned) length, false );

    return( kIOReturnSuccess );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

vm_offset_t OSKernelStackRemaining( void )
{
    return (ml_stack_remaining());
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Spin for indicated number of milliseconds.
 */
void IOSleep(unsigned milliseconds)
{
    delay_for_interval(milliseconds, kMillisecondScale);
}

/*
 * Spin for indicated number of milliseconds, and potentially an
 * additional number of milliseconds up to the leeway values.
 */
void IOSleepWithLeeway(unsigned intervalMilliseconds, unsigned leewayMilliseconds)
{
    delay_for_interval_with_leeway(intervalMilliseconds, leewayMilliseconds, kMillisecondScale);
}

/*
 * Spin for indicated number of microseconds.
 */
void IODelay(unsigned microseconds)
{
    delay_for_interval(microseconds, kMicrosecondScale);
}

/*
 * Spin for indicated number of nanoseconds.
 */
void IOPause(unsigned nanoseconds)
{
    delay_for_interval(nanoseconds, kNanosecondScale);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void _IOLogv(const char *format, va_list ap, void *caller) __printflike(1,0);

__attribute__((noinline,not_tail_called))
void IOLog(const char *format, ...)
{
    void *caller = __builtin_return_address(0);
    va_list ap;

    va_start(ap, format);
    _IOLogv(format, ap, caller);
    va_end(ap);
}

__attribute__((noinline,not_tail_called))
void IOLogv(const char *format, va_list ap)
{
    void *caller = __builtin_return_address(0);
    _IOLogv(format, ap, caller);
}

void _IOLogv(const char *format, va_list ap, void *caller)
{
    va_list ap2;
    struct console_printbuf_state info_data;
    console_printbuf_state_init(&info_data, TRUE, TRUE);

    va_copy(ap2, ap);

    os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, format, ap, caller);

    __doprnt(format, ap2, console_printbuf_putc, &info_data, 16, TRUE);
    console_printbuf_clear(&info_data);
    va_end(ap2);

    assertf(ml_get_interrupts_enabled() || ml_is_quiescing() || debug_mode_active() || !gCPUsRunning, "IOLog called with interrupts disabled");
}

#if !__LP64__
void IOPanic(const char *reason)
{
	panic("%s", reason);
}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOKitKernelLogBuffer(const char * title, const void * buffer, size_t size,
                          void (*output)(const char *format, ...))
{
    uint8_t c, chars[17];
    size_t idx;

    output("%s(0x%x):\n", title, size);
    if (size > 4096) size = 4096;
    chars[16] = idx = 0;
    while (true) {
        if (!(idx & 15)) {
            if (idx) output(" |%s|\n", chars);
            if (idx >= size) break;
            output("%04x:  ", idx);
        }
        else if (!(idx & 7)) output(" ");

        c =  ((char *)buffer)[idx];
        output("%02x ", c);
        chars[idx & 15] = ((c >= 0x20) && (c <= 0x7f)) ? c : ' ';

        idx++;
        if ((idx == size) && (idx & 15)) {
            chars[idx & 15] = 0;
            while (idx & 15) {
                idx++;
                output("   ");
            }
        }
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Convert a integer constant (typically a #define or enum) to a string.
 */
static char noValue[80];	// that's pretty

const char *IOFindNameForValue(int value, const IONamedValue *regValueArray)
{
	for( ; regValueArray->name; regValueArray++) {
		if(regValueArray->value == value)
			return(regValueArray->name);
	}
	snprintf(noValue, sizeof(noValue), "0x%x (UNDEFINED)", value);
	return((const char *)noValue);
}

IOReturn IOFindValueForName(const char *string, 
	const IONamedValue *regValueArray,
	int *value)
{
	for( ; regValueArray->name; regValueArray++) {
		if(!strcmp(regValueArray->name, string)) {
			*value = regValueArray->value;
			return kIOReturnSuccess;
		}
	}
	return kIOReturnBadArgument;
}

OSString * IOCopyLogNameForPID(int pid)
{
    char   buf[128];
    size_t len;
    snprintf(buf, sizeof(buf), "pid %d, ", pid);
    len = strlen(buf);
    proc_name(pid, buf + len, sizeof(buf) - len);
    return (OSString::withCString(buf));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOAlignment IOSizeToAlignment(unsigned int size)
{
    int shift;
    const int intsize = sizeof(unsigned int) * 8;
    
    for (shift = 1; shift < intsize; shift++) {
	if (size & 0x80000000)
	    return (IOAlignment)(intsize - shift);
	size <<= 1;
    }
    return 0;
}

unsigned int IOAlignmentToSize(IOAlignment align)
{
    unsigned int size;
    
    for (size = 1; align; align--) {
	size <<= 1;
    }
    return size;
}

} /* extern "C" */



