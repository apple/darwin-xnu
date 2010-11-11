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

extern "C"
{


mach_timespec_t IOZeroTvalspec = { 0, 0 };

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);

int
__doprnt(
	const char		*fmt,
	va_list			argp,
	void			(*putc)(int, void *),
	void                    *arg,
	int			radix);

extern void conslog_putc(char);


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


/*
 * Static variables for this module.
 */

static queue_head_t gIOMallocContiguousEntries;
static lck_mtx_t *  gIOMallocContiguousEntriesLock;

enum { kIOMaxPageableMaps = 16 };
enum { kIOPageableMapSize = 96 * 1024 * 1024 };
enum { kIOPageableMaxMapSize = 96 * 1024 * 1024 };

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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOLibInit(void)
{
    kern_return_t ret;

    static bool libInitialized;

    if(libInitialized)
        return;	

    gIOKitPageableSpace.maps[0].address = 0;
    ret = kmem_suballoc(kernel_map,
                    &gIOKitPageableSpace.maps[0].address,
                    kIOPageableMapSize,
                    TRUE,
                    VM_FLAGS_ANYWHERE,
                    &gIOKitPageableSpace.maps[0].map);
    if (ret != KERN_SUCCESS)
        panic("failed to allocate iokit pageable map\n");

    IOLockGroup = lck_grp_alloc_init("IOKit", LCK_GRP_ATTR_NULL);

    gIOKitPageableSpace.lock 		= lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
    gIOKitPageableSpace.maps[0].end	= gIOKitPageableSpace.maps[0].address + kIOPageableMapSize;
    gIOKitPageableSpace.hint		= 0;
    gIOKitPageableSpace.count		= 1;

    gIOMallocContiguousEntriesLock 	= lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
    queue_init( &gIOMallocContiguousEntries );

    libInitialized = true;
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


void * IOMalloc(vm_size_t size)
{
    void * address;

    address = (void *)kalloc(size);
#if IOALLOCDEBUG
    if (address) {
		debug_iomalloc_size += size;
	}
#endif
    return address;
}

void IOFree(void * address, vm_size_t size)
{
    if (address) {
		kfree(address, size);
#if IOALLOCDEBUG
		debug_iomalloc_size -= size;
#endif
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void * IOMallocAligned(vm_size_t size, vm_size_t alignment)
{
    kern_return_t	kr;
    vm_offset_t		address;
    vm_offset_t		allocationAddress;
    vm_size_t		adjustedSize;
    uintptr_t		alignMask;

    if (size == 0)
        return 0;
    if (alignment == 0) 
        alignment = 1;

    alignMask = alignment - 1;
    adjustedSize = size + sizeof(vm_size_t) + sizeof(vm_address_t);

    if (adjustedSize >= page_size) {

        kr = kernel_memory_allocate(kernel_map, &address,
					size, alignMask, 0);
	if (KERN_SUCCESS != kr)
	    address = 0;

    } else {

	adjustedSize += alignMask;

	if (adjustedSize >= page_size) {

	    kr = kernel_memory_allocate(kernel_map, &allocationAddress,
					    adjustedSize, 0, 0);
	    if (KERN_SUCCESS != kr)
		allocationAddress = 0;

	} else
	    allocationAddress = (vm_address_t) kalloc(adjustedSize);

        if (allocationAddress) {
            address = (allocationAddress + alignMask
                    + (sizeof(vm_size_t) + sizeof(vm_address_t)))
                    & (~alignMask);

            *((vm_size_t *)(address - sizeof(vm_size_t) - sizeof(vm_address_t))) 
			    = adjustedSize;
            *((vm_address_t *)(address - sizeof(vm_address_t)))
                            = allocationAddress;
	} else
	    address = 0;
    }

    assert(0 == (address & alignMask));

#if IOALLOCDEBUG
    if( address) {
		debug_iomalloc_size += size;
	}
#endif

    return (void *) address;
}

void IOFreeAligned(void * address, vm_size_t size)
{
    vm_address_t	allocationAddress;
    vm_size_t	adjustedSize;

    if( !address)
	return;

    assert(size);

    adjustedSize = size + sizeof(vm_size_t) + sizeof(vm_address_t);
    if (adjustedSize >= page_size) {

        kmem_free( kernel_map, (vm_offset_t) address, size);

    } else {
      	adjustedSize = *((vm_size_t *)( (vm_address_t) address
                                - sizeof(vm_address_t) - sizeof(vm_size_t)));
        allocationAddress = *((vm_address_t *)( (vm_address_t) address
				- sizeof(vm_address_t) ));

	if (adjustedSize >= page_size)
	    kmem_free( kernel_map, allocationAddress, adjustedSize);
	else
	  kfree((void *)allocationAddress, adjustedSize);
    }

#if IOALLOCDEBUG
    debug_iomalloc_size -= size;
#endif
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOKernelFreePhysical(mach_vm_address_t address, mach_vm_size_t size)
{
    mach_vm_address_t allocationAddress;
    mach_vm_size_t    adjustedSize;

    if (!address)
	return;

    assert(size);

    adjustedSize = (2 * size) + sizeof(mach_vm_size_t) + sizeof(mach_vm_address_t);
    if (adjustedSize >= page_size) {

	kmem_free( kernel_map, (vm_offset_t) address, size);

    } else {

	adjustedSize = *((mach_vm_size_t *)
			(address - sizeof(mach_vm_address_t) - sizeof(mach_vm_size_t)));
	allocationAddress = *((mach_vm_address_t *)
			(address - sizeof(mach_vm_address_t) ));
	kfree((void *)allocationAddress, adjustedSize);
    }

#if IOALLOCDEBUG
    debug_iomalloc_size -= size;
#endif
}

mach_vm_address_t
IOKernelAllocateWithPhysicalRestrict(mach_vm_size_t size, mach_vm_address_t maxPhys, 
				     mach_vm_size_t alignment, bool contiguous)
{
    kern_return_t	kr;
    mach_vm_address_t	address;
    mach_vm_address_t	allocationAddress;
    mach_vm_size_t	adjustedSize;
    mach_vm_address_t	alignMask;

    if (size == 0)
	return (0);
    if (alignment == 0) 
        alignment = 1;

    alignMask = alignment - 1;
    adjustedSize = (2 * size) + sizeof(mach_vm_size_t) + sizeof(mach_vm_address_t);

    contiguous = (contiguous && (adjustedSize > page_size))
                   || (alignment > page_size);

    if (contiguous || maxPhys)
    {
        int options = 0;
	vm_offset_t virt;

	adjustedSize = size;
        contiguous = (contiguous && (adjustedSize > page_size))
                           || (alignment > page_size);

        if ((!contiguous) && (maxPhys <= 0xFFFFFFFF))
        {
            maxPhys = 0;
            options |= KMA_LOMEM;
        }

	if (contiguous || maxPhys)
	{
	    kr = kmem_alloc_contig(kernel_map, &virt, size,
				   alignMask, atop(maxPhys), atop(alignMask), 0);
	}
	else
	{
	    kr = kernel_memory_allocate(kernel_map, &virt,
					size, alignMask, options);
	}
	if (KERN_SUCCESS == kr)
	    address = virt;
	else
	    address = 0;
    }
    else
    {
	adjustedSize += alignMask;
        allocationAddress = (mach_vm_address_t) kalloc(adjustedSize);

        if (allocationAddress) {

            address = (allocationAddress + alignMask
                    + (sizeof(mach_vm_size_t) + sizeof(mach_vm_address_t)))
                    & (~alignMask);

            if (atop_32(address) != atop_32(address + size - 1))
                address = round_page(address);

            *((mach_vm_size_t *)(address - sizeof(mach_vm_size_t)
                            - sizeof(mach_vm_address_t))) = adjustedSize;
            *((mach_vm_address_t *)(address - sizeof(mach_vm_address_t)))
                            = allocationAddress;
	} else
	    address = 0;
    }

#if IOALLOCDEBUG
    if (address) {
	debug_iomalloc_size += size;
    }
#endif

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
        if( KERN_SUCCESS == kr)
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
    vm_size_t	 size;
};

static kern_return_t IOMallocPageableCallback(vm_map_t map, void * _ref)
{
    struct IOMallocPageableRef * ref = (struct IOMallocPageableRef *) _ref;
    kern_return_t	         kr;

    kr = kmem_alloc_pageable( map, &ref->address, ref->size );

    return( kr );
}

void * IOMallocPageable(vm_size_t size, vm_size_t alignment)
{
    kern_return_t	       kr = kIOReturnNotReady;
    struct IOMallocPageableRef ref;

    if (alignment > page_size)
        return( 0 );
    if (size > kIOPageableMaxMapSize)
        return( 0 );

    ref.size = size;
    kr = IOIteratePageableMaps( size, &IOMallocPageableCallback, &ref );
    if( kIOReturnSuccess != kr)
        ref.address = 0;

#if IOALLOCDEBUG
    if( ref.address)
       debug_iomallocpageable_size += round_page(size);
#endif

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

void IOFreePageable(void * address, vm_size_t size)
{
    vm_map_t map;
    
    map = IOPageableMapForAddress( (vm_address_t) address);
    if( map)
        kmem_free( map, (vm_offset_t) address, size);

#if IOALLOCDEBUG
    debug_iomallocpageable_size -= round_page(size);
#endif
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

static void _iolog_putc(int ch, void *arg __unused)
{
	conslog_putc(ch);
}

void IOLog(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	__doprnt(format, ap, _iolog_putc, NULL, 16);
	va_end(ap);
}

void IOLogv(const char *format, va_list ap)
{
	__doprnt(format, ap, _iolog_putc, NULL, 16);
}

#if !__LP64__
void IOPanic(const char *reason)
{
	panic("%s", reason);
}
#endif

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
    register int shift;
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



