/*
 * Copyright (c) 1998-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <libkern/c++/OSCPPDebug.h>

#include <IOKit/assert.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOLib.h> 
#include <IOKit/IOMapper.h>
#include <IOKit/IOKitDebug.h> 

mach_timespec_t IOZeroTvalspec = { 0, 0 };

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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

static IOThreadFunc threadArgFcn;
static void *       threadArgArg;
static lock_t *     threadArgLock;

static queue_head_t gIOMallocContiguousEntries;
static mutex_t *    gIOMallocContiguousEntriesLock;

enum { kIOMaxPageableMaps = 16 };
enum { kIOPageableMapSize = 16 * 1024 * 1024 };
enum { kIOPageableMaxMapSize = 96 * 1024 * 1024 };

typedef struct {
    vm_map_t	map;
    vm_offset_t	address;
    vm_offset_t	end;
} IOMapData;

static struct {
    UInt32	count;
    UInt32	hint;
    IOMapData	maps[ kIOMaxPageableMaps ];
    mutex_t *	lock;
} gIOKitPageableSpace;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOLibInit(void)
{
    kern_return_t ret;

    static bool libInitialized;

    if(libInitialized)
        return;	

    threadArgLock = lock_alloc( true, NULL, NULL );

    gIOKitPageableSpace.maps[0].address = 0;
    ret = kmem_suballoc(kernel_map,
                    &gIOKitPageableSpace.maps[0].address,
                    kIOPageableMapSize,
                    TRUE,
                    TRUE,
                    &gIOKitPageableSpace.maps[0].map);
    if (ret != KERN_SUCCESS)
        panic("failed to allocate iokit pageable map\n");

    gIOKitPageableSpace.lock 		= mutex_alloc( 0 );
    gIOKitPageableSpace.maps[0].end	= gIOKitPageableSpace.maps[0].address + kIOPageableMapSize;
    gIOKitPageableSpace.hint		= 0;
    gIOKitPageableSpace.count		= 1;

    gIOMallocContiguousEntriesLock 	= mutex_alloc( 0 );
    queue_init( &gIOMallocContiguousEntries );

    libInitialized = true;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * We pass an argument to a new thread by saving fcn and arg in some
 * locked variables and starting the thread at ioThreadStart(). This
 * function retrives fcn and arg and makes the appropriate call.
 *
 */

static void ioThreadStart( void )
{
    IOThreadFunc	fcn;
    void * 		arg;

    fcn = threadArgFcn;
    arg = threadArgArg;
    lock_done( threadArgLock);

    (*fcn)(arg);

    IOExitThread();
}

IOThread IOCreateThread(IOThreadFunc fcn, void *arg)
{
	IOThread thread;

	lock_write( threadArgLock);
	threadArgFcn = fcn;
	threadArgArg = arg;

	thread = kernel_thread( kernel_task, ioThreadStart);

	return(thread);
}


volatile void IOExitThread()
{
	(void) thread_terminate(current_act());
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


void * IOMalloc(vm_size_t size)
{
    void * address;

    address = (void *)kalloc(size);
#if IOALLOCDEBUG
    if (address)
	debug_iomalloc_size += size;
#endif
    return address;
}

void IOFree(void * address, vm_size_t size)
{
    if (address) {
	kfree((vm_offset_t)address, size);
#if IOALLOCDEBUG
	debug_iomalloc_size -= size;
#endif
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void * IOMallocAligned(vm_size_t size, vm_size_t alignment)
{
    kern_return_t	kr;
    vm_address_t	address;
    vm_address_t	allocationAddress;
    vm_size_t		adjustedSize;
    vm_offset_t		alignMask;

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

            *((vm_size_t *)(address - sizeof(vm_size_t)
                            - sizeof(vm_address_t))) = adjustedSize;
            *((vm_address_t *)(address - sizeof(vm_address_t)))
                            = allocationAddress;
	} else
	    address = 0;
    }

    assert(0 == (address & alignMask));

#if IOALLOCDEBUG
    if( address)
	debug_iomalloc_size += size;
#endif

    return (void *) address;
}

void IOFreeAligned(void * address, vm_size_t size)
{
    vm_address_t	allocationAddress;
    vm_size_t		adjustedSize;

    if( !address)
	return;

    assert(size);

    adjustedSize = size + sizeof(vm_size_t) + sizeof(vm_address_t);
    if (adjustedSize >= page_size) {

        kmem_free( kernel_map, (vm_address_t) address, size);

    } else {
        adjustedSize = *((vm_size_t *)( (vm_address_t) address
                                - sizeof(vm_address_t) - sizeof(vm_size_t)));
        allocationAddress = *((vm_address_t *)( (vm_address_t) address
				- sizeof(vm_address_t) ));

	if (adjustedSize >= page_size)
	    kmem_free( kernel_map, (vm_address_t) allocationAddress, adjustedSize);
	else
	    kfree((vm_offset_t) allocationAddress, adjustedSize);
    }

#if IOALLOCDEBUG
    debug_iomalloc_size -= size;
#endif
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct _IOMallocContiguousEntry
{
    void *		virtual;
    ppnum_t		ioBase;
    queue_chain_t	link;
};
typedef struct _IOMallocContiguousEntry _IOMallocContiguousEntry;

void * IOMallocContiguous(vm_size_t size, vm_size_t alignment,
			   IOPhysicalAddress * physicalAddress)
{
    kern_return_t	kr;
    vm_address_t	address;
    vm_address_t	allocationAddress;
    vm_size_t		adjustedSize;
    vm_offset_t		alignMask;
    ppnum_t		pagenum;

    if (size == 0)
        return 0;
    if (alignment == 0) 
        alignment = 1;

    alignMask = alignment - 1;
    adjustedSize = (2 * size) + sizeof(vm_size_t) + sizeof(vm_address_t);

    if (adjustedSize >= page_size)
    {
	adjustedSize = size;
	if (adjustedSize > page_size)
	{
	    kr = kmem_alloc_contig(kernel_map, &address, size,
				    alignMask, 0);
	}
	else
	{
	    kr = kernel_memory_allocate(kernel_map, &address,
					size, alignMask, 0);
	}
	if (KERN_SUCCESS != kr)
	    address = 0;
    }
    else
    {
	adjustedSize += alignMask;
        allocationAddress = (vm_address_t) kalloc(adjustedSize);

        if (allocationAddress) {

            address = (allocationAddress + alignMask
                    + (sizeof(vm_size_t) + sizeof(vm_address_t)))
                    & (~alignMask);

            if (atop_32(address) != atop_32(address + size - 1))
                address = round_page_32(address);

            *((vm_size_t *)(address - sizeof(vm_size_t)
                            - sizeof(vm_address_t))) = adjustedSize;
            *((vm_address_t *)(address - sizeof(vm_address_t)))
                            = allocationAddress;
	} else
	    address = 0;
    }

    /* Do we want a physical address? */
    if (address && physicalAddress)
    {
	do
	{
	    /* Get the physical page */
	    pagenum = pmap_find_phys(kernel_pmap, (addr64_t) address);
	    if(pagenum)
	    {
		IOByteCount offset;
		ppnum_t base;
    
		base = IOMapperIOVMAlloc((size + PAGE_MASK) >> PAGE_SHIFT);
		if (base)
		{
		    _IOMallocContiguousEntry *
		    entry = IONew(_IOMallocContiguousEntry, 1);
		    if (!entry)
		    {
			IOFreeContiguous((void *) address, size);
			address = 0;
			break;
		    }
		    entry->virtual = (void *) address;
		    entry->ioBase  = base;
		    mutex_lock(gIOMallocContiguousEntriesLock);
		    queue_enter( &gIOMallocContiguousEntries, entry, 
				_IOMallocContiguousEntry *, link );
		    mutex_unlock(gIOMallocContiguousEntriesLock);
    
		    *physicalAddress = (IOPhysicalAddress)((base << PAGE_SHIFT) | (address & PAGE_MASK));
		    for (offset = 0; offset < ((size + PAGE_MASK) >> PAGE_SHIFT); offset++, pagenum++)
			IOMapperInsertPage( base, offset, pagenum );
		}
		else
		    *physicalAddress = (IOPhysicalAddress)((pagenum << PAGE_SHIFT) | (address & PAGE_MASK));
	    } 
	    else
		/* Did not find, return 0 */
		*physicalAddress = (IOPhysicalAddress) 0;
	}
	while (false);
    }

    assert(0 == (address & alignMask));

#if IOALLOCDEBUG
    if( address)
	debug_iomalloc_size += size;
#endif

    return (void *) address;
}

void IOFreeContiguous(void * address, vm_size_t size)
{
    vm_address_t	       allocationAddress;
    vm_size_t		       adjustedSize;
    _IOMallocContiguousEntry * entry;
    ppnum_t		       base = 0;

    if( !address)
	return;

    assert(size);

    mutex_lock(gIOMallocContiguousEntriesLock);
    queue_iterate( &gIOMallocContiguousEntries, entry,
		    _IOMallocContiguousEntry *, link )
    {
	if( entry->virtual == address ) {
	    base = entry->ioBase;
	    queue_remove( &gIOMallocContiguousEntries, entry,
			    _IOMallocContiguousEntry *, link );
	    break;
	}
    }
    mutex_unlock(gIOMallocContiguousEntriesLock);

    if (base)
    {
	IOMapperIOVMFree(base, (size + PAGE_MASK) >> PAGE_SHIFT);
	IODelete(entry, _IOMallocContiguousEntry, 1);
    }

    adjustedSize = (2 * size) + sizeof(vm_size_t) + sizeof(vm_address_t);
    if (adjustedSize >= page_size) {

        kmem_free( kernel_map, (vm_address_t) address, size);

    } else {
        adjustedSize = *((vm_size_t *)( (vm_address_t) address
                                - sizeof(vm_address_t) - sizeof(vm_size_t)));
        allocationAddress = *((vm_address_t *)( (vm_address_t) address
				- sizeof(vm_address_t) ));

        kfree((vm_offset_t) allocationAddress, adjustedSize);
    }

#if IOALLOCDEBUG
    debug_iomalloc_size -= size;
#endif
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

typedef kern_return_t (*IOIteratePageableMapsCallback)(vm_map_t map, void * ref);

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

        mutex_lock( gIOKitPageableSpace.lock );

        index = gIOKitPageableSpace.count;
        if( index >= (kIOMaxPageableMaps - 1)) {
            mutex_unlock( gIOKitPageableSpace.lock );
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
                    TRUE,
                    &map);
        if( KERN_SUCCESS != kr) {
            mutex_unlock( gIOKitPageableSpace.lock );
            break;
        }

        gIOKitPageableSpace.maps[index].map 	= map;
        gIOKitPageableSpace.maps[index].address = min;
        gIOKitPageableSpace.maps[index].end 	= min + segSize;
        gIOKitPageableSpace.hint 		= index;
        gIOKitPageableSpace.count 		= index + 1;

        mutex_unlock( gIOKitPageableSpace.lock );

    } while( true );

    return kr;
}

struct IOMallocPageableRef
{
    vm_address_t address;
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
       debug_iomalloc_size += round_page_32(size);
#endif

    return( (void *) ref.address );
}

vm_map_t IOPageableMapForAddress( vm_address_t address )
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
        IOPanic("IOPageableMapForAddress: null");

    return( map );
}

void IOFreePageable(void * address, vm_size_t size)
{
    vm_map_t map;
    
    map = IOPageableMapForAddress( (vm_address_t) address);
    if( map)
        kmem_free( map, (vm_offset_t) address, size);

#if IOALLOCDEBUG
    debug_iomalloc_size -= round_page_32(size);
#endif
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern kern_return_t IOMapPages(vm_map_t map, vm_offset_t va, vm_offset_t pa,
			vm_size_t length, unsigned int options);
extern kern_return_t IOUnmapPages(vm_map_t map, vm_offset_t va, vm_size_t length);

IOReturn IOSetProcessorCacheMode( task_t task, IOVirtualAddress address,
				  IOByteCount length, IOOptionBits cacheMode )
{
    IOReturn	ret = kIOReturnSuccess;
    ppnum_t	pagenum;

    if( task != kernel_task)
	return( kIOReturnUnsupported );

    length = round_page_32(address + length) - trunc_page_32( address );
    address = trunc_page_32( address );

    // make map mode
    cacheMode = (cacheMode << kIOMapCacheShift) & kIOMapCacheMask;

    while( (kIOReturnSuccess == ret) && (length > 0) ) {

	// Get the physical page number
	pagenum = pmap_find_phys(kernel_pmap, (addr64_t)address);
	if( pagenum) {
            ret = IOUnmapPages( get_task_map(task), address, page_size );
	    ret = IOMapPages( get_task_map(task), address, pagenum << PAGE_SHIFT, page_size, cacheMode );
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

#if __ppc__
    flush_dcache64( (addr64_t) address, (unsigned) length, false );
#endif

    return( kIOReturnSuccess );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

SInt32 OSKernelStackRemaining( void )
{
   SInt32 stack;

   stack = (((SInt32) &stack) & (KERNEL_STACK_SIZE - 1));

   return( stack );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOSleep(unsigned milliseconds)
{
    wait_result_t wait_result;

    wait_result = assert_wait_timeout(milliseconds, THREAD_UNINT);
    assert(wait_result == THREAD_WAITING);

    wait_result = thread_block(THREAD_CONTINUE_NULL);
    assert(wait_result == THREAD_TIMED_OUT);
}

/*
 * Spin for indicated number of microseconds.
 */
void IODelay(unsigned microseconds)
{
    extern void delay(int usec);

    delay(microseconds);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOLog(const char *format, ...)
{
	va_list ap;
	extern void conslog_putc(char);
	extern void logwakeup();

	va_start(ap, format);
	_doprnt(format, &ap, conslog_putc, 16);
	va_end(ap);
}

void IOPanic(const char *reason)
{
	panic(reason);
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
	sprintf(noValue, "0x%x (UNDEFINED)", value);
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

IOReturn IONDRVLibrariesInitialize( void )
{
    return( kIOReturnUnsupported );
}
