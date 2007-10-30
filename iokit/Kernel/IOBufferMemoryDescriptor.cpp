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
#include <IOKit/assert.h>
#include <IOKit/system.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include "IOKitKernelInternal.h"
#include "IOCopyMapper.h"

__BEGIN_DECLS
void ipc_port_release_send(ipc_port_t port);
#include <vm/pmap.h>

vm_map_t IOPageableMapForAddress( vm_address_t address );
__END_DECLS

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

volatile ppnum_t gIOHighestAllocatedPage;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOGeneralMemoryDescriptor
OSDefineMetaClassAndStructors(IOBufferMemoryDescriptor,
				IOGeneralMemoryDescriptor);

bool IOBufferMemoryDescriptor::initWithAddress(
                                  void *      /* address       */ ,
                                  IOByteCount /* withLength    */ ,
                                  IODirection /* withDirection */ )
{
    return false;
}

bool IOBufferMemoryDescriptor::initWithAddress(
                                  vm_address_t /* address       */ ,
                                  IOByteCount  /* withLength    */ ,
                                  IODirection  /* withDirection */ ,
                                  task_t       /* withTask      */ )
{
    return false;
}

bool IOBufferMemoryDescriptor::initWithPhysicalAddress(
                                  IOPhysicalAddress /* address       */ ,
                                  IOByteCount       /* withLength    */ ,
                                  IODirection       /* withDirection */ )
{
    return false;
}

bool IOBufferMemoryDescriptor::initWithPhysicalRanges(
                                  IOPhysicalRange * /* ranges        */ ,
                                  UInt32            /* withCount     */ ,
                                  IODirection       /* withDirection */ ,
                                  bool              /* asReference   */ )
{
    return false;
}

bool IOBufferMemoryDescriptor::initWithRanges(
                                  IOVirtualRange * /* ranges        */ ,
                                  UInt32           /* withCount     */ ,
                                  IODirection      /* withDirection */ ,
                                  task_t           /* withTask      */ ,
                                  bool             /* asReference   */ )
{
    return false;
}

bool IOBufferMemoryDescriptor::initWithOptions(
                               IOOptionBits options,
                               vm_size_t    capacity,
                               vm_offset_t  alignment,
			       task_t	    inTask)
{
    mach_vm_address_t physicalMask = 0;
    return (initWithPhysicalMask(inTask, options, capacity, alignment, physicalMask));
}

bool IOBufferMemoryDescriptor::initWithPhysicalMask(
				task_t		  inTask,
				IOOptionBits      options,
				mach_vm_size_t    capacity,
				mach_vm_address_t alignment,
				mach_vm_address_t physicalMask)
{
    kern_return_t 	kr;
    task_t		mapTask = NULL;
    vm_map_t 		vmmap = NULL;
    addr64_t            lastIOAddr;
    IOAddressRange	range;
    IOOptionBits	iomdOptions = kIOMemoryTypeVirtual64;

    if (!capacity)
        return false;

    _options   	  = options;
    _capacity     = capacity;
    _physAddrs    = 0;
    _physSegCount = 0;
    _buffer	  = 0;
    range.address = 0;
    range.length  = 0;
    _ranges.v64   = &range;

    // Grab the direction and the Auto Prepare bits from the Buffer MD options
    iomdOptions  |= options & (kIOMemoryDirectionMask | kIOMemoryAutoPrepare);

    if ((options & (kIOMemorySharingTypeMask | kIOMapCacheMask)) && (alignment < page_size))
	alignment = page_size;

    if (physicalMask && (alignment <= 1))
	alignment = ((physicalMask ^ PAGE_MASK) & PAGE_MASK) + 1;

    _alignment = alignment;

    if (((inTask != kernel_task) && !(options & kIOMemoryPageable)) ||
	(physicalMask && (options & kIOMapCacheMask)))
	return false;

    if ((options & kIOMemoryPhysicallyContiguous) && !physicalMask)
	physicalMask = 0xFFFFFFFF;

    // set flags for entry + object create
    vm_prot_t memEntryCacheMode = VM_PROT_READ | VM_PROT_WRITE;

    // set memory entry cache mode
    switch (options & kIOMapCacheMask)
    {
	case kIOMapInhibitCache:
	    SET_MAP_MEM(MAP_MEM_IO, memEntryCacheMode);
	    break;

	case kIOMapWriteThruCache:
	    SET_MAP_MEM(MAP_MEM_WTHRU, memEntryCacheMode);
	    break;

	case kIOMapWriteCombineCache:
	    SET_MAP_MEM(MAP_MEM_WCOMB, memEntryCacheMode);
	    break;

	case kIOMapCopybackCache:
	    SET_MAP_MEM(MAP_MEM_COPYBACK, memEntryCacheMode);
	    break;

	case kIOMapDefaultCache:
	default:
	    SET_MAP_MEM(MAP_MEM_NOOP, memEntryCacheMode);
	    break;
    }

    if (options & kIOMemoryPageable)
    {
	iomdOptions |= kIOMemoryBufferPageable;

	// must create the entry before any pages are allocated

	// set flags for entry + object create
	memEntryCacheMode |= MAP_MEM_NAMED_CREATE;

	if (options & kIOMemoryPurgeable)
	    memEntryCacheMode |= MAP_MEM_PURGABLE;
    }
    else
    {
	memEntryCacheMode |= MAP_MEM_NAMED_REUSE;

	if (IOMapper::gSystem)
	    // assuming mapped space is 2G
	    lastIOAddr = (1UL << 31) - PAGE_SIZE;
	else
	    lastIOAddr = ptoa_64(gIOHighestAllocatedPage);

	if (physicalMask && (lastIOAddr != (lastIOAddr & physicalMask)))
	{
	    mach_vm_address_t address;
	    iomdOptions &= ~kIOMemoryTypeVirtual64;
	    iomdOptions |= kIOMemoryTypePhysical64;

	    address = IOMallocPhysical(capacity, physicalMask);
	    _buffer = (void *) address;
	    if (!_buffer)
		return false;

	    mapTask = inTask;
	    inTask = 0;
	}
	else
	{
	    vmmap = kernel_map;

	    // Buffer shouldn't auto prepare they should be prepared explicitly
	    // But it never was enforced so what are you going to do?
	    iomdOptions |= kIOMemoryAutoPrepare;

	    /* Allocate a wired-down buffer inside kernel space. */
	    if (options & kIOMemoryPhysicallyContiguous)
		_buffer = (void *) IOKernelAllocateContiguous(capacity, alignment);
	    else if (alignment > 1)
		_buffer = IOMallocAligned(capacity, alignment);
	    else
		_buffer = IOMalloc(capacity);
	    if (!_buffer)
		return false;
	}
    }

    if( (kIOMemoryTypePhysical64 != (kIOMemoryTypeMask & iomdOptions)) 
	&& (options & (kIOMemoryPageable | kIOMapCacheMask))) {
	ipc_port_t	sharedMem;
	vm_size_t	size = round_page_32(capacity);

	kr = mach_make_memory_entry(vmmap,
				    &size, (vm_offset_t)_buffer,
				    memEntryCacheMode, &sharedMem,
				    NULL );

	if( (KERN_SUCCESS == kr) && (size != round_page_32(capacity))) {
	    ipc_port_release_send( sharedMem );
	    kr = kIOReturnVMError;
	}
	if( KERN_SUCCESS != kr)
	    return( false );

	_memEntry = (void *) sharedMem;

	if( options & kIOMemoryPageable) {
#if IOALLOCDEBUG
	    debug_iomallocpageable_size += size;
#endif
	    mapTask = inTask;
	    if (NULL == inTask)
		inTask = kernel_task;
	}
	else if (options & kIOMapCacheMask)
	{
	    // Prefetch each page to put entries into the pmap
	    volatile UInt8 *	startAddr = (UInt8 *)_buffer;
	    volatile UInt8 *	endAddr   = (UInt8 *)_buffer + capacity;

	    while (startAddr < endAddr)
	    {
		*startAddr;
		startAddr += page_size;
	    }
	}
    }

    range.address = (mach_vm_address_t) _buffer;
    range.length  = capacity;

    if (!super::initWithOptions(&range, 1, 0,
				inTask, iomdOptions, /* System mapper */ 0))
	return false;

    if (physicalMask && !IOMapper::gSystem)
    {
	IOMDDMACharacteristics mdSummary;

	bzero(&mdSummary, sizeof(mdSummary));
	IOReturn rtn = dmaCommandOperation(
		kIOMDGetCharacteristics,
		&mdSummary, sizeof(mdSummary));
	if (rtn)
	    return false;

	if (mdSummary.fHighestPage)
	{
	    ppnum_t highest;
	    while (mdSummary.fHighestPage > (highest = gIOHighestAllocatedPage))
	    {
		if (OSCompareAndSwap(highest, mdSummary.fHighestPage, 
					(UInt32 *) &gIOHighestAllocatedPage))
		    break;
	    }
	    lastIOAddr = ptoa_64(mdSummary.fHighestPage);
	}
	else
	    lastIOAddr = ptoa_64(gIOLastPage);

	if (lastIOAddr != (lastIOAddr & physicalMask))
	{
	    if (kIOMemoryTypePhysical64 != (_flags & kIOMemoryTypeMask))
	    {
		// flag a retry
		_physSegCount = 1;
	    }
	    return false;
	}
    }

    if (mapTask)
    {
	if (!reserved) {
	    reserved = IONew( ExpansionData, 1 );
	    if( !reserved)
		return( false );
	}
	reserved->map = map(mapTask, 0, kIOMapAnywhere, 0, 0);
	if (!reserved->map)
	{
	    _buffer = 0;
	    return( false );
	}
	release();	    // map took a retain on this
	mach_vm_address_t buffer = reserved->map->getAddress();
	_buffer = (void *) buffer;
	if (kIOMemoryTypeVirtual64 == (kIOMemoryTypeMask & iomdOptions))
	    _ranges.v64->address = buffer;
    }

    setLength(capacity);

    return true;
}

IOBufferMemoryDescriptor * IOBufferMemoryDescriptor::inTaskWithOptions(
					    task_t       inTask,
                                            IOOptionBits options,
                                            vm_size_t    capacity,
                                            vm_offset_t  alignment)
{
    IOBufferMemoryDescriptor *me = new IOBufferMemoryDescriptor;
    
    if (me && !me->initWithOptions(options, capacity, alignment, inTask)) {
	bool retry = me->_physSegCount;
	me->release();
	me = 0;
	if (retry)
	{
	    me = new IOBufferMemoryDescriptor;
	    if (me && !me->initWithOptions(options, capacity, alignment, inTask))
	    {
		me->release();
		me = 0;
	    }
	}
    }
    return me;
}

IOBufferMemoryDescriptor * IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
					    task_t	      inTask,
                                            IOOptionBits      options,
                                            mach_vm_size_t    capacity,
                                            mach_vm_address_t physicalMask)
{
    IOBufferMemoryDescriptor *me = new IOBufferMemoryDescriptor;
    
    if (me && !me->initWithPhysicalMask(inTask, options, capacity, 1, physicalMask))
    {
	bool retry = me->_physSegCount;
	me->release();
	me = 0;
	if (retry)
	{
	    me = new IOBufferMemoryDescriptor;
	    if (me && !me->initWithPhysicalMask(inTask, options, capacity, 1, physicalMask))
	    {
		me->release();
		me = 0;
	    }
	}
    }
    return me;
}

bool IOBufferMemoryDescriptor::initWithOptions(
                               IOOptionBits options,
                               vm_size_t    capacity,
                               vm_offset_t  alignment)
{
    return( initWithOptions(options, capacity, alignment, kernel_task) );
}

IOBufferMemoryDescriptor * IOBufferMemoryDescriptor::withOptions(
                                            IOOptionBits options,
                                            vm_size_t    capacity,
                                            vm_offset_t  alignment)
{
    return(IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, options, capacity, alignment));
}


/*
 * withCapacity:
 *
 * Returns a new IOBufferMemoryDescriptor with a buffer large enough to
 * hold capacity bytes.  The descriptor's length is initially set to the capacity.
 */
IOBufferMemoryDescriptor *
IOBufferMemoryDescriptor::withCapacity(vm_size_t   inCapacity,
                                       IODirection inDirection,
                                       bool        inContiguous)
{
    return( IOBufferMemoryDescriptor::withOptions(
               inDirection | kIOMemoryUnshared
                | (inContiguous ? kIOMemoryPhysicallyContiguous : 0),
               inCapacity, inContiguous ? inCapacity : 1 ));
}

/*
 * initWithBytes:
 *
 * Initialize a new IOBufferMemoryDescriptor preloaded with bytes (copied).
 * The descriptor's length and capacity are set to the input buffer's size.
 */
bool IOBufferMemoryDescriptor::initWithBytes(const void * inBytes,
                                             vm_size_t    inLength,
                                             IODirection  inDirection,
                                             bool         inContiguous)
{
    if (!initWithOptions(
               inDirection | kIOMemoryUnshared
                | (inContiguous ? kIOMemoryPhysicallyContiguous : 0),
               inLength, inLength ))
        return false;

    // start out with no data
    setLength(0);

    if (!appendBytes(inBytes, inLength))
        return false;

    return true;
}

/*
 * withBytes:
 *
 * Returns a new IOBufferMemoryDescriptor preloaded with bytes (copied).
 * The descriptor's length and capacity are set to the input buffer's size.
 */
IOBufferMemoryDescriptor *
IOBufferMemoryDescriptor::withBytes(const void * inBytes,
                                    vm_size_t    inLength,
                                    IODirection  inDirection,
                                    bool         inContiguous)
{
    IOBufferMemoryDescriptor *me = new IOBufferMemoryDescriptor;

    if (me && !me->initWithBytes(inBytes, inLength, inDirection, inContiguous))
    {
	bool retry = me->_physSegCount;
	me->release();
	me = 0;
	if (retry)
	{
	    me = new IOBufferMemoryDescriptor;
	    if (me && !me->initWithBytes(inBytes, inLength, inDirection, inContiguous))
	    {
		me->release();
		me = 0;
	    }
	}

    }
    return me;
}

/*
 * free:
 *
 * Free resources
 */
void IOBufferMemoryDescriptor::free()
{
    // Cache all of the relevant information on the stack for use
    // after we call super::free()!
    IOOptionBits     flags     = _flags;
    IOOptionBits     options   = _options;
    vm_size_t        size      = _capacity;
    void *           buffer    = _buffer;
    IOVirtualAddress source    = _ranges.v64->address;
    IOMemoryMap *    map       = 0;
    vm_offset_t      alignment = _alignment;

    if (reserved)
    {
	map = reserved->map;
        IODelete( reserved, ExpansionData, 1 );
	if (map)
	    map->release();
    }

    /* super::free may unwire - deallocate buffer afterwards */
    super::free();

    if (options & kIOMemoryPageable)
    {
#if IOALLOCDEBUG
	debug_iomallocpageable_size -= round_page_32(size);
#endif
    }
    else if (buffer)
    {
	if (kIOMemoryTypePhysical64 == (flags & kIOMemoryTypeMask))
	    IOFreePhysical((mach_vm_address_t) source, size);
        else if (options & kIOMemoryPhysicallyContiguous)
            IOKernelFreeContiguous((mach_vm_address_t) buffer, size);
        else if (alignment > 1)
            IOFreeAligned(buffer, size);
        else
            IOFree(buffer, size);
    }
}

/*
 * getCapacity:
 *
 * Get the buffer capacity
 */
vm_size_t IOBufferMemoryDescriptor::getCapacity() const
{
    return _capacity;
}

/*
 * setLength:
 *
 * Change the buffer length of the memory descriptor.  When a new buffer
 * is created, the initial length of the buffer is set to be the same as
 * the capacity.  The length can be adjusted via setLength for a shorter
 * transfer (there is no need to create more buffer descriptors when you
 * can reuse an existing one, even for different transfer sizes).   Note
 * that the specified length must not exceed the capacity of the buffer.
 */
void IOBufferMemoryDescriptor::setLength(vm_size_t length)
{
    assert(length <= _capacity);

    _length = length;
    _ranges.v64->length = length;
}

/*
 * setDirection:
 *
 * Change the direction of the transfer.  This method allows one to redirect
 * the descriptor's transfer direction.  This eliminates the need to destroy
 * and create new buffers when different transfer directions are needed.
 */
void IOBufferMemoryDescriptor::setDirection(IODirection direction)
{
    _direction = direction;
}

/*
 * appendBytes:
 *
 * Add some data to the end of the buffer.  This method automatically
 * maintains the memory descriptor buffer length.  Note that appendBytes
 * will not copy past the end of the memory descriptor's current capacity.
 */
bool
IOBufferMemoryDescriptor::appendBytes(const void * bytes, vm_size_t withLength)
{
    vm_size_t   actualBytesToCopy = min(withLength, _capacity - _length);
    IOByteCount offset;

    assert(_length <= _capacity);

    offset = _length;
    _length += actualBytesToCopy;
    _ranges.v64->length += actualBytesToCopy;

    if (_task == kernel_task)
	bcopy(/* from */ bytes, (void *)(_ranges.v64->address + offset),
	      actualBytesToCopy);
    else
	writeBytes(offset, bytes, actualBytesToCopy);

    return true;
}

/*
 * getBytesNoCopy:
 *
 * Return the virtual address of the beginning of the buffer
 */
void * IOBufferMemoryDescriptor::getBytesNoCopy()
{
    if (kIOMemoryTypePhysical64 == (_flags & kIOMemoryTypeMask))
	return _buffer;
    else
	return (void *)_ranges.v64->address;
}


/*
 * getBytesNoCopy:
 *
 * Return the virtual address of an offset from the beginning of the buffer
 */
void *
IOBufferMemoryDescriptor::getBytesNoCopy(vm_size_t start, vm_size_t withLength)
{
    IOVirtualAddress address;
    if (kIOMemoryTypePhysical64 == (_flags & kIOMemoryTypeMask))
	address = (IOVirtualAddress) _buffer;
    else
	address = _ranges.v64->address;

   if (start < _length && (start + withLength) <= _length)
        return (void *)(address + start);
    return 0;
}

/* DEPRECATED */ void * IOBufferMemoryDescriptor::getVirtualSegment(IOByteCount offset,
/* DEPRECATED */ 							IOByteCount * lengthOfSegment)
{
    void * bytes = getBytesNoCopy(offset, 0);
    
    if (bytes && lengthOfSegment)
	*lengthOfSegment = _length - offset;

    return bytes;
}

OSMetaClassDefineReservedUsed(IOBufferMemoryDescriptor, 0);
OSMetaClassDefineReservedUsed(IOBufferMemoryDescriptor, 1);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 2);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 3);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 4);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 5);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 6);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 7);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 8);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 9);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 10);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 11);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 12);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 13);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 14);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 15);
