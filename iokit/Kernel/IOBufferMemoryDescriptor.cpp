/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#include <IOKit/assert.h>
#include <IOKit/system.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

__BEGIN_DECLS
void ipc_port_release_send(ipc_port_t port);
__END_DECLS

extern "C" vm_map_t IOPageableMapForAddress( vm_address_t address );

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
                               vm_offset_t  alignment)
{
    if (!capacity)
        return false;

    _options   	  = options;
    _capacity     = capacity;
    _physAddrs    = 0;
    _physSegCount = 0;
    _buffer	  = 0;

    if ((options & kIOMemorySharingTypeMask) && (alignment < page_size))
        alignment = page_size;

    _alignment = alignment;
    if (options & kIOMemoryPageable)
        /* Allocate some kernel address space. */
        _buffer = IOMallocPageable(capacity, alignment);
    /* Allocate a wired-down buffer inside kernel space. */
    else if (options & kIOMemoryPhysicallyContiguous)
        _buffer = IOMallocContiguous(capacity, alignment, 0);
    else if (alignment > 1)
        _buffer = IOMallocAligned(capacity, alignment);
    else
        _buffer = IOMalloc(capacity);

    if (!_buffer)
        return false;

    _singleRange.v.address = (vm_address_t) _buffer;
    _singleRange.v.length  = capacity;

    if (!super::initWithRanges(&_singleRange.v,	1,
                                (IODirection) (options & kIOMemoryDirectionMask),
                                kernel_task, true))
	return false;

    if (options & kIOMemoryPageable) {
        _flags |= kIOMemoryRequiresWire;

        kern_return_t kr;
        ipc_port_t sharedMem = (ipc_port_t) _memEntry;
        vm_size_t size = _ranges.v[0].length;

        // must create the entry before any pages are allocated
        if( 0 == sharedMem) {
            kr = mach_make_memory_entry( IOPageableMapForAddress( _ranges.v[0].address ),
                        &size, _ranges.v[0].address,
                        VM_PROT_READ | VM_PROT_WRITE, &sharedMem,
                        NULL );
            if( (KERN_SUCCESS == kr) && (size != _ranges.v[0].length)) {
                ipc_port_release_send( sharedMem );
                kr = kIOReturnVMError;
            }
            if( KERN_SUCCESS != kr)
                sharedMem = 0;
            _memEntry = (void *) sharedMem;
        }
        
    } else {
        /* Precompute virtual-to-physical page mappings. */
        vm_address_t inBuffer = (vm_address_t) _buffer;
        _physSegCount = atop(trunc_page(inBuffer + capacity - 1) -
                            trunc_page(inBuffer)) + 1;
        _physAddrs = IONew(IOPhysicalAddress, _physSegCount);
        if (!_physAddrs)
            return false;
    
        inBuffer = trunc_page(inBuffer);
        for (unsigned i = 0; i < _physSegCount; i++) {
            _physAddrs[i] = pmap_extract(get_task_pmap(kernel_task), inBuffer);
            assert(_physAddrs[i]); /* supposed to be wired */
            inBuffer += page_size;
        }
    }

    setLength(capacity);
    
    return true;
}

IOBufferMemoryDescriptor * IOBufferMemoryDescriptor::withOptions(
                                            IOOptionBits options,
                                            vm_size_t    capacity,
                                            vm_offset_t  alignment = 1)
{
    IOBufferMemoryDescriptor *me = new IOBufferMemoryDescriptor;
    
    if (me && !me->initWithOptions(options, capacity, alignment)) {
	me->release();
	me = 0;
    }
    return me;
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

    if (me && !me->initWithBytes(inBytes, inLength, inDirection, inContiguous)){
        me->release();
        me = 0;
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
    IOOptionBits options   = _options;
    vm_size_t    size	   = _capacity;
    void *       buffer	   = _buffer;
    vm_offset_t  alignment = _alignment;

    if (_physAddrs)
        IODelete(_physAddrs, IOPhysicalAddress, _physSegCount);

    /* super::free may unwire - deallocate buffer afterwards */
    super::free();

    if (buffer) {
        if (options & kIOMemoryPageable)
            IOFreePageable(buffer, size);
        else {
            if (options & kIOMemoryPhysicallyContiguous)
                IOFreeContiguous(buffer, size);
            else if (alignment > 1)
                IOFreeAligned(buffer, size);
            else
                IOFree(buffer, size);
        }
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
    _singleRange.v.length = length;
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
    vm_size_t actualBytesToCopy = min(withLength, _capacity - _length);

    assert(_length <= _capacity);
    bcopy(/* from */ bytes, (void *)(_singleRange.v.address + _length),
          actualBytesToCopy);
    _length += actualBytesToCopy;
    _singleRange.v.length += actualBytesToCopy;

    return true;
}

/*
 * getBytesNoCopy:
 *
 * Return the virtual address of the beginning of the buffer
 */
void * IOBufferMemoryDescriptor::getBytesNoCopy()
{
    return (void *)_singleRange.v.address;
}

/*
 * getBytesNoCopy:
 *
 * Return the virtual address of an offset from the beginning of the buffer
 */
void *
IOBufferMemoryDescriptor::getBytesNoCopy(vm_size_t start, vm_size_t withLength)
{
    if (start < _length && (start + withLength) <= _length)
        return (void *)(_singleRange.v.address + start);
    return 0;
}

/*
 * getPhysicalSegment:
 *
 * Get the physical address of the buffer, relative to the current position.
 * If the current position is at the end of the buffer, a zero is returned.
 */
IOPhysicalAddress
IOBufferMemoryDescriptor::getPhysicalSegment(IOByteCount offset,
					IOByteCount * lengthOfSegment)
{
    IOPhysicalAddress physAddr;

    if( offset != _position)
	setPosition( offset );

    assert(_position <= _length);

    /* Fail gracefully if the position is at (or past) the end-of-buffer. */
    if (_position >= _length) {
        *lengthOfSegment = 0;
        return 0;
    }

    if (_options & kIOMemoryPageable) {
        physAddr = super::getPhysicalSegment(offset, lengthOfSegment);

    } else {
        /* Compute the largest contiguous physical length possible. */
        vm_address_t actualPos  = _singleRange.v.address + _position;
        vm_address_t actualPage = trunc_page(actualPos);
        unsigned     physInd    = atop(actualPage-trunc_page(_singleRange.v.address));
    
        vm_size_t physicalLength = actualPage + page_size - actualPos;
        for (unsigned index = physInd + 1; index < _physSegCount &&
            _physAddrs[index] == _physAddrs[index-1] + page_size; index++) {
            physicalLength += page_size;
        }
    
        /* Clip contiguous physical length at the end-of-buffer. */
        if (physicalLength > _length - _position)
            physicalLength = _length - _position;
    
        *lengthOfSegment = physicalLength;
        physAddr = _physAddrs[physInd] + (actualPos - actualPage);
    }

    return physAddr;
}

OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 0);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 1);
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
