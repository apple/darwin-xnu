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

#include <IOKit/IOLib.h>
#include <IOKit/IOInterleavedMemoryDescriptor.h>

#define super IOMemoryDescriptor
OSDefineMetaClassAndStructors(IOInterleavedMemoryDescriptor, IOMemoryDescriptor)

IOInterleavedMemoryDescriptor * IOInterleavedMemoryDescriptor::withCapacity(
                                  IOByteCount           capacity,
                                  IODirection           direction )
{
    //
    // Create a new IOInterleavedMemoryDescriptor.  The "buffer" will be made up
    // of several memory descriptors, that are to be chained end-to-end to make up
    // a single memory descriptor.
    //

    IOInterleavedMemoryDescriptor * me = new IOInterleavedMemoryDescriptor;

    if ( me && !me->initWithCapacity(
                                  /* capacity  */ capacity,
                                  /* direction */ direction ))
    {
	    me->release();
	    me = 0;
    }

    return me;
}

bool IOInterleavedMemoryDescriptor::initWithCapacity(
                                  IOByteCount           capacity,
                                  IODirection           direction )
{
    //
    // Initialize an IOInterleavedMemoryDescriptor. The "buffer" will be made up
    // of several memory descriptors, that are to be chained end-to-end to make up
    // a single memory descriptor.
    //

    assert(capacity);

    // Ask our superclass' opinion.
    if ( super::init() == false )  return false;
    
    // Initialize our minimal state.

    _flags                  = direction;
#ifndef __LP64__
    _direction              = (IODirection) (_flags & kIOMemoryDirectionMask);
#endif /* !__LP64__ */
    _length                 = 0;
    _mappings               = 0;
    _tag                    = 0;
    _descriptorCount        = 0;
    _descriptors            = IONew(IOMemoryDescriptor *, capacity);
    _descriptorOffsets      = IONew(IOByteCount, capacity);
    _descriptorLengths      = IONew(IOByteCount, capacity);

    if ( (_descriptors == 0) || (_descriptorOffsets == 0) || (_descriptorLengths == 0) )
        return false;

    _descriptorCapacity     = capacity;

    return true;
}

void IOInterleavedMemoryDescriptor::clearMemoryDescriptors( IODirection direction )
{
    UInt32 index;

    for ( index = 0; index < _descriptorCount; index++ )
    {
        if ( _descriptorPrepared )
	    _descriptors[index]->complete(getDirection());

	_descriptors[index]->release();
	_descriptors[index] = 0;

	_descriptorOffsets[index] = 0;
	_descriptorLengths[index] = 0;
    }

    if ( direction != kIODirectionNone )
    {
        _flags = (_flags & ~kIOMemoryDirectionMask) | direction;
#ifndef __LP64__
        _direction = (IODirection) (_flags & kIOMemoryDirectionMask);
#endif /* !__LP64__ */
    }

    _descriptorCount = 0;
    _length = 0;
    _mappings = 0;
    _tag = 0;

};

bool IOInterleavedMemoryDescriptor::setMemoryDescriptor(
                                             IOMemoryDescriptor * descriptor,
					     IOByteCount offset,
					     IOByteCount length )
{
    if ( _descriptorPrepared || (_descriptorCount == _descriptorCapacity) )
        return false;

    if ( (offset + length) > descriptor->getLength() )
        return false;

//    if ( descriptor->getDirection() != getDirection() )
//        return false;

    descriptor->retain();
    _descriptors[_descriptorCount] = descriptor;
    _descriptorOffsets[_descriptorCount] = offset;
    _descriptorLengths[_descriptorCount] = length;

    _descriptorCount++;

    _length += length;

    return true;
}

void IOInterleavedMemoryDescriptor::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if ( _descriptors )
    {
        for ( unsigned index = 0; index < _descriptorCount; index++ ) 
            _descriptors[index]->release();

        if ( _descriptors != 0 )
            IODelete(_descriptors, IOMemoryDescriptor *, _descriptorCapacity);

        if ( _descriptorOffsets != 0 )
            IODelete(_descriptorOffsets, IOMemoryDescriptor *, _descriptorCapacity);

        if ( _descriptorLengths != 0 )
            IODelete(_descriptorLengths, IOMemoryDescriptor *, _descriptorCapacity);
    }

    super::free();
}

IOReturn IOInterleavedMemoryDescriptor::prepare(IODirection forDirection)
{
    //
    // Prepare the memory for an I/O transfer.
    //
    // This involves paging in the memory and wiring it down for the duration
    // of the transfer.  The complete() method finishes the processing of the
    // memory after the I/O transfer finishes.
    //

    unsigned index;
    IOReturn status = kIOReturnSuccess;
    IOReturn statusUndo;

    if ( forDirection == kIODirectionNone )
    {
        forDirection = getDirection();
    }

    for ( index = 0; index < _descriptorCount; index++ ) 
    {
        status = _descriptors[index]->prepare(forDirection);
        if ( status != kIOReturnSuccess )  break;
    }

    if ( status != kIOReturnSuccess )
    {
        for ( unsigned indexUndo = 0; indexUndo < index; indexUndo++ )
        {
            statusUndo = _descriptors[index]->complete(forDirection);
            assert(statusUndo == kIOReturnSuccess);
        }
    }

    if ( status == kIOReturnSuccess ) _descriptorPrepared = true;

    return status;
}

IOReturn IOInterleavedMemoryDescriptor::complete(IODirection forDirection)
{
    //
    // Complete processing of the memory after an I/O transfer finishes.
    //
    // This method shouldn't be called unless a prepare() was previously issued;
    // the prepare() and complete() must occur in pairs, before and after an I/O
    // transfer.
    //

    IOReturn status;
    IOReturn statusFinal = kIOReturnSuccess;

    if ( forDirection == kIODirectionNone )
    {
        forDirection = getDirection();
    }

    for ( unsigned index = 0; index < _descriptorCount; index++ ) 
    {
        status = _descriptors[index]->complete(forDirection);
        if ( status != kIOReturnSuccess )  statusFinal = status;
        assert(status == kIOReturnSuccess);
    }

    _descriptorPrepared = false;

    return statusFinal;
}

addr64_t IOInterleavedMemoryDescriptor::getPhysicalSegment( 
                                                       IOByteCount   offset,
                                                       IOByteCount * length,
                                                       IOOptionBits  options )
{
    //
    // This method returns the physical address of the byte at the given offset
    // into the memory,  and optionally the length of the physically contiguous
    // segment from that offset.
    //

    addr64_t pa;

    assert(offset <= _length);

    for ( unsigned index = 0; index < _descriptorCount; index++ ) 
    {
        if ( offset < _descriptorLengths[index] )
        {
            pa = _descriptors[index]->getPhysicalSegment(_descriptorOffsets[index] + offset, length, options);
	    if ((_descriptorLengths[index] - offset) < *length) *length = _descriptorLengths[index] - offset;
            return pa;
        }
        offset -= _descriptorLengths[index];
    }

    if ( length )  *length = 0;

    return 0;
}
