/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <IOKit/IOLib.h>
#include <IOKit/IOMultiMemoryDescriptor.h>

#define super IOMemoryDescriptor
OSDefineMetaClassAndStructors(IOMultiMemoryDescriptor, IOMemoryDescriptor)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMultiMemoryDescriptor::initWithAddress(
                                  void *      /* address       */ ,
                                  IOByteCount /* withLength    */ ,
                                  IODirection /* withDirection */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMultiMemoryDescriptor::initWithAddress(
                                  vm_address_t /* address       */ ,
                                  IOByteCount  /* withLength    */ ,
                                  IODirection  /* withDirection */ ,
                                  task_t       /* withTask      */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMultiMemoryDescriptor::initWithPhysicalAddress(
                                  IOPhysicalAddress /* address       */ ,
                                  IOByteCount       /* withLength    */ ,
                                  IODirection       /* withDirection */ )
{
    return false;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMultiMemoryDescriptor::initWithPhysicalRanges(
                                  IOPhysicalRange * /* ranges        */ ,
                                  UInt32            /* withCount     */ ,
                                  IODirection       /* withDirection */ ,
                                  bool              /* asReference   */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMultiMemoryDescriptor::initWithRanges(
                                  IOVirtualRange * /* ranges        */ ,
                                  UInt32           /* withCount     */ ,
                                  IODirection      /* withDirection */ ,
                                  task_t           /* withTask      */ ,
                                  bool             /* asReference   */ )
{
    return false;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOMultiMemoryDescriptor * IOMultiMemoryDescriptor::withDescriptors(
                                  IOMemoryDescriptor ** descriptors,
                                  UInt32                withCount,
                                  IODirection           withDirection,
                                  bool                  asReference )
{
    //
    // Create a new IOMultiMemoryDescriptor.  The "buffer" is made up of several
    // memory descriptors, that are to be chained end-to-end to make up a single
    // memory descriptor.
    //
    // Passing the ranges as a reference will avoid an extra allocation.
    //

    IOMultiMemoryDescriptor * me = new IOMultiMemoryDescriptor;
    
    if ( me && me->initWithDescriptors(
                                  /* descriptors   */ descriptors,
                                  /* withCount     */ withCount,
                                  /* withDirection */ withDirection,
                                  /* asReference   */ asReference ) == false )
    {
	    me->release();
	    me = 0;
    }

    return me;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool IOMultiMemoryDescriptor::initWithDescriptors(
                                  IOMemoryDescriptor ** descriptors,
                                  UInt32                withCount,
                                  IODirection           withDirection,
                                  bool                  asReference )
{
    //
    // Initialize an IOMultiMemoryDescriptor. The "buffer" is made up of several
    // memory descriptors, that are to be chained end-to-end to make up a single
    // memory descriptor.
    //
    // Passing the ranges as a reference will avoid an extra allocation.
    //

    assert(descriptors);
    assert(withCount);

    // Release existing descriptors, if any
    if ( _descriptors )
    {
        for ( unsigned index = 0; index < _descriptorsCount; index++ ) 
            _descriptors[index]->release();

        if ( _descriptorsIsAllocated )
            IODelete(_descriptors, IOMemoryDescriptor *, _descriptorsCount);
    } else {
        // Ask our superclass' opinion.
        if ( super::init() == false )  return false;
    }
    
    // Initialize our minimal state.

    _descriptors            = 0;
    _descriptorsCount       = withCount;
    _descriptorsIsAllocated = asReference ? false : true;
    _direction              = withDirection;
    _length                 = 0;
    _mappings               = 0;
    _tag                    = 0;

    if ( asReference )
    {
        _descriptors = descriptors;
    }
    else
    {
        _descriptors = IONew(IOMemoryDescriptor *, withCount);
        if ( _descriptors == 0 )  return false;

        bcopy( /* from  */ descriptors,
               /* to    */ _descriptors,
               /* bytes */ withCount * sizeof(IOMemoryDescriptor *) );
    }

    for ( unsigned index = 0; index < withCount; index++ ) 
    {
        descriptors[index]->retain();
        _length += descriptors[index]->getLength();
        if ( _tag == 0 )  _tag = descriptors[index]->getTag();
        assert(descriptors[index]->getDirection() == withDirection);
    }

    return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void IOMultiMemoryDescriptor::free()
{
    //
    // Free all of this object's outstanding resources.
    //

    if ( _descriptors )
    {
        for ( unsigned index = 0; index < _descriptorsCount; index++ ) 
            _descriptors[index]->release();

        if ( _descriptorsIsAllocated )
            IODelete(_descriptors, IOMemoryDescriptor *, _descriptorsCount);
    }

    super::free();
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOMultiMemoryDescriptor::prepare(IODirection forDirection)
{
    //
    // Prepare the memory for an I/O transfer.
    //
    // This involves paging in the memory and wiring it down for the duration
    // of the transfer.  The complete() method finishes the processing of the
    // memory after the I/O transfer finishes.
    //

    unsigned index;
    IOReturn status = kIOReturnInternalError;
    IOReturn statusUndo;

    if ( forDirection == kIODirectionNone )
    {
        forDirection = _direction;
    }

    for ( index = 0; index < _descriptorsCount; index++ ) 
    {
        status = _descriptors[index]->prepare(forDirection);
        if ( status != kIOReturnSuccess )  break;
    }

    if ( status != kIOReturnSuccess )
    {
        for ( unsigned indexUndo = 0; indexUndo <= index; indexUndo++ )
        {
            statusUndo = _descriptors[index]->complete(forDirection);
            assert(statusUndo == kIOReturnSuccess);
        }
    }

    return status;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOReturn IOMultiMemoryDescriptor::complete(IODirection forDirection)
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
        forDirection = _direction;
    }

    for ( unsigned index = 0; index < _descriptorsCount; index++ ) 
    {
        status = _descriptors[index]->complete(forDirection);
        if ( status != kIOReturnSuccess )  statusFinal = status;
        assert(status == kIOReturnSuccess);
    }

    return statusFinal;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOPhysicalAddress IOMultiMemoryDescriptor::getPhysicalSegment(
                                                       IOByteCount   offset,
                                                       IOByteCount * length )
{
    //
    // This method returns the physical address of the byte at the given offset
    // into the memory,  and optionally the length of the physically contiguous
    // segment from that offset.
    //

    assert(offset <= _length);

    for ( unsigned index = 0; index < _descriptorsCount; index++ ) 
    {
        if ( offset < _descriptors[index]->getLength() )
        {
            return _descriptors[index]->getPhysicalSegment(offset, length);
        }
        offset -= _descriptors[index]->getLength();
    }

    if ( length )  *length = 0;

    return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOPhysicalAddress IOMultiMemoryDescriptor::getSourceSegment(
                                                       IOByteCount   offset,
                                                       IOByteCount * length )
{
    //
    // This method returns the physical address of the byte at the given offset
    // into the memory,  and optionally the length of the physically contiguous
    // segment from that offset.
    //

    assert(offset <= _length);

    for ( unsigned index = 0; index < _descriptorsCount; index++ ) 
    {
        if ( offset < _descriptors[index]->getLength() )
        {
            return _descriptors[index]->getSourceSegment(offset, length);
        }
        offset -= _descriptors[index]->getLength();
    }

    if ( length )  *length = 0;

    return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void * IOMultiMemoryDescriptor::getVirtualSegment( IOByteCount   /* offset */ ,
                                                   IOByteCount * /* length */ )
{
    return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOByteCount IOMultiMemoryDescriptor::readBytes( IOByteCount offset,
                                                void *      bytes,
                                                IOByteCount withLength )
{
    //
    // Copies data from the memory descriptor's buffer at the given offset, to
    // the specified buffer.  Returns the number of bytes copied.
    //

    IOByteCount bytesCopied = 0;
    unsigned    index;

    for ( index = 0; index < _descriptorsCount; index++ ) 
    {
        if ( offset < _descriptors[index]->getLength() )  break;
        offset -= _descriptors[index]->getLength();
    }

    for ( ; index < _descriptorsCount && withLength; index++)
    {
        IOByteCount copy   = min(_descriptors[index]->getLength(), withLength);
        IOByteCount copied = _descriptors[index]->readBytes(offset,bytes,copy);

        bytesCopied += copied;
        if ( copied != copy )  break;

        bytes = ((UInt8 *) bytes) + copied;
        withLength -= copied;
        offset = 0;
    }

    return bytesCopied;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

IOByteCount IOMultiMemoryDescriptor::writeBytes( IOByteCount  offset,
                                                 const void * bytes,
                                                 IOByteCount  withLength )
{
    //
    // Copies data to the memory descriptor's buffer at the given offset, from
    // the specified buffer.  Returns the number of bytes copied.
    //

    IOByteCount bytesCopied = 0;
    unsigned    index;

    for ( index = 0; index < _descriptorsCount; index++ ) 
    {
        if ( offset < _descriptors[index]->getLength() )  break;
        offset -= _descriptors[index]->getLength();
    }

    for ( ; index < _descriptorsCount && withLength; index++)
    {
        IOByteCount copy   = min(_descriptors[index]->getLength(), withLength);
        IOByteCount copied = _descriptors[index]->writeBytes(offset,bytes,copy);

        bytesCopied += copied;
        if ( copied != copy )  break;

        bytes = ((UInt8 *) bytes) + copied;
        withLength -= copied;
        offset = 0;
    }

    return bytesCopied;
}
