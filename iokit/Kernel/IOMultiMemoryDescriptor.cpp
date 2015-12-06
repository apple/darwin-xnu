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
#include <IOKit/IOMultiMemoryDescriptor.h>

#define super IOMemoryDescriptor
OSDefineMetaClassAndStructors(IOMultiMemoryDescriptor, IOMemoryDescriptor)

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

bool IOMultiMemoryDescriptor::initWithDescriptors(
                                  IOMemoryDescriptor ** descriptors,
                                  UInt32                withCount,
                                  IODirection           withDirection,
                                  bool                  asReference )
{
    unsigned index;
    IOOptionBits copyFlags;
    //
    // Initialize an IOMultiMemoryDescriptor. The "buffer" is made up of several
    // memory descriptors, that are to be chained end-to-end to make up a single
    // memory descriptor.
    //
    // Passing the ranges as a reference will avoid an extra allocation.
    //

    assert(descriptors);

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
    _flags                  = withDirection;
#ifndef __LP64__
    _direction              = (IODirection) (_flags & kIOMemoryDirectionMask);
#endif /* !__LP64__ */
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

    for ( index = 0; index < withCount; index++ )
    {
        descriptors[index]->retain();
        _length += descriptors[index]->getLength();
        if ( _tag == 0 )  _tag = descriptors[index]->getTag();
        assert(descriptors[index]->getDirection() ==
	       (withDirection & kIOMemoryDirectionMask));
    }

    enum { kCopyFlags = kIOMemoryBufferPageable };
    copyFlags = 0;
    for ( index = 0; index < withCount; index++ )
    {
	if (!index)  copyFlags =  (kCopyFlags & descriptors[index]->_flags);
	else if     (copyFlags != (kCopyFlags & descriptors[index]->_flags)) break;
    }
    if (index < withCount) return (false);
    _flags |= copyFlags;

    return true;
}

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
        forDirection = getDirection();
    }

    for ( index = 0; index < _descriptorsCount; index++ ) 
    {
        status = _descriptors[index]->prepare(forDirection);
        if ( status != kIOReturnSuccess )  break;
    }

    if ( status != kIOReturnSuccess )
    {
        for ( unsigned indexUndo = 0; indexUndo < index; indexUndo++ )
        {
            statusUndo = _descriptors[indexUndo]->complete(forDirection);
            assert(statusUndo == kIOReturnSuccess);
        }
    }

    return status;
}

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
        forDirection = getDirection();
    }

    for ( unsigned index = 0; index < _descriptorsCount; index++ ) 
    {
        status = _descriptors[index]->complete(forDirection);
        if ( status != kIOReturnSuccess )  statusFinal = status;
        assert(status == kIOReturnSuccess);
    }

    return statusFinal;
}

addr64_t IOMultiMemoryDescriptor::getPhysicalSegment(IOByteCount   offset,
                                                     IOByteCount * length,
                                                     IOOptionBits  options)
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
            return _descriptors[index]->getPhysicalSegment(offset, length, options);
        }
        offset -= _descriptors[index]->getLength();
    }

    if ( length )  *length = 0;

    return 0;
}

#include "IOKitKernelInternal.h"

IOReturn IOMultiMemoryDescriptor::doMap(vm_map_t           __addressMap,
                                        IOVirtualAddress *  __address,
                                        IOOptionBits       options,
                                        IOByteCount        __offset,
                                        IOByteCount        __length)
{
    IOMemoryMap *     mapping = (IOMemoryMap *) *__address;
    vm_map_t          map     = mapping->fAddressMap;
    mach_vm_size_t    offset  = mapping->fOffset;
    mach_vm_size_t    length  = mapping->fLength;
    mach_vm_address_t address = mapping->fAddress;

    kern_return_t     err;
    IOOptionBits      subOptions;
    mach_vm_size_t    mapOffset;
    mach_vm_size_t    bytesRemaining, chunk;
    mach_vm_address_t nextAddress;
    IOMemoryDescriptorMapAllocRef ref;
    vm_prot_t                     prot;

    do
    {
        prot = VM_PROT_READ;
        if (!(kIOMapReadOnly & options)) prot |= VM_PROT_WRITE;
        ref.map     = map;
	ref.tag     = IOMemoryTag(map);
        ref.options = options;
        ref.size    = length;
        ref.prot    = prot;
        if (options & kIOMapAnywhere)
            // vm_map looks for addresses above here, even when VM_FLAGS_ANYWHERE
            ref.mapped = 0;
        else
            ref.mapped = mapping->fAddress;

        if ((ref.map == kernel_map) && (kIOMemoryBufferPageable & _flags))
            err = IOIteratePageableMaps(ref.size, &IOMemoryDescriptorMapAlloc, &ref);
        else
            err = IOMemoryDescriptorMapAlloc(ref.map, &ref);

        if (KERN_SUCCESS != err) break;

        address = ref.mapped;
        mapping->fAddress = address;

        mapOffset = offset;
        bytesRemaining = length;
        nextAddress = address;
        assert(mapOffset <= _length);
        subOptions = (options & ~kIOMapAnywhere) | kIOMapOverwrite;

        for (unsigned index = 0; bytesRemaining && (index < _descriptorsCount); index++) 
        {
            chunk = _descriptors[index]->getLength();
            if (mapOffset >= chunk)
            {
                mapOffset -= chunk;
                continue;
            }
            chunk -= mapOffset;
            if (chunk > bytesRemaining) chunk = bytesRemaining;
            IOMemoryMap * subMap;
            subMap = _descriptors[index]->createMappingInTask(mapping->fAddressTask, nextAddress, subOptions, mapOffset, chunk );
            if (!subMap) break;
            subMap->release();          // kIOMapOverwrite means it will not deallocate

            bytesRemaining -= chunk;
            nextAddress += chunk;
            mapOffset = 0;
        }
        if (bytesRemaining) err = kIOReturnUnderrun;
    }
    while (false);

    if (kIOReturnSuccess == err)
    {
#if IOTRACKING
        IOTrackingAdd(gIOMapTracking, &mapping->fTracking, length, false);
#endif
    }
    else
    {
        mapping->release();
        mapping = 0;
    }

    return (err);
}

IOReturn IOMultiMemoryDescriptor::setPurgeable( IOOptionBits newState,
                                                IOOptionBits * oldState )
{
    IOReturn     err;
    IOOptionBits totalState, state;

    totalState = kIOMemoryPurgeableNonVolatile;
    for (unsigned index = 0; index < _descriptorsCount; index++) 
    {
        err = _descriptors[index]->setPurgeable(newState, &state);
        if (kIOReturnSuccess != err) break;

        if (kIOMemoryPurgeableEmpty == state)              totalState = kIOMemoryPurgeableEmpty;
        else if (kIOMemoryPurgeableEmpty == totalState)    continue;
        else if (kIOMemoryPurgeableVolatile == totalState) continue;
        else if (kIOMemoryPurgeableVolatile == state)      totalState = kIOMemoryPurgeableVolatile;
        else totalState = kIOMemoryPurgeableNonVolatile;
    }
    if (oldState) *oldState = totalState;

    return (err);
}

IOReturn IOMultiMemoryDescriptor::getPageCounts(IOByteCount * pResidentPageCount,
                                     	        IOByteCount * pDirtyPageCount)
{
    IOReturn    err;
    IOByteCount totalResidentPageCount, totalDirtyPageCount;
    IOByteCount residentPageCount, dirtyPageCount;

    err = kIOReturnSuccess;
    totalResidentPageCount = totalDirtyPageCount = 0;
    for (unsigned index = 0; index < _descriptorsCount; index++) 
    {
        err = _descriptors[index]->getPageCounts(&residentPageCount, &dirtyPageCount);
        if (kIOReturnSuccess != err) break;
        totalResidentPageCount += residentPageCount;
        totalDirtyPageCount    += dirtyPageCount;
    }

    if (pResidentPageCount) *pResidentPageCount = totalResidentPageCount;
    if (pDirtyPageCount)    *pDirtyPageCount = totalDirtyPageCount;

    return (err);
}
