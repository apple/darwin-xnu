/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#ifndef _IOMULTIMEMORYDESCRIPTOR_H
#define _IOMULTIMEMORYDESCRIPTOR_H

#include <IOKit/IOMemoryDescriptor.h>

/*! @class IOMultiMemoryDescriptor : public IOMemoryDescriptor
    @abstract The IOMultiMemoryDescriptor object describes a memory area made up of several other IOMemoryDescriptors.
    @discussion The IOMultiMemoryDescriptor object represents multiple ranges of memory, specified as an ordered list of IOMemoryDescriptors.  The descriptors are chained end-to-end to make up a single contiguous buffer. */

class IOMultiMemoryDescriptor : public IOMemoryDescriptor
{
    OSDeclareDefaultStructors(IOMultiMemoryDescriptor);

protected:

    IOMemoryDescriptor ** _descriptors;
    UInt32                _descriptorsCount;
    bool                  _descriptorsIsAllocated;

    virtual void free();

    /*
     * These methods are not supported under this subclass.
     */

    virtual bool initWithAddress( void *      address,       /* not supported */
                                  IOByteCount withLength,
                                  IODirection withDirection );

    virtual bool initWithAddress( vm_address_t address,      /* not supported */
                                  IOByteCount  withLength,
                                  IODirection  withDirection,
                                  task_t       withTask );

    virtual bool initWithPhysicalAddress( 
                                  IOPhysicalAddress address, /* not supported */
                                  IOByteCount       withLength,
                                  IODirection       withDirection );

    virtual bool initWithPhysicalRanges( 
                                  IOPhysicalRange * ranges,  /* not supported */
                                  UInt32            withCount,
                                  IODirection       withDirection,
                                  bool              asReference = false );

    virtual bool initWithRanges(  IOVirtualRange * ranges,   /* not supported */
                                  UInt32           withCount,
                                  IODirection      withDirection,
                                  task_t           withTask,
                                  bool             asReference = false );

    virtual void * getVirtualSegment( IOByteCount   offset,  /* not supported */
                                      IOByteCount * length );

    IOMemoryDescriptor::withAddress;                         /* not supported */
    IOMemoryDescriptor::withPhysicalAddress;                 /* not supported */
    IOMemoryDescriptor::withPhysicalRanges;                  /* not supported */
    IOMemoryDescriptor::withRanges;                          /* not supported */
    IOMemoryDescriptor::withSubRange;                        /* not supported */

public:

/*! @function withDescriptors
    @abstract Create an IOMultiMemoryDescriptor to describe a memory area made up of several other IOMemoryDescriptors.
    @discussion This method creates and initializes an IOMultiMemoryDescriptor for memory consisting of a number of other IOMemoryDescriptors, chained end-to-end (in the order they appear in the array) to represent a single contiguous memory buffer.  Passing the descriptor array as a reference will avoid an extra allocation.
    @param descriptors An array of IOMemoryDescriptors which make up the memory to be described.
    @param withCount The object count for the descriptors array.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param asReference If false, the IOMultiMemoryDescriptor object will make a copy of the descriptors array, otherwise, the array will be used in situ, avoiding an extra allocation.
    @result The created IOMultiMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMultiMemoryDescriptor * withDescriptors(
                                  IOMemoryDescriptor ** descriptors,
                                  UInt32                withCount,
                                  IODirection           withDirection,
                                  bool                  asReference = false );

/*! @function withDescriptors
    @abstract Initialize an IOMultiMemoryDescriptor to describe a memory area made up of several other IOMemoryDescriptors.
    @discussion This method initializes an IOMultiMemoryDescriptor for memory consisting of a number of other IOMemoryDescriptors, chained end-to-end (in the order they appear in the array) to represent a single contiguous memory buffer.  Passing the descriptor array as a reference will avoid an extra allocation.
    @param descriptors An array of IOMemoryDescriptors which make up the memory to be described.
    @param withCount The object count for the descriptors array.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param asReference If false, the IOMultiMemoryDescriptor object will make a copy of the descriptors array, otherwise, the array will be used in situ, avoiding an extra allocation.
    @result The created IOMultiMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    virtual bool initWithDescriptors(
                                  IOMemoryDescriptor ** descriptors,
                                  UInt32                withCount,
                                  IODirection           withDirection,
                                  bool                  asReference = false );

/*! @function getPhysicalAddress
    @abstract Return the physical address of the first byte in the memory.
    @discussion This method returns the physical address of the  first byte in the memory. It is most useful on memory known to be physically contiguous.
    @result A physical address. */

    virtual IOPhysicalAddress getPhysicalSegment( IOByteCount   offset,
                                                  IOByteCount * length );

/*! @function prepare
    @abstract Prepare the memory for an I/O transfer.
    @discussion This involves paging in the memory, if necessary, and wiring it down for the duration of the transfer.  The complete() method completes the processing of the memory after the I/O transfer finishes.  This method needn't called for non-pageable memory.
    @param forDirection The direction of the I/O just completed, or kIODirectionNone for the direction specified by the memory descriptor.
    @result An IOReturn code. */

    virtual IOReturn prepare(IODirection forDirection = kIODirectionNone);

/*! @function complete
    @abstract Complete processing of the memory after an I/O transfer finishes.
    @discussion This method should not be called unless a prepare was previously issued; the prepare() and complete() must occur in pairs, before and after an I/O transfer involving pageable memory.
    @param forDirection The direction of the I/O just completed, or kIODirectionNone for the direction specified by the memory descriptor.
    @result An IOReturn code. */

    virtual IOReturn complete(IODirection forDirection = kIODirectionNone);

/*! @function readBytes
    @abstract Copy data from the memory descriptor's buffer to the specified buffer.
    @discussion This method copies data from the memory descriptor's memory at the given offset, to the caller's buffer.
    @param offset A byte offset into the memory descriptor's memory.
    @param bytes The caller supplied buffer to copy the data to.
    @param withLength The length of the data to copy.
    @result The number of bytes copied, zero will be returned if the specified offset is beyond the length of the descriptor. */

    virtual IOByteCount readBytes( IOByteCount offset,
                                   void *      bytes,
                                   IOByteCount withLength );

/*! @function writeBytes
    @abstract Copy data to the memory descriptor's buffer from the specified buffer.
    @discussion This method copies data to the memory descriptor's memory at the given offset, from the caller's buffer.
    @param offset A byte offset into the memory descriptor's memory.
    @param bytes The caller supplied buffer to copy the data from.
    @param withLength The length of the data to copy.
    @result The number of bytes copied, zero will be returned if the specified offset is beyond the length of the descriptor. */

    virtual IOByteCount writeBytes( IOByteCount  offset,
                                    const void * bytes,
                                    IOByteCount  withLength );

    virtual IOPhysicalAddress getSourceSegment(IOByteCount offset,
                                               IOByteCount * length);
};

#endif /* !_IOMULTIMEMORYDESCRIPTOR_H */
