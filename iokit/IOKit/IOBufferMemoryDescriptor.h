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
#ifndef _IOBUFFERMEMORYDESCRIPTOR_H
#define _IOBUFFERMEMORYDESCRIPTOR_H

#include <IOKit/IOMemoryDescriptor.h>

enum {
    kIOMemoryDirectionMask		= 0x0000000f,
    kIOMemoryPhysicallyContiguous	= 0x00000010,
    kIOMemoryPageable	      		= 0x00000020,
    kIOMemorySharingTypeMask		= 0x000f0000,
    kIOMemoryUnshared			= 0x00000000,
    kIOMemoryKernelUserShared		= 0x00010000,
};


class IOBufferMemoryDescriptor : public IOGeneralMemoryDescriptor
{
    OSDeclareDefaultStructors(IOBufferMemoryDescriptor);

protected:
/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of this class in the future.
    */    
    struct ExpansionData { };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

protected:
    void *               _buffer;
    vm_size_t            _capacity;
    vm_offset_t		 _alignment;
    IOOptionBits	 _options;
    IOPhysicalAddress *  _physAddrs;
    unsigned             _physSegCount;

private:
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 0);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 1);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 2);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 3);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 4);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 5);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 6);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 7);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 8);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 9);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 10);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 11);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 12);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 13);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 14);
    OSMetaClassDeclareReservedUnused(IOBufferMemoryDescriptor, 15);

protected:
    virtual void free();

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

    IOGeneralMemoryDescriptor::withAddress;                  /* not supported */
    IOGeneralMemoryDescriptor::withPhysicalAddress;          /* not supported */
    IOGeneralMemoryDescriptor::withPhysicalRanges;           /* not supported */
    IOGeneralMemoryDescriptor::withRanges;                   /* not supported */
    IOGeneralMemoryDescriptor::withSubRange;                 /* not supported */

public:

    /*
     * withOptions:
     *
     * Returns a new IOBufferMemoryDescriptor with a buffer large enough to
     * hold capacity bytes.  The descriptor's length is initially set to the
     * capacity.
     */
    virtual bool initWithOptions(   IOOptionBits options,
                                    vm_size_t    capacity,
                                    vm_offset_t  alignment);

    static IOBufferMemoryDescriptor * withOptions(  IOOptionBits options,
                                                    vm_size_t    capacity,
                                                    vm_offset_t  alignment = 1);

    /*
     * withCapacity:
     *
     * Returns a new IOBufferMemoryDescriptor with a buffer large enough to
     * hold capacity bytes.  The descriptor's length is initially set to the
     * capacity.
     */
    static IOBufferMemoryDescriptor * withCapacity(
                                     vm_size_t    capacity,
                                     IODirection  withDirection,
                                     bool         withContiguousMemory = false);
    /*
     * initWithBytes:
     *
     * Initialize a new IOBufferMemoryDescriptor preloaded with bytes (copied).
     * The descriptor's length and capacity are set to the input buffer's size.
     */
    virtual bool initWithBytes(const void * bytes,
                               vm_size_t    withLength,
                               IODirection  withDirection,
                               bool         withContiguousMemory = false);

    /*
     * withBytes:
     *
     * Returns a new IOBufferMemoryDescriptor preloaded with bytes (copied).
     * The descriptor's length and capacity are set to the input buffer's size.
     */
    static IOBufferMemoryDescriptor * withBytes(
                                     const void * bytes,
                                     vm_size_t    withLength,
                                     IODirection  withDirection,
                                     bool         withContiguousMemory = false);

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
    virtual void setLength(vm_size_t length);

    /*
     * setDirection:
     *
     * Change the direction of the transfer.  This method allows one to redirect
     * the descriptor's transfer direction.  This eliminates the need to destroy
     * and create new buffers when different transfer directions are needed.
     */
    virtual void setDirection(IODirection direction);

    /*
     * getCapacity:
     *
     * Get the buffer capacity
     */
    virtual vm_size_t getCapacity() const;

    /*
     * getBytesNoCopy:
     *
     * Return the virtual address of the beginning of the buffer
     */
    virtual void *getBytesNoCopy();

    /*
     * getBytesNoCopy:
     *
     * Return the virtual address of an offset from the beginning of the buffer
     */
    virtual void *getBytesNoCopy(vm_size_t start, vm_size_t withLength);

    /*
     * appendBytes:
     *
     * Add some data to the end of the buffer.  This method automatically
     * maintains the memory descriptor buffer length.  Note that appendBytes
     * will not copy past the end of the memory descriptor's current capacity.
     */
    virtual bool appendBytes(const void *bytes, vm_size_t withLength);

    /*
     * getPhysicalSegment:
     *
     * Get the physical address of the buffer, relative to the current position.
     * If the current position is at the end of the buffer, a zero is returned.
     */
    virtual IOPhysicalAddress getPhysicalSegment(IOByteCount offset,
						 IOByteCount * length);    
};

#endif /* !_IOBUFFERMEMORYDESCRIPTOR_H */
