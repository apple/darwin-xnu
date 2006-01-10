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
#ifndef _IOBUFFERMEMORYDESCRIPTOR_H
#define _IOBUFFERMEMORYDESCRIPTOR_H

#include <IOKit/IOMemoryDescriptor.h>

enum {
    kIOMemoryPhysicallyContiguous	= 0x00000010,
    kIOMemoryPageable	      		= 0x00000020,
    kIOMemoryPurgeable	      		= 0x00000040,
    kIOMemorySharingTypeMask		= 0x000f0000,
    kIOMemoryUnshared			= 0x00000000,
    kIOMemoryKernelUserShared		= 0x00010000
};

#define _IOBUFFERMEMORYDESCRIPTOR_INTASKWITHOPTIONS_	1
/*!
    @class IOBufferMemoryDescriptor
    @abstract Provides a simple memory descriptor that allocates its own buffer memory.
*/

class IOBufferMemoryDescriptor : public IOGeneralMemoryDescriptor
{
    OSDeclareDefaultStructors(IOBufferMemoryDescriptor);

protected:
/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of this class in the future.
    */    
    struct ExpansionData {
	vm_map_t	map;
    };

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
    virtual bool initWithOptions(
                               IOOptionBits options,
                               vm_size_t    capacity,
                               vm_offset_t  alignment,
			       task_t	    inTask);

    OSMetaClassDeclareReservedUsed(IOBufferMemoryDescriptor, 0);
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

/*! @function inTaskWithOptions
    @abstract Creates a memory buffer with memory descriptor for that buffer. 
    @discussion Added in Mac OS X 10.2, this method allocates a memory buffer with a given size and alignment in the task's address space specified, and returns a memory descriptor instance representing the memory. It is recommended that memory allocated for I/O or sharing via mapping be created via IOBufferMemoryDescriptor. Options passed with the request specify the kind of memory to be allocated - pageablity and sharing are specified with option bits. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param inTask The task the buffer will be allocated in.
    @param options Options for the allocation:<br>
    kIOMemoryPhysicallyContiguous - pass to request memory be physically contiguous. This option is heavily discouraged. The request may fail if memory is fragmented, may cause large amounts of paging activity, and may take a very long time to execute.<br>
    kIOMemoryPageable - pass to request memory be non-wired - the default for kernel allocated memory is wired.<br>
    kIOMemoryPurgeable - pass to request memory that may later have its purgeable state set with IOMemoryDescriptor::setPurgeable. Only supported for kIOMemoryPageable allocations.<br>
    kIOMemoryKernelUserShared - pass to request memory that will be mapped into both the kernel and client applications.
    @param capacity The number of bytes to allocate.
    @param alignment The minimum required alignment of the buffer in bytes - 1 is the default for no required alignment. For example, pass 256 to get memory allocated at an address with bits 0-7 zero.
    @result Returns an instance of class IOBufferMemoryDescriptor to be released by the caller, which will free the memory desriptor and associated buffer. */

    static IOBufferMemoryDescriptor * inTaskWithOptions(
					    task_t       inTask,
                                            IOOptionBits options,
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
};

#endif /* !_IOBUFFERMEMORYDESCRIPTOR_H */
