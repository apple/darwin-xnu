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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

#include <IOKit/assert.h>
#include <IOKit/system.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>

#include <IOKit/IOKitDebug.h>

#include <libkern/c++/OSContainers.h>
#include <sys/cdefs.h>

__BEGIN_DECLS
#include <vm/pmap.h>
void pmap_enter(pmap_t pmap, vm_offset_t va, vm_offset_t pa,
                vm_prot_t prot, boolean_t wired);
void ipc_port_release_send(ipc_port_t port);
vm_offset_t vm_map_get_phys_page(vm_map_t map, vm_offset_t offset);
__END_DECLS

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClass( IOMemoryDescriptor, OSObject )
OSDefineAbstractStructors( IOMemoryDescriptor, OSObject )

#define super IOMemoryDescriptor

OSDefineMetaClassAndStructors(IOGeneralMemoryDescriptor, IOMemoryDescriptor)

extern "C" vm_map_t IOPageableMapForAddress( vm_address_t address );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

inline vm_map_t IOGeneralMemoryDescriptor::getMapForTask( task_t task, vm_address_t address )
{
    if( (task == kernel_task) && (kIOMemoryRequiresWire & _flags))
        return( IOPageableMapForAddress( address ) );
    else
        return( get_task_map( task ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * withAddress:
 *
 * Create a new IOMemoryDescriptor.  The buffer is a virtual address
 * relative to the specified task.  If no task is supplied, the kernel
 * task is implied.
 */
IOMemoryDescriptor *
IOMemoryDescriptor::withAddress(void *      address,
                                IOByteCount   withLength,
                                IODirection withDirection)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithAddress(address, withLength, withDirection))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withAddress(vm_address_t address,
                                IOByteCount  withLength,
                                IODirection  withDirection,
                                task_t       withTask)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithAddress(address, withLength, withDirection, withTask))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withPhysicalAddress(
				IOPhysicalAddress	address,
				IOByteCount		withLength,
				IODirection      	withDirection )
{
    return( IOMemoryDescriptor::withAddress( address, withLength,
					withDirection, (task_t) 0  ));
}


/*
 * withRanges:
 *
 * Create a new IOMemoryDescriptor. The buffer is made up of several
 * virtual address ranges, from a given task.
 *
 * Passing the ranges as a reference will avoid an extra allocation.
 */
IOMemoryDescriptor *
IOMemoryDescriptor::withRanges(	IOVirtualRange * ranges,
				UInt32           withCount,
				IODirection      withDirection,
				task_t           withTask,
				bool             asReference = false)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithRanges(ranges, withCount, withDirection, withTask, asReference))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withPhysicalRanges(	IOPhysicalRange * ranges,
                                        UInt32          withCount,
                                        IODirection     withDirection,
                                        bool            asReference = false)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithPhysicalRanges(ranges, withCount, withDirection, asReference))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withSubRange(IOMemoryDescriptor *	of,
				IOByteCount		offset,
				IOByteCount		length,
				IODirection		withDirection)
{
    IOSubMemoryDescriptor * that = new IOSubMemoryDescriptor;

    if (that && !that->initSubRange(of, offset, length, withDirection)) {
        that->release();
	that = 0;
    }
    return that;
}

/*
 * initWithAddress:
 *
 * Initialize an IOMemoryDescriptor. The buffer is a virtual address
 * relative to the specified task.  If no task is supplied, the kernel
 * task is implied.
 *
 * An IOMemoryDescriptor can be re-used by calling initWithAddress or
 * initWithRanges again on an existing instance -- note this behavior
 * is not commonly supported in other I/O Kit classes, although it is
 * supported here.
 */
bool
IOGeneralMemoryDescriptor::initWithAddress(void *      address,
                                    IOByteCount   withLength,
                                    IODirection withDirection)
{
    _singleRange.v.address = (vm_address_t) address;
    _singleRange.v.length  = withLength;

    return initWithRanges(&_singleRange.v, 1, withDirection, kernel_task, true);
}

bool
IOGeneralMemoryDescriptor::initWithAddress(vm_address_t address,
                                    IOByteCount    withLength,
                                    IODirection  withDirection,
                                    task_t       withTask)
{
    _singleRange.v.address = address;
    _singleRange.v.length  = withLength;

    return initWithRanges(&_singleRange.v, 1, withDirection, withTask, true);
}

bool
IOGeneralMemoryDescriptor::initWithPhysicalAddress(
				 IOPhysicalAddress	address,
				 IOByteCount		withLength,
				 IODirection      	withDirection )
{
    _singleRange.p.address = address;
    _singleRange.p.length  = withLength;

    return initWithPhysicalRanges( &_singleRange.p, 1, withDirection, true);
}

/*
 * initWithRanges:
 *
 * Initialize an IOMemoryDescriptor. The buffer is made up of several
 * virtual address ranges, from a given task
 *
 * Passing the ranges as a reference will avoid an extra allocation.
 *
 * An IOMemoryDescriptor can be re-used by calling initWithAddress or
 * initWithRanges again on an existing instance -- note this behavior
 * is not commonly supported in other I/O Kit classes, although it is
 * supported here.
 */
bool
IOGeneralMemoryDescriptor::initWithRanges(
                                   IOVirtualRange * ranges,
                                   UInt32           withCount,
                                   IODirection      withDirection,
                                   task_t           withTask,
                                   bool             asReference = false)
{
    assert(ranges);
    assert(withCount);

    /*
     * We can check the _initialized  instance variable before having ever set
     * it to an initial value because I/O Kit guarantees that all our instance
     * variables are zeroed on an object's allocation.
     */

    if (_initialized == false)
    {
        if (super::init() == false)  return false;
        _initialized = true;
    }
    else
    {
        /*
         * An existing memory descriptor is being retargeted to point to
         * somewhere else.  Clean up our present state.
         */

        assert(_wireCount == 0);

        while (_wireCount)
            complete();
        if (_kernPtrAligned)
            unmapFromKernel();
        if (_ranges.v && _rangesIsAllocated)
            IODelete(_ranges.v, IOVirtualRange, _rangesCount);
    }

    /*
     * Initialize the memory descriptor.
     */

    _ranges.v              = 0;
    _rangesCount           = withCount;
    _rangesIsAllocated     = asReference ? false : true;
    _direction             = withDirection;
    _length                = 0;
    _task                  = withTask;
    _position              = 0;
    _positionAtIndex       = 0;
    _positionAtOffset      = 0;
    _kernPtrAligned        = 0;
    _cachedPhysicalAddress = 0;
    _cachedVirtualAddress  = 0;
    _flags		   = 0;

    if (withTask && (withTask != kernel_task))
        _flags |= kIOMemoryRequiresWire;

    if (asReference)
        _ranges.v = ranges;
    else
    {
        _ranges.v = IONew(IOVirtualRange, withCount);
        if (_ranges.v == 0)  return false;
        bcopy(/* from */ ranges, _ranges.v, withCount * sizeof(IOVirtualRange));
    } 

    for (unsigned index = 0; index < _rangesCount; index++)
    {
        _length += _ranges.v[index].length;
    }

    return true;
}

bool
IOGeneralMemoryDescriptor::initWithPhysicalRanges(	IOPhysicalRange * ranges,
                                        	UInt32           withCount,
                                        	IODirection      withDirection,
                                        	bool             asReference = false)
{
#warning assuming virtual, physical addresses same size
    return( initWithRanges( (IOVirtualRange *) ranges,
			withCount, withDirection, (task_t) 0, asReference ));
}

/*
 * free
 *
 * Free resources.
 */
void IOGeneralMemoryDescriptor::free()
{
    while (_wireCount)
        complete();
    if (_kernPtrAligned)
        unmapFromKernel();
    if (_ranges.v && _rangesIsAllocated)
        IODelete(_ranges.v, IOVirtualRange, _rangesCount);
    if( _memEntry)
        ipc_port_release_send( (ipc_port_t) _memEntry );
    super::free();
}

void IOGeneralMemoryDescriptor::unmapFromKernel()
{
    kern_return_t krtn;
    vm_offset_t off;
    // Pull the shared pages out of the task map
    // Do we need to unwire it first?
    for ( off = 0; off < _kernSize; off += page_size )
    {
	pmap_change_wiring(
			kernel_pmap,
			_kernPtrAligned + off,
			FALSE);

	pmap_remove(
			kernel_pmap,
			_kernPtrAligned + off,
			_kernPtrAligned + off + page_size);
    }
    // Free the former shmem area in the task
    krtn = vm_deallocate(kernel_map,
			_kernPtrAligned,
			_kernSize );
    assert(krtn == KERN_SUCCESS);
    _kernPtrAligned = 0;
}

void IOGeneralMemoryDescriptor::mapIntoKernel(unsigned rangeIndex)
{
    kern_return_t krtn;
    vm_offset_t off;

    if (_kernPtrAligned)
    {
        if (_kernPtrAtIndex == rangeIndex)  return;
        unmapFromKernel();
        assert(_kernPtrAligned == 0);
    }
 
    vm_offset_t srcAlign = trunc_page(_ranges.v[rangeIndex].address);

    _kernSize = trunc_page(_ranges.v[rangeIndex].address +
                           _ranges.v[rangeIndex].length  +
                           page_size - 1) - srcAlign;

    /* Find some memory of the same size in kernel task.  We use vm_allocate()
    to do this. vm_allocate inserts the found memory object in the
    target task's map as a side effect. */
    krtn = vm_allocate( kernel_map,
	    &_kernPtrAligned,
	    _kernSize,
	    VM_FLAGS_ANYWHERE|VM_MAKE_TAG(VM_MEMORY_IOKIT) );  // Find first fit
    assert(krtn == KERN_SUCCESS);
    if(krtn)  return;

    /* For each page in the area allocated from the kernel map,
	    find the physical address of the page.
	    Enter the page in the target task's pmap, at the
	    appropriate target task virtual address. */
    for ( off = 0; off < _kernSize; off += page_size )
    {
	vm_offset_t kern_phys_addr, phys_addr;
	if( _task)
	    phys_addr = pmap_extract( get_task_pmap(_task), srcAlign + off );
	else
	    phys_addr = srcAlign + off;
        assert(phys_addr);
	if(phys_addr == 0)  return;

	// Check original state.
	kern_phys_addr = pmap_extract( kernel_pmap, _kernPtrAligned + off );
	// Set virtual page to point to the right physical one
	pmap_enter(
	    kernel_pmap,
	    _kernPtrAligned + off,
	    phys_addr,
	    VM_PROT_READ|VM_PROT_WRITE,
	    TRUE);
    }
    _kernPtrAtIndex = rangeIndex;
}

/*
 * getDirection:
 *
 * Get the direction of the transfer.
 */
IODirection IOMemoryDescriptor::getDirection() const
{
    return _direction;
}

/*
 * getLength:
 *
 * Get the length of the transfer (over all ranges).
 */
IOByteCount IOMemoryDescriptor::getLength() const
{
    return _length;
}

void IOMemoryDescriptor::setTag(
	IOOptionBits		tag )
{
    _tag = tag;    
}

IOOptionBits IOMemoryDescriptor::getTag( void )
{
    return( _tag);
}

/*
 * setPosition
 *
 * Set the logical start position inside the client buffer.
 *
 * It is convention that the position reflect the actual byte count that
 * is successfully transferred into or out of the buffer, before the I/O
 * request is "completed" (ie. sent back to its originator).
 */

void IOGeneralMemoryDescriptor::setPosition(IOByteCount position)
{
    assert(position <= _length);

    if (position >= _length)
    {
        _position         = _length;
        _positionAtIndex  = _rangesCount;          /* careful: out-of-bounds */
        _positionAtOffset = 0;
        return;
    }

    if (position < _position)
    {
	_positionAtOffset = position;
	_positionAtIndex  = 0;
    }
    else
    {
	_positionAtOffset += (position - _position);
    }
    _position = position;

    while (_positionAtOffset >= _ranges.v[_positionAtIndex].length)
    {
        _positionAtOffset -= _ranges.v[_positionAtIndex].length;
        _positionAtIndex++;
    }
}

/*
 * readBytes:
 *
 * Copy data from the memory descriptor's buffer into the specified buffer,
 * relative to the current position.   The memory descriptor's position is
 * advanced based on the number of bytes copied.
 */

IOByteCount IOGeneralMemoryDescriptor::readBytes(IOByteCount offset,
					void * bytes, IOByteCount withLength)
{
    IOByteCount bytesLeft;
    void *    segment;
    IOByteCount segmentLength;

    if( offset != _position)
	setPosition( offset );

    withLength = min(withLength, _length - _position);
    bytesLeft  = withLength;

#if 0
    while (bytesLeft && (_position < _length))
    {
	/* Compute the relative length to the end of this virtual segment. */
        segmentLength = min(_ranges.v[_positionAtIndex].length - _positionAtOffset, bytesLeft);

	/* Compute the relative address of this virtual segment. */
        segment = (void *)(_ranges.v[_positionAtIndex].address + _positionAtOffset);

	if (KERN_SUCCESS != vm_map_read_user(getMapForTask(_task, segment),
		/* from */ (vm_offset_t) segment, /* to */ (vm_offset_t) bytes,
		/* size */ segmentLength))
	{
	    assert( false );
            bytesLeft = withLength;
	    break;
	}
        bytesLeft -= segmentLength;
	offset += segmentLength;
	setPosition(offset);
    }
#else
    while (bytesLeft && (segment = getVirtualSegment(offset, &segmentLength)))
    {
        segmentLength = min(segmentLength, bytesLeft);
        bcopy(/* from */ segment, /* to */ bytes, /* size */ segmentLength);
        bytesLeft -= segmentLength;
	offset += segmentLength;
        bytes = (void *) (((UInt32) bytes) + segmentLength);
    }
#endif

    return withLength - bytesLeft;
}

/*
 * writeBytes:
 *
 * Copy data to the memory descriptor's buffer from the specified buffer,
 * relative to the current position.  The memory descriptor's position is
 * advanced based on the number of bytes copied.
 */
IOByteCount IOGeneralMemoryDescriptor::writeBytes(IOByteCount offset,
				const void* bytes,IOByteCount withLength)
{
    IOByteCount bytesLeft;
    void *    segment;
    IOByteCount segmentLength;

    if( offset != _position)
	setPosition( offset );

    withLength = min(withLength, _length - _position);
    bytesLeft  = withLength;

#if 0
    while (bytesLeft && (_position < _length))
    {
	assert(_position <= _length);

	/* Compute the relative length to the end of this virtual segment. */
        segmentLength = min(_ranges.v[_positionAtIndex].length - _positionAtOffset, bytesLeft);

	/* Compute the relative address of this virtual segment. */
        segment = (void *)(_ranges.v[_positionAtIndex].address + _positionAtOffset);

	if (KERN_SUCCESS != vm_map_write_user(getMapForTask(_task, segment),
		/* from */ (vm_offset_t) bytes, 
	        /* to */ (vm_offset_t) segment,
		/* size */ segmentLength))
	{
	    assert( false );
            bytesLeft = withLength;
	    break;
	}
        bytesLeft -= segmentLength;
	offset += segmentLength;
	setPosition(offset);
    }
#else
    while (bytesLeft && (segment = getVirtualSegment(offset, &segmentLength)))
    {
        segmentLength = min(segmentLength, bytesLeft);
        bcopy(/* from */ bytes, /* to */ segment, /* size */ segmentLength);
        // Flush cache in case we're copying code around, eg. handling a code page fault
        IOFlushProcessorCache(kernel_task, (vm_offset_t) segment, segmentLength );
        
        bytesLeft -= segmentLength;
        offset += segmentLength;
        bytes = (void *) (((UInt32) bytes) + segmentLength);
    }
#endif

    return withLength - bytesLeft;
}

/*
 * getPhysicalSegment:
 *
 * Get the physical address of the buffer, relative to the current position.
 * If the current position is at the end of the buffer, a zero is returned.
 */
IOPhysicalAddress
IOGeneralMemoryDescriptor::getPhysicalSegment(IOByteCount offset,
						IOByteCount * lengthOfSegment)
{
    vm_address_t      virtualAddress;
    IOByteCount       virtualLength;
    pmap_t            virtualPMap;
    IOPhysicalAddress physicalAddress;
    IOPhysicalLength  physicalLength;

    if( kIOMemoryRequiresWire & _flags)
        assert( _wireCount );

    if ((0 == _task) && (1 == _rangesCount))
    {
	assert(offset <= _length);
	if (offset >= _length)
	{
	    physicalAddress = 0;
	    physicalLength  = 0;
	}
	else
	{
	    physicalLength = _length - offset;
	    physicalAddress = offset + _ranges.v[0].address;
	}

	if (lengthOfSegment)
	    *lengthOfSegment = physicalLength;
	return physicalAddress;
    }

    if( offset != _position)
	setPosition( offset );

    assert(_position <= _length);

    /* Fail gracefully if the position is at (or past) the end-of-buffer. */
    if (_position >= _length)
    {
        *lengthOfSegment = 0;
        return 0;
    }

    /* Prepare to compute the largest contiguous physical length possible. */

    virtualAddress  = _ranges.v[_positionAtIndex].address + _positionAtOffset;
    virtualLength   = _ranges.v[_positionAtIndex].length  - _positionAtOffset;
    vm_address_t      virtualPage  = trunc_page(virtualAddress);
    if( _task)
	virtualPMap     = get_task_pmap(_task);
    else
	virtualPMap	= 0;

    physicalAddress = (virtualAddress == _cachedVirtualAddress) ?
                        _cachedPhysicalAddress :              /* optimization */
			virtualPMap ?
                        	pmap_extract(virtualPMap, virtualAddress) :
				virtualAddress;
    physicalLength  = trunc_page(physicalAddress) + page_size - physicalAddress;

    if (!physicalAddress && _task)
    {
	physicalAddress =
	    vm_map_get_phys_page(get_task_map(_task), virtualPage);
	physicalAddress += virtualAddress - virtualPage;
    }

    if (physicalAddress == 0)     /* memory must be wired in order to proceed */
    {
        assert(physicalAddress);
        *lengthOfSegment = 0;
        return 0;
    }

    /* Compute the largest contiguous physical length possible, within range. */
    IOPhysicalAddress physicalPage = trunc_page(physicalAddress);

    while (physicalLength < virtualLength)
    {
        physicalPage          += page_size;
        virtualPage           += page_size;
        _cachedVirtualAddress  = virtualPage;
        _cachedPhysicalAddress = virtualPMap ?
                        		pmap_extract(virtualPMap, virtualPage) :
					virtualPage;
	if (!_cachedPhysicalAddress && _task)
	{
	    _cachedPhysicalAddress =
		vm_map_get_phys_page(get_task_map(_task), virtualPage);
	}

        if (_cachedPhysicalAddress != physicalPage)  break;

        physicalLength += page_size;
    }

    /* Clip contiguous physical length at the end of this range. */
    if (physicalLength > virtualLength)
        physicalLength = virtualLength;

    if( lengthOfSegment)
	*lengthOfSegment = physicalLength;

    return physicalAddress;
}


/*
 * getVirtualSegment:
 *
 * Get the virtual address of the buffer, relative to the current position.
 * If the memory wasn't mapped into the caller's address space, it will be
 * mapped in now.   If the current position is at the end of the buffer, a
 * null is returned.
 */
void * IOGeneralMemoryDescriptor::getVirtualSegment(IOByteCount offset,
							IOByteCount * lengthOfSegment)
{
    if( offset != _position)
	setPosition( offset );

    assert(_position <= _length);

    /* Fail gracefully if the position is at (or past) the end-of-buffer. */
    if (_position >= _length)
    {
        *lengthOfSegment = 0;
        return 0;
    }

    /* Compute the relative length to the end of this virtual segment. */
    *lengthOfSegment = _ranges.v[_positionAtIndex].length - _positionAtOffset;

    /* Compute the relative address of this virtual segment. */
    if (_task == kernel_task)
        return (void *)(_ranges.v[_positionAtIndex].address + _positionAtOffset);
    else
    {
	vm_offset_t off;

        mapIntoKernel(_positionAtIndex);

	off  = _ranges.v[_kernPtrAtIndex].address;
	off -= trunc_page(off);

	return (void *) (_kernPtrAligned + off + _positionAtOffset);
    }
}

/*
 * prepare
 *
 * Prepare the memory for an I/O transfer.  This involves paging in
 * the memory, if necessary, and wiring it down for the duration of
 * the transfer.  The complete() method completes the processing of
 * the memory after the I/O transfer finishes.  This method needn't
 * called for non-pageable memory.
 */
IOReturn IOGeneralMemoryDescriptor::prepare(
		IODirection forDirection = kIODirectionNone)
{
    UInt rangeIndex = 0;

    if((_wireCount == 0) && (kIOMemoryRequiresWire & _flags)) {
        kern_return_t rc;

        if(forDirection == kIODirectionNone)
            forDirection = _direction;

        vm_prot_t access = VM_PROT_DEFAULT;    // Could be cleverer using direction

        //
        // Check user read/write access to the data buffer.
        //

        for (rangeIndex = 0; rangeIndex < _rangesCount; rangeIndex++)
        {
            vm_offset_t checkBase = trunc_page(_ranges.v[rangeIndex].address);
            vm_size_t   checkSize = round_page(_ranges.v[rangeIndex].length );

            while (checkSize)
            {
                vm_region_basic_info_data_t regionInfo;
                mach_msg_type_number_t      regionInfoSize = sizeof(regionInfo);
                vm_size_t                   regionSize;

                if ( (vm_region(
                          /* map         */ getMapForTask(_task, checkBase),
                          /* address     */ &checkBase,
                          /* size        */ &regionSize,
                          /* flavor      */ VM_REGION_BASIC_INFO,
                          /* info        */ (vm_region_info_t) &regionInfo,
                          /* info size   */ &regionInfoSize,
                          /* object name */ 0 ) != KERN_SUCCESS             ) ||
                     ( (forDirection & kIODirectionIn ) &&
                                   !(regionInfo.protection & VM_PROT_WRITE) ) ||
                     ( (forDirection & kIODirectionOut) && 
                                   !(regionInfo.protection & VM_PROT_READ ) ) )
                {
                    return kIOReturnVMError;
                }

                assert((regionSize & PAGE_MASK) == 0);

                regionSize = min(regionSize, checkSize);
                checkSize -= regionSize;
                checkBase += regionSize;
            } // (for each vm region)
        } // (for each io range)

        for (rangeIndex = 0; rangeIndex < _rangesCount; rangeIndex++) {

            vm_offset_t srcAlign = trunc_page(_ranges.v[rangeIndex].address);
            IOByteCount srcAlignEnd = trunc_page(_ranges.v[rangeIndex].address +
                                _ranges.v[rangeIndex].length  +
                                page_size - 1);

	    vm_map_t taskVMMap = getMapForTask(_task, srcAlign);

            rc = vm_map_wire(taskVMMap, srcAlign, srcAlignEnd, access, FALSE);
	    if (KERN_SUCCESS != rc) {
		IOLog("IOMemoryDescriptor::prepare vm_map_wire failed: %d\n", rc);
		goto abortExit;
	    }

	    // If this I/O is for a user land task then protect ourselves
	    // against COW and other vm_shenanigans
	    if (_task && _task != kernel_task) {
		// setup a data object to hold the 'named' memory regions
		// @@@ gvdl: If we fail to allocate an OSData we will just
		// hope for the best for the time being.  Lets not fail a
		// prepare at this late stage in product release.
		if (!_memoryEntries)
		    _memoryEntries = OSData::withCapacity(16);
		if (_memoryEntries) {
		    vm_object_offset_t desiredSize = srcAlignEnd - srcAlign;
		    vm_object_offset_t entryStart = srcAlign;
		    ipc_port_t memHandle;

		    do {
			vm_object_offset_t actualSize = desiredSize;

			rc = mach_make_memory_entry_64
			    (taskVMMap, &actualSize, entryStart,
			    forDirection, &memHandle, NULL);
			if (KERN_SUCCESS != rc) {
			    IOLog("IOMemoryDescriptor::prepare mach_make_memory_entry_64 failed: %d\n", rc);
			    goto abortExit;
			}

			_memoryEntries->
			    appendBytes(&memHandle, sizeof(memHandle));
			desiredSize -= actualSize;
			entryStart += actualSize;
		    } while (desiredSize);
		}
	    }
        }
    }
    _wireCount++;
    return kIOReturnSuccess;

abortExit:
    UInt doneIndex;


    for(doneIndex = 0; doneIndex < rangeIndex; doneIndex++) {
	vm_offset_t srcAlign = trunc_page(_ranges.v[doneIndex].address);
	IOByteCount srcAlignEnd = trunc_page(_ranges.v[doneIndex].address +
			    _ranges.v[doneIndex].length  +
			    page_size - 1);

	vm_map_unwire(getMapForTask(_task, srcAlign), srcAlign,
			    srcAlignEnd, FALSE);
    }

    if (_memoryEntries) {
	ipc_port_t *handles, *handlesEnd;

	handles = (ipc_port_t *) _memoryEntries->getBytesNoCopy();
	handlesEnd = (ipc_port_t *)
	    ((vm_address_t) handles + _memoryEntries->getLength());
	while (handles < handlesEnd)
	    ipc_port_release_send(*handles++);
	_memoryEntries->release();
	_memoryEntries = 0;
    }

    return kIOReturnVMError;
}

/*
 * complete
 *
 * Complete processing of the memory after an I/O transfer finishes.
 * This method should not be called unless a prepare was previously
 * issued; the prepare() and complete() must occur in pairs, before
 * before and after an I/O transfer involving pageable memory.
 */
 
IOReturn IOGeneralMemoryDescriptor::complete(
		IODirection forDirection = kIODirectionNone)
{
    assert(_wireCount);

    if(0 == _wireCount)
        return kIOReturnSuccess;

    _wireCount--;
    if((_wireCount == 0) && (kIOMemoryRequiresWire & _flags)) {
        UInt rangeIndex;
        kern_return_t rc;

        if(forDirection == kIODirectionNone)
            forDirection = _direction;

        for(rangeIndex = 0; rangeIndex < _rangesCount; rangeIndex++) {

            vm_offset_t srcAlign = trunc_page(_ranges.v[rangeIndex].address);
            IOByteCount srcAlignEnd = trunc_page(_ranges.v[rangeIndex].address +
                                _ranges.v[rangeIndex].length  +
                                page_size - 1);

            if(forDirection == kIODirectionIn)
                pmap_modify_pages(get_task_pmap(_task), srcAlign, srcAlignEnd);

            rc = vm_map_unwire(getMapForTask(_task, srcAlign), srcAlign,
                                  srcAlignEnd, FALSE);
            if(rc != KERN_SUCCESS)
                IOLog("IOMemoryDescriptor::complete: vm_map_unwire failed: %d\n", rc);
        }

	if (_memoryEntries) {
	    ipc_port_t *handles, *handlesEnd;

	    handles = (ipc_port_t *) _memoryEntries->getBytesNoCopy();
	    handlesEnd = (ipc_port_t *)
			((vm_address_t) handles + _memoryEntries->getLength());
	    while (handles < handlesEnd)
		ipc_port_release_send(*handles++);

	    _memoryEntries->release();
	    _memoryEntries = 0;
	}

	_cachedVirtualAddress = 0;
    }
    return kIOReturnSuccess;
}

IOReturn IOGeneralMemoryDescriptor::doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset = 0,
	IOByteCount		length = 0 )
{
    kern_return_t kr;

    // mapping source == dest? (could be much better)
    if( _task && (addressMap == get_task_map(_task)) && (options & kIOMapAnywhere)
	&& (1 == _rangesCount) && (0 == sourceOffset)
	&& (length <= _ranges.v[0].length) ) {
	    *atAddress = _ranges.v[0].address;
	    return( kIOReturnSuccess );
    }

     if( _task && _memEntry && (_flags & kIOMemoryRequiresWire)) {

        do {

            if( (1 != _rangesCount)
             || (kIOMapDefaultCache != (options & kIOMapCacheMask)) ) {
                kr = kIOReturnUnsupported;
                continue;
            }

            if( 0 == length)
                length = getLength();
            if( (sourceOffset + length) > _ranges.v[0].length) {
                kr = kIOReturnBadArgument;
                continue;
            }

            ipc_port_t sharedMem = (ipc_port_t) _memEntry;
            vm_prot_t prot = VM_PROT_READ
                            | ((options & kIOMapReadOnly) ? 0 : VM_PROT_WRITE);

            // vm_map looks for addresses above here, even when VM_FLAGS_ANYWHERE
            if( options & kIOMapAnywhere)
                *atAddress = 0;

            if( 0 == sharedMem)
                kr = kIOReturnVMError;
            else
                kr = KERN_SUCCESS;

            if( KERN_SUCCESS == kr)
                kr = vm_map( addressMap,
                             atAddress,
                             length, 0 /* mask */, 
                             (( options & kIOMapAnywhere ) ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
                             | VM_MAKE_TAG(VM_MEMORY_IOKIT), 
                             sharedMem, sourceOffset,
                             false, // copy
                             prot, // cur
                             prot, // max
                             VM_INHERIT_NONE);
        
        } while( false );

    } else
        kr = super::doMap( addressMap, atAddress,
                           options, sourceOffset, length );
    return( kr );
}

IOReturn IOGeneralMemoryDescriptor::doUnmap(
	vm_map_t		addressMap,
	IOVirtualAddress	logical,
	IOByteCount		length )
{
    // could be much better
    if( _task && (addressMap == getMapForTask(_task, _ranges.v[0].address)) && (1 == _rangesCount)
	 && (logical == _ranges.v[0].address)
	 && (length <= _ranges.v[0].length) )
	    return( kIOReturnSuccess );

    return( super::doUnmap( addressMap, logical, length ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" {
// osfmk/device/iokit_rpc.c
extern kern_return_t IOMapPages( vm_map_t map, vm_offset_t va, vm_offset_t pa,
                                 vm_size_t length, unsigned int mapFlags);
extern kern_return_t IOUnmapPages(vm_map_t map, vm_offset_t va, vm_size_t length);
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IORecursiveLock * gIOMemoryLock;

#define LOCK	IORecursiveLockLock( gIOMemoryLock)
#define UNLOCK	IORecursiveLockUnlock( gIOMemoryLock)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClass( IOMemoryMap, OSObject )
OSDefineAbstractStructors( IOMemoryMap, OSObject )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class _IOMemoryMap : public IOMemoryMap
{
    OSDeclareDefaultStructors(_IOMemoryMap)

    IOMemoryDescriptor * memory;
    IOMemoryMap *	superMap;
    IOByteCount		offset;
    IOByteCount		length;
    IOVirtualAddress	logical;
    task_t		addressTask;
    vm_map_t		addressMap;
    IOOptionBits	options;

public:
    virtual void free();

    // IOMemoryMap methods
    virtual IOVirtualAddress 	getVirtualAddress();
    virtual IOByteCount 	getLength();
    virtual task_t		getAddressTask();
    virtual IOMemoryDescriptor * getMemoryDescriptor();
    virtual IOOptionBits 	getMapOptions();

    virtual IOReturn 		unmap();
    virtual void 		taskDied();

    virtual IOPhysicalAddress 	getPhysicalSegment(IOByteCount offset,
	       					   IOByteCount * length);

    // for IOMemoryDescriptor use
    _IOMemoryMap * isCompatible(
		IOMemoryDescriptor *	owner,
                task_t			intoTask,
                IOVirtualAddress	toAddress,
                IOOptionBits		options,
                IOByteCount		offset,
                IOByteCount		length );

    bool init(
	IOMemoryDescriptor *	memory,
	IOMemoryMap *		superMap,
        IOByteCount		offset,
        IOByteCount		length );

    bool init(
	IOMemoryDescriptor *	memory,
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
        IOByteCount		offset,
        IOByteCount		length );

    IOReturn redirect(
	task_t			intoTask, bool redirect );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOMemoryMap

OSDefineMetaClassAndStructors(_IOMemoryMap, IOMemoryMap)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool _IOMemoryMap::init(
	IOMemoryDescriptor *	_memory,
	IOMemoryMap *		_superMap,
        IOByteCount		_offset,
        IOByteCount		_length )
{

    if( !super::init())
	return( false);

    if( (_offset + _length) > _superMap->getLength())
	return( false);

    _memory->retain();
    memory	= _memory;
    _superMap->retain();
    superMap 	= _superMap;

    offset	= _offset;
    if( _length)
        length	= _length;
    else
        length	= _memory->getLength();

    options	= superMap->getMapOptions();
    logical	= superMap->getVirtualAddress() + offset;

    return( true );
}

bool _IOMemoryMap::init(
        IOMemoryDescriptor *	_memory,
        task_t			intoTask,
        IOVirtualAddress	toAddress,
        IOOptionBits		_options,
        IOByteCount		_offset,
        IOByteCount		_length )
{
    bool	ok;

    if( (!_memory) || (!intoTask) || !super::init())
	return( false);

    if( (_offset + _length) > _memory->getLength())
	return( false);

    addressMap  = get_task_map(intoTask);
    if( !addressMap)
	return( false);
    kernel_vm_map_reference(addressMap);

    _memory->retain();
    memory	= _memory;

    offset	= _offset;
    if( _length)
        length	= _length;
    else
        length	= _memory->getLength();

    addressTask	= intoTask;
    logical	= toAddress;
    options 	= _options;

    if( options & kIOMapStatic)
	ok = true;
    else
	ok = (kIOReturnSuccess == memory->doMap( addressMap, &logical,
						 options, offset, length ));
    if( !ok) {
	logical = 0;
        memory->release();
        memory = 0;
        vm_map_deallocate(addressMap);
        addressMap = 0;
    }
    return( ok );
}

IOReturn IOMemoryDescriptor::doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset = 0,
	IOByteCount		length = 0 )
{
    IOReturn		err = kIOReturnSuccess;
    vm_size_t		ourSize;
    vm_size_t		bytes;
    vm_offset_t		mapped;
    vm_address_t	logical;
    IOByteCount		pageOffset;
    IOPhysicalLength	segLen;
    IOPhysicalAddress	physAddr;

    if( 0 == length)
	length = getLength();

    physAddr = getPhysicalSegment( sourceOffset, &segLen );
    assert( physAddr );

    pageOffset = physAddr - trunc_page( physAddr );
    ourSize = length + pageOffset;
    physAddr -= pageOffset;

    logical = *atAddress;
    if( 0 == (options & kIOMapAnywhere)) {
        mapped = trunc_page( logical );
	if( (logical - mapped) != pageOffset)
	    err = kIOReturnVMError;
    }
    if( kIOReturnSuccess == err)
        err = vm_allocate( addressMap, &mapped, ourSize,
			   ((options & kIOMapAnywhere) ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
                           | VM_MAKE_TAG(VM_MEMORY_IOKIT) );

    if( err) {
#ifdef DEBUG
        kprintf("IOMemoryDescriptor::doMap: vm_allocate() "
		"returned %08x\n", err);
#endif
        return( err);
    }

    // we have to make sure that these guys don't get copied if we fork.
    err = vm_inherit( addressMap, mapped, ourSize, VM_INHERIT_NONE);
    if( err != KERN_SUCCESS) {
        doUnmap( addressMap, mapped, ourSize);	// back out
        return( err);
    }

    logical = mapped;
    *atAddress = mapped + pageOffset;

    segLen += pageOffset;
    bytes = ourSize;
    do {
	// in the middle of the loop only map whole pages
	if( segLen >= bytes)
	    segLen = bytes;
	else if( segLen != trunc_page( segLen))
	    err = kIOReturnVMError;
        if( physAddr != trunc_page( physAddr))
	    err = kIOReturnBadArgument;

#ifdef DEBUG
	if( kIOLogMapping & gIOKitDebug)
	    kprintf("_IOMemoryMap::map(%x) %08x->%08x:%08x\n",
                addressMap, mapped + pageOffset, physAddr + pageOffset,
		segLen - pageOffset);
#endif

	if( kIOReturnSuccess == err)
            err = IOMapPages( addressMap, mapped, physAddr, segLen, options );
	if( err)
	    break;

	sourceOffset += segLen - pageOffset;
	mapped += segLen;
	bytes -= segLen;
	pageOffset = 0;

    } while( bytes
	&& (physAddr = getPhysicalSegment( sourceOffset, &segLen )));

    if( bytes)
        err = kIOReturnBadArgument;
    if( err)
	doUnmap( addressMap, logical, ourSize );
    else
        mapped = true;

    return( err );
}

IOReturn IOMemoryDescriptor::doUnmap(
	vm_map_t		addressMap,
	IOVirtualAddress	logical,
	IOByteCount		length )
{
    IOReturn	err;

#ifdef DEBUG
    if( kIOLogMapping & gIOKitDebug)
	kprintf("IOMemoryDescriptor::doUnmap(%x) %08x:%08x\n",
                addressMap, logical, length );
#endif

    if( (addressMap == kernel_map) || (addressMap == get_task_map(current_task())))
        err = vm_deallocate( addressMap, logical, length );
    else
        err = kIOReturnSuccess;

    return( err );
}

IOReturn IOMemoryDescriptor::redirect( task_t safeTask, bool redirect )
{
    IOReturn		err;
    _IOMemoryMap *	mapping = 0;
    OSIterator *	iter;

    LOCK;

    do {
	if( (iter = OSCollectionIterator::withCollection( _mappings))) {
            while( (mapping = (_IOMemoryMap *) iter->getNextObject()))
                mapping->redirect( safeTask, redirect );

            iter->release();
        }
    } while( false );

    UNLOCK;

    // temporary binary compatibility
    IOSubMemoryDescriptor * subMem;
    if( (subMem = OSDynamicCast( IOSubMemoryDescriptor, this)))
        err = subMem->redirect( safeTask, redirect );
    else
        err = kIOReturnSuccess;

    return( err );
}

IOReturn IOSubMemoryDescriptor::redirect( task_t safeTask, bool redirect )
{
// temporary binary compatibility   IOMemoryDescriptor::redirect( safeTask, redirect );
    return( _parent->redirect( safeTask, redirect ));
}

IOReturn _IOMemoryMap::redirect( task_t safeTask, bool redirect )
{
    IOReturn err = kIOReturnSuccess;

    if( superMap) {
//        err = ((_IOMemoryMap *)superMap)->redirect( safeTask, redirect );
    } else {

        LOCK;
        if( logical && addressMap
        && (get_task_map( safeTask) != addressMap)
        && (0 == (options & kIOMapStatic))) {
    
            IOUnmapPages( addressMap, logical, length );
            if( !redirect) {
                err = vm_deallocate( addressMap, logical, length );
                err = memory->doMap( addressMap, &logical,
                                     (options & ~kIOMapAnywhere) /*| kIOMapReserve*/ );
            } else
                err = kIOReturnSuccess;
#ifdef DEBUG
            IOLog("IOMemoryMap::redirect(%d, %x) %x from %lx\n", redirect, err, logical, addressMap);
#endif
        }
        UNLOCK;
    }

    return( err );
}

IOReturn _IOMemoryMap::unmap( void )
{
    IOReturn	err;

    LOCK;

    if( logical && addressMap && (0 == superMap)
	&& (0 == (options & kIOMapStatic))) {

        err = memory->doUnmap( addressMap, logical, length );
        vm_map_deallocate(addressMap);
        addressMap = 0;

    } else
	err = kIOReturnSuccess;

    logical = 0;

    UNLOCK;

    return( err );
}

void _IOMemoryMap::taskDied( void )
{
    LOCK;
    if( addressMap) {
        vm_map_deallocate(addressMap);
        addressMap = 0;
    }
    addressTask	= 0;
    logical	= 0;
    UNLOCK;
}

void _IOMemoryMap::free()
{
    unmap();

    if( memory) {
        LOCK;
	memory->removeMapping( this);
	UNLOCK;
	memory->release();
    }

    if( superMap)
	superMap->release();

    super::free();
}

IOByteCount _IOMemoryMap::getLength()
{
    return( length );
}

IOVirtualAddress _IOMemoryMap::getVirtualAddress()
{
    return( logical);
}

task_t _IOMemoryMap::getAddressTask()
{
    if( superMap)
	return( superMap->getAddressTask());
    else
        return( addressTask);
}

IOOptionBits _IOMemoryMap::getMapOptions()
{
    return( options);
}

IOMemoryDescriptor * _IOMemoryMap::getMemoryDescriptor()
{
    return( memory );
}

_IOMemoryMap * _IOMemoryMap::isCompatible(
		IOMemoryDescriptor *	owner,
                task_t			task,
                IOVirtualAddress	toAddress,
                IOOptionBits		_options,
                IOByteCount		_offset,
                IOByteCount		_length )
{
    _IOMemoryMap * mapping;

    if( (!task) || (task != getAddressTask()))
	return( 0 );
    if( (options ^ _options) & (kIOMapCacheMask | kIOMapReadOnly))
	return( 0 );

    if( (0 == (_options & kIOMapAnywhere)) && (logical != toAddress))
	return( 0 );

    if( _offset < offset)
	return( 0 );

    _offset -= offset;

    if( (_offset + _length) > length)
	return( 0 );

    if( (length == _length) && (!_offset)) {
        retain();
	mapping = this;

    } else {
        mapping = new _IOMemoryMap;
        if( mapping
        && !mapping->init( owner, this, _offset, _length )) {
            mapping->release();
            mapping = 0;
        }
    }

    return( mapping );
}

IOPhysicalAddress _IOMemoryMap::getPhysicalSegment( IOByteCount _offset,
	       					    IOPhysicalLength * length)
{
    IOPhysicalAddress	address;

    LOCK;
    address = memory->getPhysicalSegment( offset + _offset, length );
    UNLOCK;

    return( address );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSObject

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOMemoryDescriptor::initialize( void )
{
    if( 0 == gIOMemoryLock)
	gIOMemoryLock = IORecursiveLockAlloc();
}

void IOMemoryDescriptor::free( void )
{
    if( _mappings)
	_mappings->release();

    super::free();
}

IOMemoryMap * IOMemoryDescriptor::setMapping(
	task_t			intoTask,
	IOVirtualAddress	mapAddress,
	IOOptionBits		options = 0 )
{
    _IOMemoryMap *		map;

    map = new _IOMemoryMap;

    LOCK;

    if( map
     && !map->init( this, intoTask, mapAddress,
                    options | kIOMapStatic, 0, getLength() )) {
	map->release();
	map = 0;
    }

    addMapping( map);

    UNLOCK;

    return( map);
}

IOMemoryMap * IOMemoryDescriptor::map( 
	IOOptionBits		options = 0 )
{

    return( makeMapping( this, kernel_task, 0,
			options | kIOMapAnywhere,
			0, getLength() ));
}

IOMemoryMap * IOMemoryDescriptor::map(
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
	IOByteCount		offset = 0,
	IOByteCount		length = 0 )
{
    if( 0 == length)
	length = getLength();

    return( makeMapping( this, intoTask, toAddress, options, offset, length ));
}

IOMemoryMap * IOMemoryDescriptor::makeMapping(
	IOMemoryDescriptor *	owner,
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length )
{
    _IOMemoryMap *	mapping = 0;
    OSIterator *	iter;

    LOCK;

    do {
	// look for an existing mapping
	if( (iter = OSCollectionIterator::withCollection( _mappings))) {

            while( (mapping = (_IOMemoryMap *) iter->getNextObject())) {

		if( (mapping = mapping->isCompatible( 
					owner, intoTask, toAddress,
					options | kIOMapReference,
					offset, length )))
		    break;
            }
            iter->release();
            if( mapping)
                continue;
        }


	if( mapping || (options & kIOMapReference))
	    continue;

	owner = this;

        mapping = new _IOMemoryMap;
	if( mapping
	&& !mapping->init( owner, intoTask, toAddress, options,
			   offset, length )) {

	    IOLog("Didn't make map %08lx : %08lx\n", offset, length );
	    mapping->release();
            mapping = 0;
	}

    } while( false );

    owner->addMapping( mapping);

    UNLOCK;

    return( mapping);
}

void IOMemoryDescriptor::addMapping(
	IOMemoryMap * mapping )
{
    if( mapping) {
        if( 0 == _mappings)
            _mappings = OSSet::withCapacity(1);
	if( _mappings && _mappings->setObject( mapping ))
	    mapping->release(); 	/* really */
    }
}

void IOMemoryDescriptor::removeMapping(
	IOMemoryMap * mapping )
{
    if( _mappings) {
        mapping->retain();
        mapping->retain();
        _mappings->removeObject( mapping);
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOMemoryDescriptor

OSDefineMetaClassAndStructors(IOSubMemoryDescriptor, IOMemoryDescriptor)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOSubMemoryDescriptor::initSubRange( IOMemoryDescriptor * parent,
					IOByteCount offset, IOByteCount length,
					IODirection withDirection )
{
    if( !super::init())
	return( false );

    if( !parent)
	return( false);

    if( (offset + length) > parent->getLength())
	return( false);

    parent->retain();
    _parent	= parent;
    _start	= offset;
    _length	= length;
    _direction  = withDirection;
    _tag	= parent->getTag();

    return( true );
}

void IOSubMemoryDescriptor::free( void )
{
    if( _parent)
	_parent->release();

    super::free();
}


IOPhysicalAddress IOSubMemoryDescriptor::getPhysicalSegment( IOByteCount offset,
						      	IOByteCount * length )
{
    IOPhysicalAddress	address;
    IOByteCount		actualLength;

    assert(offset <= _length);

    if( length)
        *length = 0;

    if( offset >= _length)
        return( 0 );

    address = _parent->getPhysicalSegment( offset + _start, &actualLength );

    if( address && length)
	*length = min( _length - offset, actualLength );

    return( address );
}

void * IOSubMemoryDescriptor::getVirtualSegment(IOByteCount offset,
					IOByteCount * lengthOfSegment)
{
    return( 0 );
}

IOByteCount IOSubMemoryDescriptor::readBytes(IOByteCount offset,
					void * bytes, IOByteCount withLength)
{
    IOByteCount	byteCount;

    assert(offset <= _length);

    if( offset >= _length)
        return( 0 );

    LOCK;
    byteCount = _parent->readBytes( _start + offset, bytes,
				min(withLength, _length - offset) );
    UNLOCK;

    return( byteCount );
}

IOByteCount IOSubMemoryDescriptor::writeBytes(IOByteCount offset,
				const void* bytes, IOByteCount withLength)
{
    IOByteCount	byteCount;

    assert(offset <= _length);

    if( offset >= _length)
        return( 0 );

    LOCK;
    byteCount = _parent->writeBytes( _start + offset, bytes,
				min(withLength, _length - offset) );
    UNLOCK;

    return( byteCount );
}

IOReturn IOSubMemoryDescriptor::prepare(
		IODirection forDirection = kIODirectionNone)
{
    IOReturn	err;

    LOCK;
    err = _parent->prepare( forDirection);
    UNLOCK;

    return( err );
}

IOReturn IOSubMemoryDescriptor::complete(
		IODirection forDirection = kIODirectionNone)
{
    IOReturn	err;

    LOCK;
    err = _parent->complete( forDirection);
    UNLOCK;

    return( err );
}

IOMemoryMap * IOSubMemoryDescriptor::makeMapping(
	IOMemoryDescriptor *	owner,
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length )
{
    IOMemoryMap * mapping;

     mapping = (IOMemoryMap *) _parent->makeMapping(
					_parent, intoTask,
					toAddress - (_start + offset),
					options | kIOMapReference,
					_start + offset, length );

    if( !mapping)
	mapping = super::makeMapping( owner, intoTask, toAddress, options,
					offset, length );

    return( mapping );
}

/* ick */

bool
IOSubMemoryDescriptor::initWithAddress(void *      address,
                                    IOByteCount   withLength,
                                    IODirection withDirection)
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithAddress(vm_address_t address,
                                    IOByteCount    withLength,
                                    IODirection  withDirection,
                                    task_t       withTask)
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithPhysicalAddress(
				 IOPhysicalAddress	address,
				 IOByteCount		withLength,
				 IODirection      	withDirection )
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithRanges(
                                   	IOVirtualRange * ranges,
                                   	UInt32           withCount,
                                   	IODirection      withDirection,
                                   	task_t           withTask,
                                  	bool             asReference = false)
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithPhysicalRanges(	IOPhysicalRange * ranges,
                                        	UInt32           withCount,
                                        	IODirection      withDirection,
                                        	bool             asReference = false)
{
    return( false );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 0);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 1);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 2);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 3);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 4);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 5);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 6);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 7);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 8);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 9);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 10);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 11);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 12);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 13);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 14);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 15);
