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
#include <device/device_port.h>
void bcopy_phys(char *from, char *to, int size);
void pmap_enter(pmap_t pmap, vm_offset_t va, vm_offset_t pa,
                vm_prot_t prot, boolean_t wired);
void ipc_port_release_send(ipc_port_t port);
vm_offset_t vm_map_get_phys_page(vm_map_t map, vm_offset_t offset);

memory_object_t
device_pager_setup(
	memory_object_t	pager,
	int		device_handle,
	vm_size_t	size,
	int		flags);
kern_return_t
device_pager_populate_object(
	memory_object_t		pager,
	vm_object_offset_t	offset,
	vm_offset_t		phys_addr,
	vm_size_t		size);

__END_DECLS

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClass( IOMemoryDescriptor, OSObject )
OSDefineAbstractStructors( IOMemoryDescriptor, OSObject )

#define super IOMemoryDescriptor

OSDefineMetaClassAndStructors(IOGeneralMemoryDescriptor, IOMemoryDescriptor)

extern "C" {

vm_map_t IOPageableMapForAddress( vm_address_t address );

typedef kern_return_t (*IOIteratePageableMapsCallback)(vm_map_t map, void * ref);

kern_return_t IOIteratePageableMaps(vm_size_t size,
                    IOIteratePageableMapsCallback callback, void * ref);

}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

inline vm_map_t IOGeneralMemoryDescriptor::getMapForTask( task_t task, vm_address_t address )
{
    if( (task == kernel_task) && (kIOMemoryRequiresWire & _flags))
        return( IOPageableMapForAddress( address ) );
    else
        return( get_task_map( task ));
}

inline vm_offset_t pmap_extract_safe(task_t task, vm_offset_t va)
{
    vm_offset_t pa = pmap_extract(get_task_pmap(task), va);

    if ( pa == 0 )
    {
        pa = vm_map_get_phys_page(get_task_map(task), trunc_page(va));
        if ( pa )  pa += va - trunc_page(va);
    }

    return pa;
}

inline void bcopy_phys_safe(char * from, char * to, int size)
{
    boolean_t enabled = ml_set_interrupts_enabled(FALSE);

    bcopy_phys(from, to, size);

    ml_set_interrupts_enabled(enabled);
}

#define next_page(a) ( trunc_page(a) + page_size )


extern "C" {

kern_return_t device_data_action(
               int                     device_handle, 
               ipc_port_t              device_pager,
               vm_prot_t               protection, 
               vm_object_offset_t      offset, 
               vm_size_t               size)
{
    IOMemoryDescriptor * memDesc = (IOMemoryDescriptor *) device_handle;

    assert( OSDynamicCast( IOMemoryDescriptor, memDesc ));

    return( memDesc->handleFault( device_pager, 0, 0,
                offset, size, kIOMapDefaultCache /*?*/));
}

kern_return_t device_close(
               int     device_handle)
{
    IOMemoryDescriptor * memDesc = (IOMemoryDescriptor *) device_handle;

    assert( OSDynamicCast( IOMemoryDescriptor, memDesc ));

    memDesc->release();

    return( kIOReturnSuccess );
}

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

/* DEPRECATED */ void IOGeneralMemoryDescriptor::unmapFromKernel()
/* DEPRECATED */ {
/* DEPRECATED */     kern_return_t krtn;
/* DEPRECATED */     vm_offset_t off;
/* DEPRECATED */     // Pull the shared pages out of the task map
/* DEPRECATED */     // Do we need to unwire it first?
/* DEPRECATED */     for ( off = 0; off < _kernSize; off += page_size )
/* DEPRECATED */     {
/* DEPRECATED */ 	pmap_change_wiring(
/* DEPRECATED */ 			kernel_pmap,
/* DEPRECATED */ 			_kernPtrAligned + off,
/* DEPRECATED */ 			FALSE);
/* DEPRECATED */ 
/* DEPRECATED */ 	pmap_remove(
/* DEPRECATED */ 			kernel_pmap,
/* DEPRECATED */ 			_kernPtrAligned + off,
/* DEPRECATED */ 			_kernPtrAligned + off + page_size);
/* DEPRECATED */     }
/* DEPRECATED */     // Free the former shmem area in the task
/* DEPRECATED */     krtn = vm_deallocate(kernel_map,
/* DEPRECATED */ 			_kernPtrAligned,
/* DEPRECATED */ 			_kernSize );
/* DEPRECATED */     assert(krtn == KERN_SUCCESS);
/* DEPRECATED */     _kernPtrAligned = 0;
/* DEPRECATED */ }
/* DEPRECATED */ 
/* DEPRECATED */ void IOGeneralMemoryDescriptor::mapIntoKernel(unsigned rangeIndex)
/* DEPRECATED */ {
/* DEPRECATED */     kern_return_t krtn;
/* DEPRECATED */     vm_offset_t off;
/* DEPRECATED */ 
/* DEPRECATED */     if (_kernPtrAligned)
/* DEPRECATED */     {
/* DEPRECATED */         if (_kernPtrAtIndex == rangeIndex)  return;
/* DEPRECATED */         unmapFromKernel();
/* DEPRECATED */         assert(_kernPtrAligned == 0);
/* DEPRECATED */     }
/* DEPRECATED */  
/* DEPRECATED */     vm_offset_t srcAlign = trunc_page(_ranges.v[rangeIndex].address);
/* DEPRECATED */ 
/* DEPRECATED */     _kernSize = trunc_page(_ranges.v[rangeIndex].address +
/* DEPRECATED */                            _ranges.v[rangeIndex].length  +
/* DEPRECATED */                            page_size - 1) - srcAlign;
/* DEPRECATED */ 
/* DEPRECATED */     /* Find some memory of the same size in kernel task.  We use vm_allocate() */
/* DEPRECATED */     /* to do this. vm_allocate inserts the found memory object in the */
/* DEPRECATED */     /* target task's map as a side effect. */
/* DEPRECATED */     krtn = vm_allocate( kernel_map,
/* DEPRECATED */ 	    &_kernPtrAligned,
/* DEPRECATED */ 	    _kernSize,
/* DEPRECATED */ 	    VM_FLAGS_ANYWHERE|VM_MAKE_TAG(VM_MEMORY_IOKIT) );  // Find first fit
/* DEPRECATED */     assert(krtn == KERN_SUCCESS);
/* DEPRECATED */     if(krtn)  return;
/* DEPRECATED */ 
/* DEPRECATED */     /* For each page in the area allocated from the kernel map, */
/* DEPRECATED */ 	 /* find the physical address of the page. */
/* DEPRECATED */ 	 /* Enter the page in the target task's pmap, at the */
/* DEPRECATED */ 	 /* appropriate target task virtual address. */
/* DEPRECATED */     for ( off = 0; off < _kernSize; off += page_size )
/* DEPRECATED */     {
/* DEPRECATED */ 	vm_offset_t kern_phys_addr, phys_addr;
/* DEPRECATED */ 	if( _task)
/* DEPRECATED */ 	    phys_addr = pmap_extract( get_task_pmap(_task), srcAlign + off );
/* DEPRECATED */ 	else
/* DEPRECATED */ 	    phys_addr = srcAlign + off;
/* DEPRECATED */         assert(phys_addr);
/* DEPRECATED */ 	if(phys_addr == 0)  return;
/* DEPRECATED */ 
/* DEPRECATED */ 	// Check original state.
/* DEPRECATED */ 	kern_phys_addr = pmap_extract( kernel_pmap, _kernPtrAligned + off );
/* DEPRECATED */ 	// Set virtual page to point to the right physical one
/* DEPRECATED */ 	pmap_enter(
/* DEPRECATED */ 	    kernel_pmap,
/* DEPRECATED */ 	    _kernPtrAligned + off,
/* DEPRECATED */ 	    phys_addr,
/* DEPRECATED */ 	    VM_PROT_READ|VM_PROT_WRITE,
/* DEPRECATED */ 	    TRUE);
/* DEPRECATED */     }
/* DEPRECATED */     _kernPtrAtIndex = rangeIndex;
/* DEPRECATED */ }

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

IOPhysicalAddress IOMemoryDescriptor::getSourceSegment( IOByteCount   offset,
                                                        IOByteCount * length )
{
    IOPhysicalAddress physAddr;

    prepare();
    physAddr = getPhysicalSegment( offset, length );
    complete();

    return( physAddr );
}

IOByteCount IOMemoryDescriptor::readBytes( IOByteCount offset,
                                                  void *      bytes,
                                                  IOByteCount withLength )
{
    IOByteCount bytesCopied = 0;

    assert(offset <= _length);
    assert(offset <= _length - withLength);

    if ( offset < _length )
    {
        withLength = min(withLength, _length - offset);

        while ( withLength ) // (process another source segment?)
        {
            IOPhysicalAddress sourceSegment;
            IOByteCount       sourceSegmentLength;

            sourceSegment = getPhysicalSegment(offset, &sourceSegmentLength);
            if ( sourceSegment == 0 )  goto readBytesErr;

            sourceSegmentLength = min(sourceSegmentLength, withLength);

            while ( sourceSegmentLength ) // (process another target segment?)
            {
                IOPhysicalAddress targetSegment;
                IOByteCount       targetSegmentLength;

                targetSegment = pmap_extract_safe(kernel_task, (vm_offset_t) bytes);
                if ( targetSegment == 0 )  goto readBytesErr;

                targetSegmentLength = min(next_page(targetSegment) - targetSegment, sourceSegmentLength);

                if ( sourceSegment + targetSegmentLength > next_page(sourceSegment) )
                {
                    IOByteCount pageLength;

                    pageLength = next_page(sourceSegment) - sourceSegment;

                    bcopy_phys_safe( /* from */ (char *) sourceSegment, 
                                     /* to   */ (char *) targetSegment,
                                     /* size */ (int   ) pageLength );

                    ((UInt8 *) bytes)   += pageLength;
                    bytesCopied         += pageLength;
                    offset              += pageLength;
                    sourceSegment       += pageLength;
                    sourceSegmentLength -= pageLength;
                    targetSegment       += pageLength;
                    targetSegmentLength -= pageLength;
                    withLength          -= pageLength;
                }

                bcopy_phys_safe( /* from */ (char *) sourceSegment, 
                                 /* to   */ (char *) targetSegment,
                                 /* size */ (int   ) targetSegmentLength );

                ((UInt8 *) bytes)   += targetSegmentLength;
                bytesCopied         += targetSegmentLength;
                offset              += targetSegmentLength;
                sourceSegment       += targetSegmentLength;
                sourceSegmentLength -= targetSegmentLength;
                withLength          -= targetSegmentLength;
            }
        }
    }

readBytesErr:

    if ( bytesCopied )
    {
        // We mark the destination pages as modified, just
        // in case they are made pageable later on in life.

        pmap_modify_pages( /* pmap  */ kernel_pmap,       
                           /* start */ trunc_page(((vm_offset_t) bytes) - bytesCopied),
                           /* end   */ round_page(((vm_offset_t) bytes)) );
    }

    return bytesCopied;
}

IOByteCount IOMemoryDescriptor::writeBytes( IOByteCount  offset,
                                                   const void * bytes,
                                                   IOByteCount  withLength )
{
    IOByteCount bytesCopied = 0;

    assert(offset <= _length);
    assert(offset <= _length - withLength);

    if ( offset < _length )
    {
        withLength = min(withLength, _length - offset);

        while ( withLength ) // (process another target segment?)
        {
            IOPhysicalAddress targetSegment;
            IOByteCount       targetSegmentLength;

            targetSegment = getPhysicalSegment(offset, &targetSegmentLength);
            if ( targetSegment == 0 )  goto writeBytesErr;

            targetSegmentLength = min(targetSegmentLength, withLength);

            while ( targetSegmentLength ) // (process another source segment?)
            {
                IOPhysicalAddress sourceSegment;
                IOByteCount       sourceSegmentLength;

                sourceSegment = pmap_extract_safe(kernel_task, (vm_offset_t) bytes);
                if ( sourceSegment == 0 )  goto writeBytesErr;

                sourceSegmentLength = min(next_page(sourceSegment) - sourceSegment, targetSegmentLength);

                if ( targetSegment + sourceSegmentLength > next_page(targetSegment) )
                {
                    IOByteCount pageLength;

                    pageLength = next_page(targetSegment) - targetSegment;

                    bcopy_phys_safe( /* from */ (char *) sourceSegment, 
                                     /* to   */ (char *) targetSegment,
                                     /* size */ (int   ) pageLength );

                    // We flush the data cache in case it is code we've copied,
                    // such that the instruction cache is in the know about it.

                    flush_dcache(targetSegment, pageLength, true);

                    ((UInt8 *) bytes)   += pageLength;
                    bytesCopied         += pageLength;
                    offset              += pageLength;
                    sourceSegment       += pageLength;
                    sourceSegmentLength -= pageLength;
                    targetSegment       += pageLength;
                    targetSegmentLength -= pageLength;
                    withLength          -= pageLength;
                }

                bcopy_phys_safe( /* from */ (char *) sourceSegment, 
                                 /* to   */ (char *) targetSegment,
                                 /* size */ (int   ) sourceSegmentLength );

                // We flush the data cache in case it is code we've copied,
                // such that the instruction cache is in the know about it.

                flush_dcache(targetSegment, sourceSegmentLength, true);

                ((UInt8 *) bytes)   += sourceSegmentLength;
                bytesCopied         += sourceSegmentLength;
                offset              += sourceSegmentLength;
                targetSegment       += sourceSegmentLength;
                targetSegmentLength -= sourceSegmentLength;
                withLength          -= sourceSegmentLength;
            }
        }
    }

writeBytesErr:

    return bytesCopied;
}

/* DEPRECATED */ void IOGeneralMemoryDescriptor::setPosition(IOByteCount position)
/* DEPRECATED */ {
/* DEPRECATED */     assert(position <= _length);
/* DEPRECATED */ 
/* DEPRECATED */     if (position >= _length)
/* DEPRECATED */     {
/* DEPRECATED */         _position         = _length;
/* DEPRECATED */         _positionAtIndex  = _rangesCount; /* careful: out-of-bounds */
/* DEPRECATED */         _positionAtOffset = 0;
/* DEPRECATED */         return;
/* DEPRECATED */     }
/* DEPRECATED */ 
/* DEPRECATED */     if (position < _position)
/* DEPRECATED */     {
/* DEPRECATED */ 	_positionAtOffset = position;
/* DEPRECATED */ 	_positionAtIndex  = 0;
/* DEPRECATED */     }
/* DEPRECATED */     else
/* DEPRECATED */     {
/* DEPRECATED */ 	_positionAtOffset += (position - _position);
/* DEPRECATED */     }
/* DEPRECATED */     _position = position;
/* DEPRECATED */ 
/* DEPRECATED */     while (_positionAtOffset >= _ranges.v[_positionAtIndex].length)
/* DEPRECATED */     {
/* DEPRECATED */         _positionAtOffset -= _ranges.v[_positionAtIndex].length;
/* DEPRECATED */         _positionAtIndex++;
/* DEPRECATED */     }
/* DEPRECATED */ }

IOPhysicalAddress IOGeneralMemoryDescriptor::getPhysicalSegment( IOByteCount   offset,
                                                                 IOByteCount * lengthOfSegment )
{
    IOPhysicalAddress address = 0;
    IOPhysicalLength  length  = 0;


//    assert(offset <= _length);

    if ( offset < _length ) // (within bounds?)
    {
        unsigned rangesIndex = 0;

        for ( ; offset >= _ranges.v[rangesIndex].length; rangesIndex++ )
        {
            offset -= _ranges.v[rangesIndex].length; // (make offset relative)
        }

        if ( _task == 0 ) // (physical memory?)
        {
            address = _ranges.v[rangesIndex].address + offset;
            length  = _ranges.v[rangesIndex].length  - offset;

            for ( ++rangesIndex; rangesIndex < _rangesCount; rangesIndex++ )
            {
                if ( address + length != _ranges.v[rangesIndex].address )  break;

                length += _ranges.v[rangesIndex].length; // (coalesce ranges)
            }
        }
        else // (virtual memory?)
        {
            vm_address_t addressVirtual = _ranges.v[rangesIndex].address + offset;

            assert((0 == (kIOMemoryRequiresWire & _flags)) || _wireCount);

            address = pmap_extract_safe(_task, addressVirtual);
            length  = next_page(addressVirtual) - addressVirtual;
            length  = min(_ranges.v[rangesIndex].length - offset, length);
        }

        assert(address);
        if ( address == 0 )  length = 0;
    }

    if ( lengthOfSegment )  *lengthOfSegment = length;

    return address;
}

IOPhysicalAddress IOGeneralMemoryDescriptor::getSourceSegment( IOByteCount   offset,
                                                               IOByteCount * lengthOfSegment )
{
    IOPhysicalAddress address = 0;
    IOPhysicalLength  length  = 0;

    assert(offset <= _length);

    if ( offset < _length ) // (within bounds?)
    {
        unsigned rangesIndex = 0;

        for ( ; offset >= _ranges.v[rangesIndex].length; rangesIndex++ )
        {
            offset -= _ranges.v[rangesIndex].length; // (make offset relative)
        }

        address = _ranges.v[rangesIndex].address + offset;
        length  = _ranges.v[rangesIndex].length  - offset;

        for ( ++rangesIndex; rangesIndex < _rangesCount; rangesIndex++ )
        {
            if ( address + length != _ranges.v[rangesIndex].address )  break;

            length += _ranges.v[rangesIndex].length; // (coalesce ranges)
        }

        assert(address);
        if ( address == 0 )  length = 0;
    }

    if ( lengthOfSegment )  *lengthOfSegment = length;

    return address;
}

/* DEPRECATED */ /* USE INSTEAD: map(), readBytes(), writeBytes() */
/* DEPRECATED */ void * IOGeneralMemoryDescriptor::getVirtualSegment(IOByteCount offset,
/* DEPRECATED */ 							IOByteCount * lengthOfSegment)
/* DEPRECATED */ {
/* DEPRECATED */     if( offset != _position)
/* DEPRECATED */ 	setPosition( offset );
/* DEPRECATED */ 
/* DEPRECATED */     assert(_position <= _length);
/* DEPRECATED */ 
/* DEPRECATED */     /* Fail gracefully if the position is at (or past) the end-of-buffer. */
/* DEPRECATED */     if (_position >= _length)
/* DEPRECATED */     {
/* DEPRECATED */         *lengthOfSegment = 0;
/* DEPRECATED */         return 0;
/* DEPRECATED */     }
/* DEPRECATED */ 
/* DEPRECATED */     /* Compute the relative length to the end of this virtual segment. */
/* DEPRECATED */     *lengthOfSegment = _ranges.v[_positionAtIndex].length - _positionAtOffset;
/* DEPRECATED */ 
/* DEPRECATED */     /* Compute the relative address of this virtual segment. */
/* DEPRECATED */     if (_task == kernel_task)
/* DEPRECATED */         return (void *)(_ranges.v[_positionAtIndex].address + _positionAtOffset);
/* DEPRECATED */     else
/* DEPRECATED */     {
/* DEPRECATED */ 	vm_offset_t off;
/* DEPRECATED */ 
/* DEPRECATED */         mapIntoKernel(_positionAtIndex);
/* DEPRECATED */ 
/* DEPRECATED */ 	off  = _ranges.v[_kernPtrAtIndex].address;
/* DEPRECATED */ 	off -= trunc_page(off);
/* DEPRECATED */ 
/* DEPRECATED */ 	return (void *) (_kernPtrAligned + off + _positionAtOffset);
/* DEPRECATED */     }
/* DEPRECATED */ }
/* DEPRECATED */ /* USE INSTEAD: map(), readBytes(), writeBytes() */

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

        vm_prot_t access;

        switch (forDirection)
        {
            case kIODirectionIn:
                access = VM_PROT_WRITE;
                break;

            case kIODirectionOut:
                access = VM_PROT_READ;
                break;

            default:
                access = VM_PROT_READ | VM_PROT_WRITE;
                break;
        }

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

            rc = vm_map_wire(taskVMMap, srcAlign, srcAlignEnd, access, FALSE);
	    if (KERN_SUCCESS != rc) {
		IOLog("IOMemoryDescriptor::prepare vm_map_wire failed: %d\n", rc);
		goto abortExit;
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
    ipc_port_t sharedMem = (ipc_port_t) _memEntry;

    // mapping source == dest? (could be much better)
    if( _task && (addressMap == get_task_map(_task)) && (options & kIOMapAnywhere)
	&& (1 == _rangesCount) && (0 == sourceOffset)
	&& (length <= _ranges.v[0].length) ) {
	    *atAddress = _ranges.v[0].address;
	    return( kIOReturnSuccess );
    }

    if( 0 == sharedMem) {

        vm_size_t size = 0;

        for (unsigned index = 0; index < _rangesCount; index++)
            size += round_page(_ranges.v[index].address + _ranges.v[index].length)
                  - trunc_page(_ranges.v[index].address);

        if( _task) {
#if NOTYET
            vm_object_offset_t actualSize = size;
            kr = mach_make_memory_entry_64( get_task_map(_task),
                        &actualSize, _ranges.v[0].address,
                        VM_PROT_READ | VM_PROT_WRITE, &sharedMem,
                        NULL );

            if( (KERN_SUCCESS == kr) && (actualSize != size)) {
#if IOASSERT
                IOLog("mach_make_memory_entry_64 (%08lx) size (%08lx:%08lx)\n",
                            _ranges.v[0].address, (UInt32)actualSize, size);
#endif
                kr = kIOReturnVMError;
                ipc_port_release_send( sharedMem );
            }

            if( KERN_SUCCESS != kr)
#endif /* NOTYET */
                sharedMem = MACH_PORT_NULL;

        } else do {

            memory_object_t pager;

            if( !reserved) {
                reserved = IONew( ExpansionData, 1 );
                if( !reserved)
                    continue;
            }
            reserved->pagerContig = (1 == _rangesCount);

            pager = device_pager_setup( (memory_object_t) 0, (int) this, size, 
                            reserved->pagerContig ? DEVICE_PAGER_CONTIGUOUS : 0 );
            assert( pager );

            if( pager) {
                retain();	// pager has a ref
                kr = mach_memory_object_memory_entry_64( (host_t) 1, false /*internal*/, 
                            size, VM_PROT_READ | VM_PROT_WRITE, pager, &sharedMem );

                assert( KERN_SUCCESS == kr );
                if( KERN_SUCCESS != kr) {
// chris?
//                    ipc_port_release_send( (ipc_port_t) pager );
                    pager = MACH_PORT_NULL;
                    sharedMem = MACH_PORT_NULL;
                }
            }
            reserved->devicePager = pager;

        } while( false );

        _memEntry = (void *) sharedMem;
    }

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

struct IOMemoryDescriptorMapAllocRef
{
    ipc_port_t		sharedMem;
    vm_size_t		size;
    vm_offset_t		mapped;
    IOByteCount		sourceOffset;
    IOOptionBits	options;
};

static kern_return_t IOMemoryDescriptorMapAlloc(vm_map_t map, void * _ref)
{
    IOMemoryDescriptorMapAllocRef * ref = (IOMemoryDescriptorMapAllocRef *)_ref;
    IOReturn			    err;

    do {
        if( ref->sharedMem) {
            vm_prot_t prot = VM_PROT_READ
                            | ((ref->options & kIOMapReadOnly) ? 0 : VM_PROT_WRITE);
    
            err = vm_map( map,
                            &ref->mapped,
                            ref->size, 0 /* mask */, 
                            (( ref->options & kIOMapAnywhere ) ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
                            | VM_MAKE_TAG(VM_MEMORY_IOKIT), 
                            ref->sharedMem, ref->sourceOffset,
                            false, // copy
                            prot, // cur
                            prot, // max
                            VM_INHERIT_NONE);
    
            if( KERN_SUCCESS != err) {
                ref->mapped = 0;
                continue;
            }
    
        } else {
    
            err = vm_allocate( map, &ref->mapped, ref->size,
                            ((ref->options & kIOMapAnywhere) ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
                            | VM_MAKE_TAG(VM_MEMORY_IOKIT) );
    
            if( KERN_SUCCESS != err) {
                ref->mapped = 0;
                continue;
            }
    
            // we have to make sure that these guys don't get copied if we fork.
            err = vm_inherit( map, ref->mapped, ref->size, VM_INHERIT_NONE);
            assert( KERN_SUCCESS == err );
        }

    } while( false );

    return( err );
}

IOReturn IOMemoryDescriptor::doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset = 0,
	IOByteCount		length = 0 )
{
    IOReturn		err = kIOReturnSuccess;
    memory_object_t	pager;
    vm_address_t	logical;
    IOByteCount		pageOffset;
    IOPhysicalAddress	sourceAddr;
    IOMemoryDescriptorMapAllocRef	ref;

    ref.sharedMem	= (ipc_port_t) _memEntry;
    ref.sourceOffset	= sourceOffset;
    ref.options		= options;

    do {

        if( 0 == length)
            length = getLength();

        sourceAddr = getSourceSegment( sourceOffset, NULL );
        assert( sourceAddr );
        pageOffset = sourceAddr - trunc_page( sourceAddr );

        ref.size = round_page( length + pageOffset );

        logical = *atAddress;
        if( options & kIOMapAnywhere) 
            // vm_map looks for addresses above here, even when VM_FLAGS_ANYWHERE
            ref.mapped = 0;
        else {
            ref.mapped = trunc_page( logical );
            if( (logical - ref.mapped) != pageOffset) {
                err = kIOReturnVMError;
                continue;
            }
        }

        if( ref.sharedMem && (addressMap == kernel_map) && (kIOMemoryRequiresWire & _flags))
            err = IOIteratePageableMaps( ref.size, &IOMemoryDescriptorMapAlloc, &ref );
        else
            err = IOMemoryDescriptorMapAlloc( addressMap, &ref );

        if( err != KERN_SUCCESS)
            continue;

        if( reserved)
            pager = (memory_object_t) reserved->devicePager;
        else
            pager = MACH_PORT_NULL;

        if( !ref.sharedMem || pager )
            err = handleFault( pager, addressMap, ref.mapped, sourceOffset, length, options );

    } while( false );

    if( err != KERN_SUCCESS) {
        if( ref.mapped)
            doUnmap( addressMap, ref.mapped, ref.size );
        *atAddress = NULL;
    } else
        *atAddress = ref.mapped + pageOffset;

    return( err );
}

enum {
    kIOMemoryRedirected	= 0x00010000
};

IOReturn IOMemoryDescriptor::handleFault(
        void *			_pager,
	vm_map_t		addressMap,
	IOVirtualAddress	address,
	IOByteCount		sourceOffset,
	IOByteCount		length,
        IOOptionBits		options )
{
    IOReturn		err = kIOReturnSuccess;
    memory_object_t	pager = (memory_object_t) _pager;
    vm_size_t		size;
    vm_size_t		bytes;
    vm_size_t		page;
    IOByteCount		pageOffset;
    IOPhysicalLength	segLen;
    IOPhysicalAddress	physAddr;

    if( !addressMap) {

        LOCK;

        if( kIOMemoryRedirected & _flags) {
#ifdef DEBUG
            IOLog("sleep mem redirect %x, %lx\n", address, sourceOffset);
#endif
            do {
                assert_wait( (event_t) this, THREAD_UNINT );
                UNLOCK;
                thread_block((void (*)(void)) 0);
                LOCK;
            } while( kIOMemoryRedirected & _flags );
        }

        UNLOCK;
        return( kIOReturnSuccess );
    }

    physAddr = getPhysicalSegment( sourceOffset, &segLen );
    assert( physAddr );
    pageOffset = physAddr - trunc_page( physAddr );

    size = length + pageOffset;
    physAddr -= pageOffset;

    segLen += pageOffset;
    bytes = size;
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
	    IOLog("_IOMemoryMap::map(%p) %08lx->%08lx:%08lx\n",
                addressMap, address + pageOffset, physAddr + pageOffset,
		segLen - pageOffset);
#endif

	if( addressMap && (kIOReturnSuccess == err))
            err = IOMapPages( addressMap, address, physAddr, segLen, options );
        assert( KERN_SUCCESS == err );
	if( err)
	    break;

        if( pager) {
            if( reserved && reserved->pagerContig) {
                IOPhysicalLength	allLen;
                IOPhysicalAddress	allPhys;

                allPhys = getPhysicalSegment( 0, &allLen );
                assert( allPhys );
                err = device_pager_populate_object( pager, 0, trunc_page(allPhys), round_page(allPhys + allLen) );

            } else {

                for( page = 0;
                     (page < segLen) && (KERN_SUCCESS == err);
                     page += page_size) {
                        err = device_pager_populate_object( pager, sourceOffset + page,
                                                            physAddr + page, page_size );
                }
            }
            assert( KERN_SUCCESS == err );
            if( err)
                break;
        }
	sourceOffset += segLen - pageOffset;
	address += segLen;
	bytes -= segLen;
	pageOffset = 0;

    } while( bytes
	&& (physAddr = getPhysicalSegment( sourceOffset, &segLen )));

    if( bytes)
        err = kIOReturnBadArgument;

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

    if( (addressMap == kernel_map) || (addressMap == get_task_map(current_task()))) {

        if( _memEntry && (addressMap == kernel_map) && (kIOMemoryRequiresWire & _flags))
            addressMap = IOPageableMapForAddress( logical );

        err = vm_deallocate( addressMap, logical, length );

    } else
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

    if( redirect)
        _flags |= kIOMemoryRedirected;
    else {
        _flags &= ~kIOMemoryRedirected;
        thread_wakeup( (event_t) this);
    }

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
                                     (options & ~kIOMapAnywhere) /*| kIOMapReserve*/,
                                     offset, length );
            } else
                err = kIOReturnSuccess;
#ifdef DEBUG
            IOLog("IOMemoryMap::redirect(%d, %x) %x from %p\n", redirect, err, logical, addressMap);
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

    if( reserved)
        IODelete( reserved, ExpansionData, 1 );

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

IOPhysicalAddress IOSubMemoryDescriptor::getSourceSegment( IOByteCount offset,
						      	   IOByteCount * length )
{
    IOPhysicalAddress	address;
    IOByteCount		actualLength;

    assert(offset <= _length);

    if( length)
        *length = 0;

    if( offset >= _length)
        return( 0 );

    address = _parent->getSourceSegment( offset + _start, &actualLength );

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
        mapping = (IOMemoryMap *) _parent->makeMapping(
					_parent, intoTask,
					toAddress,
					options, _start + offset, length );

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

OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 0);
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
