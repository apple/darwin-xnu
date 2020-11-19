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
#define IOKIT_ENABLE_SHARED_PTR

#define _IOMEMORYDESCRIPTOR_INTERNAL_

#include <IOKit/assert.h>
#include <IOKit/system.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <libkern/OSDebug.h>
#include <mach/mach_vm.h>

#include "IOKitKernelInternal.h"

#ifdef IOALLOCDEBUG
#include <libkern/c++/OSCPPDebug.h>
#endif
#include <IOKit/IOStatisticsPrivate.h>

#if IOKITSTATS
#define IOStatisticsAlloc(type, size) \
do { \
	IOStatistics::countAlloc(type, size); \
} while (0)
#else
#define IOStatisticsAlloc(type, size)
#endif /* IOKITSTATS */


__BEGIN_DECLS
void ipc_port_release_send(ipc_port_t port);
#include <vm/pmap.h>

__END_DECLS

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

enum{
	kInternalFlagPhysical      = 0x00000001,
	kInternalFlagPageSized     = 0x00000002,
	kInternalFlagPageAllocated = 0x00000004,
	kInternalFlagInit          = 0x00000008
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOGeneralMemoryDescriptor
OSDefineMetaClassAndStructorsWithZone(IOBufferMemoryDescriptor,
    IOGeneralMemoryDescriptor, ZC_ZFREE_CLEARMEM);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static uintptr_t
IOBMDPageProc(iopa_t * a)
{
	kern_return_t kr;
	vm_address_t  vmaddr  = 0;
	int           options = 0;// KMA_LOMEM;

	kr = kernel_memory_allocate(kernel_map, &vmaddr,
	    page_size, 0, options, VM_KERN_MEMORY_IOKIT);

	if (KERN_SUCCESS != kr) {
		vmaddr = 0;
	} else {
		bzero((void *) vmaddr, page_size);
	}

	return (uintptr_t) vmaddr;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef __LP64__
bool
IOBufferMemoryDescriptor::initWithOptions(
	IOOptionBits options,
	vm_size_t    capacity,
	vm_offset_t  alignment,
	task_t       inTask)
{
	mach_vm_address_t physicalMask = 0;
	return initWithPhysicalMask(inTask, options, capacity, alignment, physicalMask);
}
#endif /* !__LP64__ */

OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::withCopy(
	task_t                inTask,
	IOOptionBits      options,
	vm_map_t              sourceMap,
	mach_vm_address_t source,
	mach_vm_size_t    size)
{
	OSSharedPtr<IOBufferMemoryDescriptor> inst;
	kern_return_t              err;
	vm_map_copy_t              copy;
	vm_map_address_t           address;

	copy = NULL;
	do {
		err = kIOReturnNoMemory;
		inst = OSMakeShared<IOBufferMemoryDescriptor>();
		if (!inst) {
			break;
		}
		inst->_ranges.v64 = IONew(IOAddressRange, 1);
		if (!inst->_ranges.v64) {
			break;
		}

		err = vm_map_copyin(sourceMap, source, size,
		    false /* src_destroy */, &copy);
		if (KERN_SUCCESS != err) {
			break;
		}

		err = vm_map_copyout(get_task_map(inTask), &address, copy);
		if (KERN_SUCCESS != err) {
			break;
		}
		copy = NULL;

		inst->_ranges.v64->address = address;
		inst->_ranges.v64->length  = size;

		if (!inst->initWithPhysicalMask(inTask, options, size, page_size, 0)) {
			err = kIOReturnError;
		}
	} while (false);

	if (KERN_SUCCESS == err) {
		return inst;
	}

	if (copy) {
		vm_map_copy_discard(copy);
	}

	return nullptr;
}


bool
IOBufferMemoryDescriptor::initWithPhysicalMask(
	task_t            inTask,
	IOOptionBits      options,
	mach_vm_size_t    capacity,
	mach_vm_address_t alignment,
	mach_vm_address_t physicalMask)
{
	task_t                mapTask = NULL;
	vm_map_t              vmmap = NULL;
	mach_vm_address_t     highestMask = 0;
	IOOptionBits          iomdOptions = kIOMemoryTypeVirtual64 | kIOMemoryAsReference;
	IODMAMapSpecification mapSpec;
	bool                  mapped = false;
	bool                  withCopy = false;
	bool                  mappedOrShared = false;

	if (!capacity) {
		return false;
	}

	_options          = options;
	_capacity         = capacity;
	_internalFlags    = 0;
	_internalReserved = 0;
	_buffer           = NULL;

	if (!_ranges.v64) {
		_ranges.v64 = IONew(IOAddressRange, 1);
		if (!_ranges.v64) {
			return false;
		}
		_ranges.v64->address = 0;
		_ranges.v64->length  = 0;
	} else {
		if (!_ranges.v64->address) {
			return false;
		}
		if (!(kIOMemoryPageable & options)) {
			return false;
		}
		if (!inTask) {
			return false;
		}
		_buffer = (void *) _ranges.v64->address;
		withCopy = true;
	}
	//  make sure super::free doesn't dealloc _ranges before super::init
	_flags = kIOMemoryAsReference;

	// Grab IOMD bits from the Buffer MD options
	iomdOptions  |= (options & kIOBufferDescriptorMemoryFlags);

	if (!(kIOMemoryMapperNone & options)) {
		IOMapper::checkForSystemMapper();
		mapped = (NULL != IOMapper::gSystem);
	}

	if (physicalMask && (alignment <= 1)) {
		alignment   = ((physicalMask ^ (-1ULL)) & (physicalMask - 1));
		highestMask = (physicalMask | alignment);
		alignment++;
		if (alignment < page_size) {
			alignment = page_size;
		}
	}

	if ((options & (kIOMemorySharingTypeMask | kIOMapCacheMask | kIOMemoryClearEncrypt)) && (alignment < page_size)) {
		alignment = page_size;
	}

	if (alignment >= page_size) {
		if (round_page_overflow(capacity, &capacity)) {
			return false;
		}
	}

	if (alignment > page_size) {
		options |= kIOMemoryPhysicallyContiguous;
	}

	_alignment = alignment;

	if ((capacity + alignment) < _capacity) {
		return false;
	}

	if ((inTask != kernel_task) && !(options & kIOMemoryPageable)) {
		return false;
	}

	bzero(&mapSpec, sizeof(mapSpec));
	mapSpec.alignment      = _alignment;
	mapSpec.numAddressBits = 64;
	if (highestMask && mapped) {
		if (highestMask <= 0xFFFFFFFF) {
			mapSpec.numAddressBits = (uint8_t)(32 - __builtin_clz((unsigned int) highestMask));
		} else {
			mapSpec.numAddressBits = (uint8_t)(64 - __builtin_clz((unsigned int) (highestMask >> 32)));
		}
		highestMask = 0;
	}

	// set memory entry cache mode, pageable, purgeable
	iomdOptions |= ((options & kIOMapCacheMask) >> kIOMapCacheShift) << kIOMemoryBufferCacheShift;
	if (options & kIOMemoryPageable) {
		iomdOptions |= kIOMemoryBufferPageable;
		if (options & kIOMemoryPurgeable) {
			iomdOptions |= kIOMemoryBufferPurgeable;
		}
	} else {
		vmmap = kernel_map;

		// Buffer shouldn't auto prepare they should be prepared explicitly
		// But it never was enforced so what are you going to do?
		iomdOptions |= kIOMemoryAutoPrepare;

		/* Allocate a wired-down buffer inside kernel space. */

		bool contig = (0 != (options & kIOMemoryHostPhysicallyContiguous));

		if (!contig && (0 != (options & kIOMemoryPhysicallyContiguous))) {
			contig |= (!mapped);
			contig |= (0 != (kIOMemoryMapperNone & options));
#if 0
			// treat kIOMemoryPhysicallyContiguous as kIOMemoryHostPhysicallyContiguous for now
			contig |= true;
#endif
		}

		mappedOrShared = (mapped || (0 != (kIOMemorySharingTypeMask & options)));
		if (contig || highestMask || (alignment > page_size)) {
			_internalFlags |= kInternalFlagPhysical;
			if (highestMask) {
				_internalFlags |= kInternalFlagPageSized;
				if (round_page_overflow(capacity, &capacity)) {
					return false;
				}
			}
			_buffer = (void *) IOKernelAllocateWithPhysicalRestrict(
				capacity, highestMask, alignment, contig);
		} else if (mappedOrShared
		    && (capacity + alignment) <= (page_size - gIOPageAllocChunkBytes)) {
			_internalFlags |= kInternalFlagPageAllocated;
			_buffer         = (void *) iopa_alloc(&gIOBMDPageAllocator, &IOBMDPageProc, capacity, alignment);
			if (_buffer) {
				IOStatisticsAlloc(kIOStatisticsMallocAligned, capacity);
#if IOALLOCDEBUG
				OSAddAtomicLong(capacity, &debug_iomalloc_size);
#endif
			}
		} else if (alignment > 1) {
			_buffer = IOMallocAligned(capacity, alignment);
		} else {
			_buffer = IOMalloc(capacity);
		}
		if (!_buffer) {
			return false;
		}
		bzero(_buffer, capacity);
	}

	if ((options & (kIOMemoryPageable | kIOMapCacheMask))) {
		vm_size_t       size = round_page(capacity);

		// initWithOptions will create memory entry
		if (!withCopy) {
			iomdOptions |= kIOMemoryPersistent;
		}

		if (options & kIOMemoryPageable) {
#if IOALLOCDEBUG
			OSAddAtomicLong(size, &debug_iomallocpageable_size);
#endif
			if (!withCopy) {
				mapTask = inTask;
			}
			if (NULL == inTask) {
				inTask = kernel_task;
			}
		} else if (options & kIOMapCacheMask) {
			// Prefetch each page to put entries into the pmap
			volatile UInt8 *    startAddr = (UInt8 *)_buffer;
			volatile UInt8 *    endAddr   = (UInt8 *)_buffer + capacity;

			while (startAddr < endAddr) {
				UInt8 dummyVar = *startAddr;
				(void) dummyVar;
				startAddr += page_size;
			}
		}
	}

	_ranges.v64->address = (mach_vm_address_t) _buffer;
	_ranges.v64->length  = _capacity;

	if (!super::initWithOptions(_ranges.v64, 1, 0,
	    inTask, iomdOptions, /* System mapper */ NULL)) {
		return false;
	}

	_internalFlags |= kInternalFlagInit;
#if IOTRACKING
	if (!(options & kIOMemoryPageable)) {
		trackingAccumSize(capacity);
	}
#endif /* IOTRACKING */

	// give any system mapper the allocation params
	if (kIOReturnSuccess != dmaCommandOperation(kIOMDAddDMAMapSpec,
	    &mapSpec, sizeof(mapSpec))) {
		return false;
	}

	if (mapTask) {
		if (!reserved) {
			reserved = IONew( ExpansionData, 1 );
			if (!reserved) {
				return false;
			}
		}
		reserved->map = createMappingInTask(mapTask, 0,
		    kIOMapAnywhere | (options & kIOMapPrefault) | (options & kIOMapCacheMask), 0, 0).detach();
		if (!reserved->map) {
			_buffer = NULL;
			return false;
		}
		release();  // map took a retain on this
		reserved->map->retain();
		removeMapping(reserved->map);
		mach_vm_address_t buffer = reserved->map->getAddress();
		_buffer = (void *) buffer;
		if (kIOMemoryTypeVirtual64 == (kIOMemoryTypeMask & iomdOptions)) {
			_ranges.v64->address = buffer;
		}
	}

	setLength(_capacity);

	return true;
}

OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::inTaskWithOptions(
	task_t       inTask,
	IOOptionBits options,
	vm_size_t    capacity,
	vm_offset_t  alignment)
{
	OSSharedPtr<IOBufferMemoryDescriptor> me = OSMakeShared<IOBufferMemoryDescriptor>();

	if (me && !me->initWithPhysicalMask(inTask, options, capacity, alignment, 0)) {
		me.reset();
	}
	return me;
}

OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::inTaskWithOptions(
	task_t       inTask,
	IOOptionBits options,
	vm_size_t    capacity,
	vm_offset_t  alignment,
	uint32_t     kernTag,
	uint32_t     userTag)
{
	OSSharedPtr<IOBufferMemoryDescriptor> me = OSMakeShared<IOBufferMemoryDescriptor>();

	if (me) {
		me->setVMTags(kernTag, userTag);

		if (!me->initWithPhysicalMask(inTask, options, capacity, alignment, 0)) {
			me.reset();
		}
	}
	return me;
}

OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
	task_t            inTask,
	IOOptionBits      options,
	mach_vm_size_t    capacity,
	mach_vm_address_t physicalMask)
{
	OSSharedPtr<IOBufferMemoryDescriptor> me = OSMakeShared<IOBufferMemoryDescriptor>();

	if (me && !me->initWithPhysicalMask(inTask, options, capacity, 1, physicalMask)) {
		me.reset();
	}
	return me;
}

#ifndef __LP64__
bool
IOBufferMemoryDescriptor::initWithOptions(
	IOOptionBits options,
	vm_size_t    capacity,
	vm_offset_t  alignment)
{
	return initWithPhysicalMask(kernel_task, options, capacity, alignment, (mach_vm_address_t)0);
}
#endif /* !__LP64__ */

OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::withOptions(
	IOOptionBits options,
	vm_size_t    capacity,
	vm_offset_t  alignment)
{
	OSSharedPtr<IOBufferMemoryDescriptor> me = OSMakeShared<IOBufferMemoryDescriptor>();

	if (me && !me->initWithPhysicalMask(kernel_task, options, capacity, alignment, 0)) {
		me.reset();
	}
	return me;
}


/*
 * withCapacity:
 *
 * Returns a new IOBufferMemoryDescriptor with a buffer large enough to
 * hold capacity bytes.  The descriptor's length is initially set to the capacity.
 */
OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::withCapacity(vm_size_t   inCapacity,
    IODirection inDirection,
    bool        inContiguous)
{
	return IOBufferMemoryDescriptor::withOptions(
		inDirection | kIOMemoryUnshared
		| (inContiguous ? kIOMemoryPhysicallyContiguous : 0),
		inCapacity, inContiguous ? inCapacity : 1 );
}

#ifndef __LP64__
/*
 * initWithBytes:
 *
 * Initialize a new IOBufferMemoryDescriptor preloaded with bytes (copied).
 * The descriptor's length and capacity are set to the input buffer's size.
 */
bool
IOBufferMemoryDescriptor::initWithBytes(const void * inBytes,
    vm_size_t    inLength,
    IODirection  inDirection,
    bool         inContiguous)
{
	if (!initWithPhysicalMask(kernel_task, inDirection | kIOMemoryUnshared
	    | (inContiguous ? kIOMemoryPhysicallyContiguous : 0),
	    inLength, inLength, (mach_vm_address_t)0)) {
		return false;
	}

	// start out with no data
	setLength(0);

	if (!appendBytes(inBytes, inLength)) {
		return false;
	}

	return true;
}
#endif /* !__LP64__ */

/*
 * withBytes:
 *
 * Returns a new IOBufferMemoryDescriptor preloaded with bytes (copied).
 * The descriptor's length and capacity are set to the input buffer's size.
 */
OSSharedPtr<IOBufferMemoryDescriptor>
IOBufferMemoryDescriptor::withBytes(const void * inBytes,
    vm_size_t    inLength,
    IODirection  inDirection,
    bool         inContiguous)
{
	OSSharedPtr<IOBufferMemoryDescriptor> me = OSMakeShared<IOBufferMemoryDescriptor>();

	if (me && !me->initWithPhysicalMask(
		    kernel_task, inDirection | kIOMemoryUnshared
		    | (inContiguous ? kIOMemoryPhysicallyContiguous : 0),
		    inLength, inLength, 0 )) {
		me.reset();
	}

	if (me) {
		// start out with no data
		me->setLength(0);

		if (!me->appendBytes(inBytes, inLength)) {
			me.reset();
		}
	}
	return me;
}

/*
 * free:
 *
 * Free resources
 */
void
IOBufferMemoryDescriptor::free()
{
	// Cache all of the relevant information on the stack for use
	// after we call super::free()!
	IOOptionBits     flags         = _flags;
	IOOptionBits     internalFlags = _internalFlags;
	IOOptionBits     options   = _options;
	vm_size_t        size      = _capacity;
	void *           buffer    = _buffer;
	IOMemoryMap *    map       = NULL;
	IOAddressRange * range     = _ranges.v64;
	vm_offset_t      alignment = _alignment;

	if (alignment >= page_size) {
		size = round_page(size);
	}

	if (reserved) {
		map = reserved->map;
		IODelete( reserved, ExpansionData, 1 );
		if (map) {
			map->release();
		}
	}

	if ((options & kIOMemoryPageable)
	    || (kInternalFlagPageSized & internalFlags)) {
		size = round_page(size);
	}

#if IOTRACKING
	if (!(options & kIOMemoryPageable)
	    && buffer
	    && (kInternalFlagInit & _internalFlags)) {
		trackingAccumSize(-size);
	}
#endif /* IOTRACKING */

	/* super::free may unwire - deallocate buffer afterwards */
	super::free();

	if (options & kIOMemoryPageable) {
#if IOALLOCDEBUG
		OSAddAtomicLong(-size, &debug_iomallocpageable_size);
#endif
	} else if (buffer) {
		if (kInternalFlagPhysical & internalFlags) {
			IOKernelFreePhysical((mach_vm_address_t) buffer, size);
		} else if (kInternalFlagPageAllocated & internalFlags) {
			uintptr_t page;
			page = iopa_free(&gIOBMDPageAllocator, (uintptr_t) buffer, size);
			if (page) {
				kmem_free(kernel_map, page, page_size);
			}
#if IOALLOCDEBUG
			OSAddAtomicLong(-size, &debug_iomalloc_size);
#endif
			IOStatisticsAlloc(kIOStatisticsFreeAligned, size);
		} else if (alignment > 1) {
			IOFreeAligned(buffer, size);
		} else {
			IOFree(buffer, size);
		}
	}
	if (range && (kIOMemoryAsReference & flags)) {
		IODelete(range, IOAddressRange, 1);
	}
}

/*
 * getCapacity:
 *
 * Get the buffer capacity
 */
vm_size_t
IOBufferMemoryDescriptor::getCapacity() const
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
void
IOBufferMemoryDescriptor::setLength(vm_size_t length)
{
	assert(length <= _capacity);
	if (length > _capacity) {
		return;
	}

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
void
IOBufferMemoryDescriptor::setDirection(IODirection direction)
{
	_flags = (_flags & ~kIOMemoryDirectionMask) | direction;
#ifndef __LP64__
	_direction = (IODirection) (_flags & kIOMemoryDirectionMask);
#endif /* !__LP64__ */
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

	if (_task == kernel_task) {
		bcopy(/* from */ bytes, (void *)(_ranges.v64->address + offset),
		    actualBytesToCopy);
	} else {
		writeBytes(offset, bytes, actualBytesToCopy);
	}

	return true;
}

/*
 * getBytesNoCopy:
 *
 * Return the virtual address of the beginning of the buffer
 */
void *
IOBufferMemoryDescriptor::getBytesNoCopy()
{
	if (kIOMemoryTypePhysical64 == (_flags & kIOMemoryTypeMask)) {
		return _buffer;
	} else {
		return (void *)_ranges.v64->address;
	}
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

	if ((start + withLength) < start) {
		return NULL;
	}

	if (kIOMemoryTypePhysical64 == (_flags & kIOMemoryTypeMask)) {
		address = (IOVirtualAddress) _buffer;
	} else {
		address = _ranges.v64->address;
	}

	if (start < _length && (start + withLength) <= _length) {
		return (void *)(address + start);
	}
	return NULL;
}

#ifndef __LP64__
void *
IOBufferMemoryDescriptor::getVirtualSegment(IOByteCount offset,
    IOByteCount * lengthOfSegment)
{
	void * bytes = getBytesNoCopy(offset, 0);

	if (bytes && lengthOfSegment) {
		*lengthOfSegment = _length - offset;
	}

	return bytes;
}
#endif /* !__LP64__ */

#ifdef __LP64__
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 0);
OSMetaClassDefineReservedUnused(IOBufferMemoryDescriptor, 1);
#else /* !__LP64__ */
OSMetaClassDefineReservedUsedX86(IOBufferMemoryDescriptor, 0);
OSMetaClassDefineReservedUsedX86(IOBufferMemoryDescriptor, 1);
#endif /* !__LP64__ */
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
