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
#ifndef _IOMEMORYDESCRIPTOR_H
#define _IOMEMORYDESCRIPTOR_H

#include <IOKit/IOTypes.h>
#include <libkern/c++/OSContainers.h>

struct IOPhysicalRange
{
    IOPhysicalAddress	address;
    IOByteCount		length;
};

class IOMemoryMap;

/*
 * Direction of transfer, with respect to the described memory.
 */
enum IODirection
{
    kIODirectionNone  = 0x0,	//                    same as VM_PROT_NONE
    kIODirectionIn    = 0x1,	// User land 'read',  same as VM_PROT_READ
    kIODirectionOut   = 0x2,	// User land 'write', same as VM_PROT_WRITE
    kIODirectionOutIn = kIODirectionIn | kIODirectionOut,
};

/*! @class IOMemoryDescriptor : public OSObject
    @abstract An abstract base class defining common methods for describing physical or virtual memory.
    @discussion The IOMemoryDescriptor object represents a buffer or range of memory, specified as one or more physical or virtual address ranges. It contains methods to return the memory's physically contiguous segments (fragments), for use with the IOMemoryCursor, and methods to map the memory into any address space with caching and placed mapping options. */

class IOMemoryDescriptor : public OSObject
{
    friend class _IOMemoryMap;
    friend class IOSubMemoryDescriptor;

    OSDeclareDefaultStructors(IOMemoryDescriptor);

protected:
/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of this class in the future.
    */    
    struct ExpansionData { };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

protected:
    OSSet *		_mappings;
    IOOptionBits 	_flags;
    void *		_memEntry;

    IODirection         _direction;        /* direction of transfer */
    IOByteCount         _length;           /* length of all ranges */
    IOOptionBits 	_tag;

private:
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 0);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 1);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 2);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 3);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 4);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 5);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 6);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 7);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 8);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 9);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 10);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 11);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 12);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 13);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 14);
    OSMetaClassDeclareReservedUnused(IOMemoryDescriptor, 15);

protected:
    virtual void free();
public:
    static void initialize( void );

public:
/*! @function withAddress
    @abstract Create an IOMemoryDescriptor to describe one virtual range of the kernel task.
    @discussion This method creates and initializes an IOMemoryDescriptor for memory consisting of a single virtual memory range mapped into the kernel map.
    @param address The virtual address of the first byte in the memory.
    @param withLength The length of memory.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor * withAddress(void *       address,
                                            IOByteCount  withLength,
                                            IODirection  withDirection);

/*! @function withAddress
    @abstract Create an IOMemoryDescriptor to describe one virtual range of the specified map.
    @discussion This method creates and initializes an IOMemoryDescriptor for memory consisting of a single virtual memory range mapped into the specified map.
    @param address The virtual address of the first byte in the memory.
    @param withLength The length of memory.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param withTask The task the virtual ranges are mapped into.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor * withAddress(vm_address_t address,
                                            IOByteCount  withLength,
                                            IODirection  withDirection,
                                            task_t       withTask);

/*! @function withPhysicalAddress
    @abstract Create an IOMemoryDescriptor to describe one physical range.
    @discussion This method creates and initializes an IOMemoryDescriptor for memory consisting of a single physical memory range.
    @param address The physical address of the first byte in the memory.
    @param withLength The length of memory.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor * withPhysicalAddress(
				IOPhysicalAddress	address,
				IOByteCount		withLength,
				IODirection      	withDirection );

/*! @function withRanges
    @abstract Create an IOMemoryDescriptor to describe one or more virtual ranges.
    @discussion This method creates and initializes an IOMemoryDescriptor for memory consisting of an array of virtual memory ranges each mapped into a specified source task.
    @param ranges An array of IOVirtualRange structures which specify the virtual ranges in the specified map which make up the memory to be described.
    @param withCount The member count of the ranges array.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param withTask The task each of the virtual ranges are mapped into.
    @param asReference If false, the IOMemoryDescriptor object will make a copy of the ranges array, otherwise, the array will be used in situ, avoiding an extra allocation.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

     static IOMemoryDescriptor * withRanges(IOVirtualRange *	ranges,
                                            UInt32		withCount,
                                            IODirection		withDirection,
                                            task_t            withTask,
                                            bool		asReference = false);

/*! @function withPhysicalRanges
    @abstract Create an IOMemoryDescriptor to describe one or more physical ranges.
    @discussion  This method creates and initializes an IOMemoryDescriptor for memory consisting of an array of physical memory ranges.
    @param ranges An array of IOPhysicalRange structures which specify the physical ranges which make up the memory to be described.
    @param withCount The member count of the ranges array.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param asReference If false, the IOMemoryDescriptor object will make a copy of the ranges array, otherwise, the array will be used in situ, avoiding an extra allocation.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor * withPhysicalRanges(
                                            IOPhysicalRange *	ranges,
                                            UInt32		withCount,
                                            IODirection		withDirection,
                                            bool		asReference = false);

/*! @function withSubRange
    @abstract Create an IOMemoryDescriptor to describe a subrange of an existing descriptor.
    @discussion  This method creates and initializes an IOMemoryDescriptor for memory consisting of a subrange of the specified memory descriptor. The parent memory descriptor is retained by the new descriptor.
    @param of The parent IOMemoryDescriptor of which a subrange is to be used for the new descriptor, which will be retained by the subrange IOMemoryDescriptor.
    @param offset A byte offset into the parent memory descriptor's memory.
    @param length The length of the subrange.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures. This is used over the direction of the parent descriptor.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor *	withSubRange(IOMemoryDescriptor *	of,
					     IOByteCount		offset,
					     IOByteCount		length,
                                             IODirection		withDirection);

/*! @function initWithAddress
    @abstract Initialize or reinitialize an IOMemoryDescriptor to describe one virtual range of the kernel task.
    @discussion This method initializes an IOMemoryDescriptor for memory consisting of a single virtual memory range mapped into the kernel map. An IOMemoryDescriptor can be re-used by calling initWithAddress or initWithRanges again on an existing instance -- note this behavior is not commonly supported in other IOKit classes, although it is supported here.
    @param address The virtual address of the first byte in the memory.
    @param withLength The length of memory.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @result true on success, false on failure. */

    virtual bool initWithAddress(void *       address,
                                 IOByteCount  withLength,
                                 IODirection  withDirection) = 0;

/*! @function initWithAddress
    @abstract Initialize or reinitialize an IOMemoryDescriptor to describe one virtual range of the specified map.
    @discussion This method initializes an IOMemoryDescriptor for memory consisting of a single virtual memory range mapped into the specified map. An IOMemoryDescriptor can be re-used by calling initWithAddress or initWithRanges again on an existing instance -- note this behavior is not commonly supported in other IOKit classes, although it is supported here.
    @param address The virtual address of the first byte in the memory.
    @param withLength The length of memory.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param withTask The task the virtual ranges are mapped into.
    @result true on success, false on failure. */

    virtual bool initWithAddress(vm_address_t address,
                                 IOByteCount  withLength,
                                 IODirection  withDirection,
                                 task_t       withTask) = 0;

/*! @function initWithPhysicalAddress
    @abstract Initialize or reinitialize an IOMemoryDescriptor to describe one physical range.
    @discussion This method initializes an IOMemoryDescriptor for memory consisting of a single physical memory range. An IOMemoryDescriptor can be re-used by calling initWithAddress or initWithRanges again on an existing instance -- note this behavior is not commonly supported in other IOKit classes, although it is supported here.
    @param address The physical address of the first byte in the memory.
    @param withLength The length of memory.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @result true on success, false on failure. */

    virtual bool initWithPhysicalAddress(
				 IOPhysicalAddress	address,
				 IOByteCount		withLength,
				 IODirection      	withDirection ) = 0;

/*! @function initWithRanges
    @abstract Initialize or reinitialize an IOMemoryDescriptor to describe one or more virtual ranges.
    @discussion This method initializes an IOMemoryDescriptor for memory consisting of an array of virtual memory ranges each mapped into a specified source task. An IOMemoryDescriptor can be re-used by calling initWithAddress or initWithRanges again on an existing instance -- note this behavior is not commonly supported in other IOKit classes, although it is supported here.
    @param ranges An array of IOVirtualRange structures which specify the virtual ranges in the specified map which make up the memory to be described.
    @param withCount The member count of the ranges array.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param withTask The task each of the virtual ranges are mapped into.
    @param asReference If false, the IOMemoryDescriptor object will make a copy of the ranges array, otherwise, the array will be used in situ, avoiding an extra allocation.
    @result true on success, false on failure. */

    virtual bool initWithRanges(        IOVirtualRange * ranges,
                                        UInt32           withCount,
                                        IODirection      withDirection,
                                        task_t           withTask,
                                        bool             asReference = false) = 0;

/*! @function initWithPhysicalRanges
    @abstract Initialize or reinitialize an IOMemoryDescriptor to describe one or more physical ranges.
    @discussion  This method initializes an IOMemoryDescriptor for memory consisting of an array of physical memory ranges. An IOMemoryDescriptor can be re-used by calling initWithAddress or initWithRanges again on an existing instance -- note this behavior is not commonly supported in other IOKit classes, although it is supported here.
    @param ranges An array of IOPhysicalRange structures which specify the physical ranges which make up the memory to be described.
    @param withCount The member count of the ranges array.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures.
    @param asReference If false, the IOMemoryDescriptor object will make a copy of the ranges array, otherwise, the array will be used in situ, avoiding an extra allocation.
    @result true on success, false on failure. */

    virtual bool initWithPhysicalRanges(IOPhysicalRange * ranges,
                                        UInt32           withCount,
                                        IODirection      withDirection,
                                        bool             asReference = false) = 0;

/*! @function getDirection
    @abstract Accessor to get the direction the memory descriptor was created with.
    @discussion This method returns the direction the memory descriptor was created with.
    @result The direction. */

    virtual IODirection getDirection() const;

/*! @function getLength
    @abstract Accessor to get the length of the memory descriptor (over all its ranges).
    @discussion This method returns the total length of the memory described by the descriptor, ie. the sum of its ranges' lengths.
    @result The byte count. */

    virtual IOByteCount getLength() const;

/*! @function setTag
    @abstract Set the tag for the memory descriptor.
    @discussion This method sets the tag for the memory descriptor. Tag bits are not interpreted by IOMemoryDescriptor.
    @param tag The tag. */

    virtual void setTag( IOOptionBits tag );

/*! @function getTag
    @abstract Accessor to the retrieve the tag for the memory descriptor.
    @discussion This method returns the tag for the memory descriptor. Tag bits are not interpreted by IOMemoryDescriptor.
    @result The tag. */

    virtual IOOptionBits getTag( void );

/*! @function readBytes
    @abstract Copy data from the memory descriptor's buffer to the specified buffer.
    @discussion This method copies data from the memory descriptor's memory at the given offset, to the caller's buffer.
    @param offset A byte offset into the memory descriptor's memory.
    @param bytes The caller supplied buffer to copy the data to.
    @param withLength The length of the data to copy.
    @result The number of bytes copied, zero will be returned if the specified offset is beyond the length of the descriptor. */

    virtual IOByteCount readBytes(IOByteCount offset,
				void * bytes, IOByteCount withLength) = 0;

/*! @function writeBytes
    @abstract Copy data to the memory descriptor's buffer from the specified buffer.
    @discussion This method copies data to the memory descriptor's memory at the given offset, from the caller's buffer.
    @param offset A byte offset into the memory descriptor's memory.
    @param bytes The caller supplied buffer to copy the data from.
    @param withLength The length of the data to copy.
    @result The number of bytes copied, zero will be returned if the specified offset is beyond the length of the descriptor. */

    virtual IOByteCount writeBytes(IOByteCount offset,
				const void * bytes, IOByteCount withLength) = 0;

/*! @function getPhysicalSegment
    @abstract Break a memory descriptor into its physically contiguous segments.
    @discussion This method returns the physical address of the byte at the given offset into the memory, and optionally the length of the physically contiguous segment from that offset.
    @param offset A byte offset into the memory whose physical address to return.
    @param length If non-zero, getPhysicalSegment will store here the length of the physically contiguous segement at the given offset.
    @result A physical address, or zero if the offset is beyond the length of the memory. */

    virtual IOPhysicalAddress getPhysicalSegment(IOByteCount offset,
						 IOByteCount * length) = 0;

/*! @function getPhysicalAddress
    @abstract Return the physical address of the first byte in the memory.
    @discussion This method returns the physical address of the  first byte in the memory. It is most useful on memory known to be physically contiguous.
    @result A physical address. */

    inline IOPhysicalAddress 	getPhysicalAddress()
				{ return( getPhysicalSegment( 0, 0 )); }

    /*
     * getVirtualSegment:
     *
     * Get the virtual address of the buffer, relative to the given offset.
     * If the memory wasn't mapped into the caller's address space, it will be
     * mapped in now.   If the current position is at the end of the buffer, a
     * null is returned.
     */
    virtual void * getVirtualSegment(IOByteCount offset,
					IOByteCount * length) = 0;

/*! @function prepare
    @abstract Prepare the memory for an I/O transfer.
    @discussion This involves paging in the memory, if necessary, and wiring it down for the duration of the transfer.  The complete() method completes the processing of the memory after the I/O transfer finishes.  This method needn't called for non-pageable memory.
    @param forDirection The direction of the I/O just completed, or kIODirectionNone for the direction specified by the memory descriptor.
    @result An IOReturn code. */

    virtual IOReturn prepare(IODirection forDirection = kIODirectionNone) = 0;

/*! @function complete
    @abstract Complete processing of the memory after an I/O transfer finishes.
    @discussion This method should not be called unless a prepare was previously issued; the prepare() and complete() must occur in pairs, before and after an I/O transfer involving pageable memory.
    @param forDirection The direction of the I/O just completed, or kIODirectionNone for the direction specified by the memory descriptor.
    @result An IOReturn code. */

    virtual IOReturn complete(IODirection forDirection = kIODirectionNone) = 0;

    /*
     * Mapping functions.
     */

/*! @function map
    @abstract Maps a IOMemoryDescriptor into a task.
    @discussion This is the general purpose method to map all or part of the memory described by a memory descriptor into a task at any available address, or at a fixed address if possible. Caching & read-only options may be set for the mapping. The mapping is represented as a returned reference to a IOMemoryMap object, which may be shared if the mapping is compatible with an existing mapping of the IOMemoryDescriptor. The IOMemoryMap object returned should be released only when the caller has finished accessing the mapping, as freeing the object destroys the mapping. 
    @param intoTask Sets the target task for the mapping. Pass kernel_task for the kernel address space.
    @param atAddress If a placed mapping is requested, atAddress specifies its address, and the kIOMapAnywhere should not be set. Otherwise, atAddress is ignored.
    @param options Mapping options are defined in IOTypes.h,<br>
	kIOMapAnywhere should be passed if the mapping can be created anywhere. If not set, the atAddress parameter sets the location of the mapping, if it is available in the target map.<br>
	kIOMapDefaultCache to inhibit the cache in I/O areas, kIOMapCopybackCache in general purpose RAM.<br>
	kIOMapInhibitCache, kIOMapWriteThruCache, kIOMapCopybackCache to set the appropriate caching.<br>
	kIOMapReadOnly to allow only read only accesses to the memory - writes will cause and access fault.<br>
	kIOMapReference will only succeed if the mapping already exists, and the IOMemoryMap object is just an extra reference, ie. no new mapping will be created.<br>
    @param offset Is a beginning offset into the IOMemoryDescriptor's memory where the mapping starts. Zero is the default to map all the memory.
    @param length Is the length of the mapping requested for a subset of the IOMemoryDescriptor. Zero is the default to map all the memory.
    @result A reference to an IOMemoryMap object representing the mapping, which can supply the virtual address of the mapping and other information. The mapping may be shared with multiple callers - multiple maps are avoided if a compatible one exists. The IOMemoryMap object returned should be released only when the caller has finished accessing the mapping, as freeing the object destroys the mapping. The IOMemoryMap instance also retains the IOMemoryDescriptor it maps while it exists. */

    virtual IOMemoryMap * 	map(
	task_t		intoTask,
	IOVirtualAddress	atAddress,
	IOOptionBits		options,
	IOByteCount		offset = 0,
	IOByteCount		length = 0 );

/*! @function map
    @abstract Maps a IOMemoryDescriptor into the kernel map.
    @discussion This is a shortcut method to map all the memory described by a memory descriptor into the kernel map at any available address. See the full version of the map method for further details.
    @param options Mapping options as in the full version of the map method, with kIOMapAnywhere assumed.
    @result See the full version of the map method. */

    virtual IOMemoryMap * 	map(
	IOOptionBits		options = 0 );

/*! @function setMapping
    @abstract Establishes an already existing mapping.
    @discussion This method tells the IOMemoryDescriptor about a mapping that exists, but was created elsewhere. It allows later callers of the map method to share this externally created mapping. The IOMemoryMap object returned is created to represent it. This method is not commonly needed.
    @param task Address space in which the mapping exists.
    @param mapAddress Virtual address of the mapping.
    @param options Caching and read-only attributes of the mapping.
    @result A IOMemoryMap object created to represent the mapping. */

    virtual IOMemoryMap * 	setMapping(
	task_t		task,
	IOVirtualAddress	mapAddress,
	IOOptionBits		options = 0 );

    // Following methods are private implementation

    // make virtual
    IOReturn redirect( task_t safeTask, bool redirect );

protected:
    virtual IOMemoryMap * 	makeMapping(
	IOMemoryDescriptor *	owner,
	task_t		intoTask,
	IOVirtualAddress	atAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length );

    virtual void 		addMapping(
	IOMemoryMap *		mapping );

    virtual void 		removeMapping(
	IOMemoryMap *		mapping );

    virtual IOReturn doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset = 0,
	IOByteCount		length = 0 );

    virtual IOReturn doUnmap(
	vm_map_t		addressMap,
	IOVirtualAddress	logical,
	IOByteCount		length );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*! @class IOMemoryMap : public OSObject
    @abstract An abstract base class defining common methods for describing a memory mapping.
    @discussion The IOMemoryMap object represents a mapped range of memory, described by a IOMemoryDescriptor. The mapping may be in the kernel or a non-kernel task and has processor cache mode attributes. IOMemoryMap instances are created by IOMemoryDescriptor when it creates mappings in its map method, and returned to the caller. */

class IOMemoryMap : public OSObject
{
    OSDeclareAbstractStructors(IOMemoryMap)

public:
/*! @function getVirtualAddress
    @abstract Accessor to the virtual address of the first byte in the mapping.
    @discussion This method returns the virtual address of the first byte in the mapping.
    @result A virtual address. */

    virtual IOVirtualAddress 	getVirtualAddress() = 0;

/*! @function getPhysicalSegment
    @abstract Break a mapping into its physically contiguous segments.
    @discussion This method returns the physical address of the byte at the given offset into the mapping, and optionally the length of the physically contiguous segment from that offset. It functions similarly to IOMemoryDescriptor::getPhysicalSegment.
    @param offset A byte offset into the mapping whose physical address to return.
    @param length If non-zero, getPhysicalSegment will store here the length of the physically contiguous segement at the given offset.
    @result A physical address, or zero if the offset is beyond the length of the mapping. */

    virtual IOPhysicalAddress 	getPhysicalSegment(IOByteCount offset,
	       					   IOByteCount * length) = 0;

/*! @function getPhysicalAddress
    @abstract Return the physical address of the first byte in the mapping.
    @discussion This method returns the physical address of the  first byte in the mapping. It is most useful on mappings known to be physically contiguous.
    @result A physical address. */

    inline IOPhysicalAddress 	getPhysicalAddress()
				{ return( getPhysicalSegment( 0, 0 )); }

/*! @function getLength
    @abstract Accessor to the length of the mapping.
    @discussion This method returns the length of the mapping.
    @result A byte count. */

    virtual IOByteCount 	getLength() = 0;

/*! @function getAddressTask
    @abstract Accessor to the task of the mapping.
    @discussion This method returns the mach task the mapping exists in.
    @result A mach task_t. */

    virtual task_t		getAddressTask() = 0;

/*! @function getMemoryDescriptor
    @abstract Accessor to the IOMemoryDescriptor the mapping was created from.
    @discussion This method returns the IOMemoryDescriptor the mapping was created from.
    @result An IOMemoryDescriptor reference, which is valid while the IOMemoryMap object is retained. It should not be released by the caller. */

    virtual IOMemoryDescriptor * getMemoryDescriptor() = 0;

/*! @function getMapOptions
    @abstract Accessor to the options the mapping was created with.
    @discussion This method returns the options to IOMemoryDescriptor::map the mapping was created with.
    @result Options for the mapping, including cache settings. */

    virtual IOOptionBits 	getMapOptions() = 0;

/*! @function unmap
    @abstract Force the IOMemoryMap to unmap, without destroying the object.
    @discussion IOMemoryMap instances will unmap themselves upon free, ie. when the last client with a reference calls release. This method forces the IOMemoryMap to destroy the mapping it represents, regardless of the number of clients. It is not generally used.
    @result An IOReturn code. */

    virtual IOReturn 		unmap() = 0;

    virtual void 			taskDied() = 0;
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// The following classes are private implementation of IOMemoryDescriptor - they
// should not be reference directly, just through the public API's in the 
// IOMemoryDescriptor class.

enum {
    kIOMemoryRequiresWire	= 0x00000001
};

class IOGeneralMemoryDescriptor : public IOMemoryDescriptor
{
    OSDeclareDefaultStructors(IOGeneralMemoryDescriptor);

protected:
    union {
    IOVirtualRange *	v;
    IOPhysicalRange *	p;
    }			_ranges;            /* list of address ranges */
    unsigned		_rangesCount;       /* number of address ranges in list */
    bool		_rangesIsAllocated; /* is list allocated by us? */

    task_t		_task;               /* task where all ranges are mapped to */

    union {
    IOVirtualRange	v;
    IOPhysicalRange	p;
    }			_singleRange;	   /* storage space for a single range */

    unsigned		_wireCount;        /* number of outstanding wires */

    vm_address_t	_cachedVirtualAddress;  /* a cached virtual-to-physical */
    IOPhysicalAddress	_cachedPhysicalAddress; /*    mapping, for optimization */

    bool		_initialized;      /* has superclass been initialized? */

    virtual void free();

protected: /* (to be deprecated) */
    IOByteCount		_position;         /* absolute position over all ranges */
    virtual void setPosition(IOByteCount position);

private:
    unsigned		_positionAtIndex;  /* range #n in which position is now */
    IOByteCount		_positionAtOffset; /* relative position within range #n */
    OSData *_memoryEntries;

    vm_offset_t _kernPtrAligned;
    unsigned    _kernPtrAtIndex;
    IOByteCount  _kernSize;
    virtual void mapIntoKernel(unsigned rangeIndex);
    virtual void unmapFromKernel();
    inline vm_map_t getMapForTask( task_t task, vm_address_t address );

public:
    /*
     * IOMemoryDescriptor required methods
     */

    virtual bool initWithAddress(void *       address,
                                 IOByteCount    withLength,
                                 IODirection  withDirection);

    virtual bool initWithAddress(vm_address_t address,
                                 IOByteCount    withLength,
                                 IODirection  withDirection,
                                 task_t       withTask);

    virtual bool initWithPhysicalAddress(
				 IOPhysicalAddress	address,
				 IOByteCount		withLength,
				 IODirection      	withDirection );

    virtual bool initWithRanges(        IOVirtualRange * ranges,
                                        UInt32           withCount,
                                        IODirection      withDirection,
                                        task_t           withTask,
                                        bool             asReference = false);

    virtual bool initWithPhysicalRanges(IOPhysicalRange * ranges,
                                        UInt32           withCount,
                                        IODirection      withDirection,
                                        bool             asReference = false);

    virtual IOByteCount readBytes(IOByteCount offset,
				void * bytes, IOByteCount withLength);

    virtual IOByteCount writeBytes(IOByteCount offset,
				const void * bytes, IOByteCount withLength);

    virtual IOPhysicalAddress getPhysicalSegment(IOByteCount offset,
						 IOByteCount * length);

    virtual void * getVirtualSegment(IOByteCount offset,
					IOByteCount * length);

    virtual IOReturn prepare(IODirection forDirection = kIODirectionNone);

    virtual IOReturn complete(IODirection forDirection = kIODirectionNone);

    virtual IOReturn doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset = 0,
	IOByteCount		length = 0 );

    virtual IOReturn doUnmap(
	vm_map_t		addressMap,
	IOVirtualAddress	logical,
	IOByteCount		length );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOSubMemoryDescriptor : public IOMemoryDescriptor
{
    friend IOMemoryDescriptor;

    OSDeclareDefaultStructors(IOSubMemoryDescriptor);

protected:
    IOMemoryDescriptor * _parent;
    IOByteCount 	 _start;

    virtual void free();

    virtual bool initSubRange( IOMemoryDescriptor * parent,
				IOByteCount offset, IOByteCount length,
				IODirection withDirection );

    virtual bool initWithAddress(void *       address,
                                 IOByteCount    withLength,
                                 IODirection  withDirection);

    virtual bool initWithAddress(vm_address_t address,
                                 IOByteCount    withLength,
                                 IODirection  withDirection,
                                 task_t       withTask);

    virtual bool initWithPhysicalAddress(
				 IOPhysicalAddress	address,
				 IOByteCount		withLength,
				 IODirection      	withDirection );

    virtual bool initWithRanges(        IOVirtualRange * ranges,
                                        UInt32           withCount,
                                        IODirection      withDirection,
                                        task_t           withTask,
                                        bool             asReference = false);

    virtual bool initWithPhysicalRanges(IOPhysicalRange * ranges,
                                        UInt32           withCount,
                                        IODirection      withDirection,
                                        bool             asReference = false);

    IOMemoryDescriptor::withAddress;
    IOMemoryDescriptor::withPhysicalAddress;
    IOMemoryDescriptor::withPhysicalRanges;
    IOMemoryDescriptor::withRanges;
    IOMemoryDescriptor::withSubRange;

public:
    /*
     * IOMemoryDescriptor required methods
     */

    virtual IOPhysicalAddress getPhysicalSegment(IOByteCount offset,
						 IOByteCount * length);

    virtual IOByteCount readBytes(IOByteCount offset,
				void * bytes, IOByteCount withLength);

    virtual IOByteCount writeBytes(IOByteCount offset,
				const void * bytes, IOByteCount withLength);

    virtual void * getVirtualSegment(IOByteCount offset,
					IOByteCount * length);

    virtual IOReturn prepare(IODirection forDirection = kIODirectionNone);

    virtual IOReturn complete(IODirection forDirection = kIODirectionNone);

    // make virtual
    IOReturn redirect( task_t safeTask, bool redirect );

protected:
    virtual IOMemoryMap * 	makeMapping(
	IOMemoryDescriptor *	owner,
	task_t		intoTask,
	IOVirtualAddress	atAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#endif /* !_IOMEMORYDESCRIPTOR_H */
