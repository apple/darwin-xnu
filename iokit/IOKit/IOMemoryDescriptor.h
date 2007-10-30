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
#ifndef _IOMEMORYDESCRIPTOR_H
#define _IOMEMORYDESCRIPTOR_H

#include <sys/cdefs.h>

#include <IOKit/IOTypes.h>
#include <libkern/c++/OSContainers.h>

__BEGIN_DECLS
#include <mach/memory_object_types.h>
__END_DECLS

struct IOPhysicalRange
{
    IOPhysicalAddress	address;
    IOByteCount		length;
};

class IOMemoryMap;
class IOMapper;

/*
 * Direction of transfer, with respect to the described memory.
 */
enum IODirection
{
    kIODirectionNone  = 0x0,	//                    same as VM_PROT_NONE
    kIODirectionIn    = 0x1,	// User land 'read',  same as VM_PROT_READ
    kIODirectionOut   = 0x2,	// User land 'write', same as VM_PROT_WRITE
    kIODirectionOutIn = kIODirectionOut | kIODirectionIn,
    kIODirectionInOut = kIODirectionIn  | kIODirectionOut
};

/*
 * IOOptionBits used in the withOptions variant
 */
enum {
    kIOMemoryDirectionMask	= 0x00000007,
    kIOMemoryAutoPrepare	= 0x00000008,	// Shared with Buffer MD
    
    kIOMemoryTypeVirtual	= 0x00000010,
    kIOMemoryTypePhysical	= 0x00000020,
    kIOMemoryTypeUPL		= 0x00000030,
    kIOMemoryTypePersistentMD	= 0x00000040,	// Persistent Memory Descriptor
    kIOMemoryTypeUIO		= 0x00000050,
    kIOMemoryTypeMask		= 0x000000f0,

    kIOMemoryAsReference	= 0x00000100,
    kIOMemoryBufferPageable	= 0x00000400,
    kIOMemoryDontMap		= 0x00000800,
    kIOMemoryPersistent		= 0x00010000
};

#define kIOMapperNone	((IOMapper *) -1)
#define kIOMapperSystem	((IOMapper *) 0)

enum 
{
    kIOMemoryPurgeableKeepCurrent = 1,
    kIOMemoryPurgeableNonVolatile = 2,
    kIOMemoryPurgeableVolatile    = 3,
    kIOMemoryPurgeableEmpty       = 4
};
enum 
{
    kIOMemoryIncoherentIOFlush	 = 1,
    kIOMemoryIncoherentIOStore	 = 2,
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
    struct ExpansionData {
        void *				devicePager;
        unsigned int			pagerContig:1;
        unsigned int			unused:31;
	IOMemoryDescriptor *		memory;
    };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

protected:
    OSSet *		_mappings;
    IOOptionBits 	_flags;
    void *		_memEntry;

    IODirection         _direction;        /* DEPRECATED: use _flags instead. direction of transfer */
    IOByteCount         _length;           /* length of all ranges */
    IOOptionBits 	_tag;

public:

    virtual IOPhysicalAddress getSourceSegment( IOByteCount offset,
						IOByteCount * length );
    OSMetaClassDeclareReservedUsed(IOMemoryDescriptor, 0);

/*! @function initWithOptions
    @abstract Master initialiser for all variants of memory descriptors.  For a more complete description see IOMemoryDescriptor::withOptions.
    @discussion Note this function can be used to re-init a previously created memory descriptor.
    @result true on success, false on failure. */
    virtual bool initWithOptions(void *		buffers,
                                 UInt32		count,
                                 UInt32		offset,
                                 task_t		task,
                                 IOOptionBits	options,
                                 IOMapper *	mapper = 0);
    OSMetaClassDeclareReservedUsed(IOMemoryDescriptor, 1);

    virtual addr64_t getPhysicalSegment64( IOByteCount offset,
                                            IOByteCount * length );
    OSMetaClassDeclareReservedUsed(IOMemoryDescriptor, 2);


/*! @function setPurgeable
    @abstract Control the purgeable status of a memory descriptors memory.
    @discussion Buffers may be allocated with the ability to have their purgeable status changed - IOBufferMemoryDescriptor with the kIOMemoryPurgeable option, VM_FLAGS_PURGEABLE may be passed to vm_allocate() in user space to allocate such buffers. The purgeable status of such a buffer may be controlled with setPurgeable(). The process of making a purgeable memory descriptor non-volatile and determining its previous state is atomic - if a purgeable memory descriptor is made nonvolatile and the old state is returned as kIOMemoryPurgeableVolatile, then the memory's previous contents are completely intact and will remain so until the memory is made volatile again.  If the old state is returned as kIOMemoryPurgeableEmpty then the memory was reclaimed while it was in a volatile state and its previous contents have been lost.
    @param newState - the desired new purgeable state of the memory:<br>
    kIOMemoryPurgeableKeepCurrent - make no changes to the memory's purgeable state.<br>
    kIOMemoryPurgeableVolatile    - make the memory volatile - the memory may be reclaimed by the VM system without saving its contents to backing store.<br>
    kIOMemoryPurgeableNonVolatile - make the memory nonvolatile - the memory is treated as with usual allocations and must be saved to backing store if paged.<br>
    kIOMemoryPurgeableEmpty       - make the memory volatile, and discard any pages allocated to it.
    @param oldState - if non-NULL, the previous purgeable state of the memory is returned here:<br>
    kIOMemoryPurgeableNonVolatile - the memory was nonvolatile.<br>
    kIOMemoryPurgeableVolatile    - the memory was volatile but its content has not been discarded by the VM system.<br>
    kIOMemoryPurgeableEmpty       - the memory was volatile and has been discarded by the VM system.<br>
    @result An IOReturn code. */

    virtual IOReturn setPurgeable( IOOptionBits newState,
                                    IOOptionBits * oldState );
    OSMetaClassDeclareReservedUsed(IOMemoryDescriptor, 3);

/*! @function performOperation
    @abstract Perform an operation on the memory descriptor's memory.
    @discussion This method performs some operation on a range of the memory descriptor's memory. When a memory descriptor's memory is not mapped, it should be more efficient to use this method than mapping the memory to perform the operation virtually.
    @param options The operation to perform on the memory:<br>
    kIOMemoryIncoherentIOFlush - pass this option to store to memory and flush any data in the processor cache for the memory range, with synchronization to ensure the data has passed through all levels of processor cache. It may not be supported on all architectures. This type of flush may be used for non-coherent I/O such as AGP - it is NOT required for PCI coherent operations. The memory descriptor must have been previously prepared.<br>
    kIOMemoryIncoherentIOStore - pass this option to store to memory any data in the processor cache for the memory range, with synchronization to ensure the data has passed through all levels of processor cache. It may not be supported on all architectures. This type of flush may be used for non-coherent I/O such as AGP - it is NOT required for PCI coherent operations. The memory descriptor must have been previously prepared.
    @param offset A byte offset into the memory descriptor's memory.
    @param length The length of the data range.
    @result An IOReturn code. */

    virtual IOReturn performOperation( IOOptionBits options,
                                        IOByteCount offset, IOByteCount length );
    OSMetaClassDeclareReservedUsed(IOMemoryDescriptor, 4);

private:

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

     static IOMemoryDescriptor * withRanges(IOVirtualRange * ranges,
                                            UInt32           withCount,
                                            IODirection      withDirection,
                                            task_t           withTask,
                                            bool             asReference = false);

/*! @function withOptions
    @abstract Master initialiser for all variants of memory descriptors.
    @discussion This method creates and initializes an IOMemoryDescriptor for memory it has three main variants: Virtual, Physical & mach UPL.  These variants are selected with the options parameter, see below.  This memory descriptor needs to be prepared before it can be used to extract data from the memory described.  However we temporarily have setup a mechanism that automatically prepares kernel_task memory descriptors at creation time.


    @param buffers A pointer to an array of IOVirtualRanges or IOPhysicalRanges if the options:type is Virtual or Physical.  For type UPL it is a upl_t returned by the mach/memory_object_types.h apis, primarily used internally by the UBC.

    @param count options:type = Virtual or Physical count contains a count of the number of entires in the buffers array.  For options:type = UPL this field contains a total length.

    @param offset Only used when options:type = UPL, in which case this field contains an offset for the memory within the buffers upl.

    @param task Only used options:type = Virtual, The task each of the virtual ranges are mapped into.

    @param options
        kIOMemoryDirectionMask (options:direction)	This nibble indicates the I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures. 
        kIOMemoryTypeMask (options:type)	kIOMemoryTypeVirtual, kIOMemoryTypePhysical, kIOMemoryTypeUPL Indicates that what type of memory basic memory descriptor to use.  This sub-field also controls the interpretation of the buffers, count, offset & task parameters.
        kIOMemoryAsReference	For options:type = Virtual or Physical this indicate that the memory descriptor need not copy the ranges array into local memory.  This is an optimisation to try to minimise unnecessary allocations.
        kIOMemoryBufferPageable	Only used by the IOBufferMemoryDescriptor as an indication that the kernel virtual memory is in fact pageable and we need to use the kernel pageable submap rather than the default map.
        kIOMemoryNoAutoPrepare	Indicates that the temporary AutoPrepare of kernel_task memory should not be performed.
    
    @param mapper Which IOMapper should be used to map the in-memory physical addresses into I/O space addresses.  Defaults to 0 which indicates that the system mapper is to be used, if present.  

    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor *withOptions(void *	buffers,
                                           UInt32	count,
                                           UInt32	offset,
                                           task_t	task,
                                           IOOptionBits	options,
                                           IOMapper *	mapper = 0);

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
                                            IODirection 	withDirection,
                                            bool		asReference = false);

/*! @function withSubRange
    @abstract Create an IOMemoryDescriptor to describe a subrange of an existing descriptor.
    @discussion  This method creates and initializes an IOMemoryDescriptor for memory consisting of a subrange of the specified memory descriptor. The parent memory descriptor is retained by the new descriptor.
    @param of The parent IOMemoryDescriptor of which a subrange is to be used for the new descriptor, which will be retained by the subrange IOMemoryDescriptor.
    @param offset A byte offset into the parent memory descriptor's memory.
    @param length The length of the subrange.
    @param withDirection An I/O direction to be associated with the descriptor, which may affect the operation of the prepare and complete methods on some architectures. This is used over the direction of the parent descriptor.
    @result The created IOMemoryDescriptor on success, to be released by the caller, or zero on failure. */

    static IOMemoryDescriptor *	withSubRange(IOMemoryDescriptor *of,
					     IOByteCount offset,
					     IOByteCount length,
                                             IODirection withDirection);

/*! @function withPersistentMemoryDescriptor
    @abstract Copy constructor that generates a new memory descriptor if the backing memory for the same task's virtual address and length has changed.
    @discussion If the original memory descriptor's address and length is still backed by the same real memory, i.e. the user hasn't deallocated and the reallocated memory at the same address then the original memory descriptor is returned with a additional reference.  Otherwise we build a totally new memory descriptor with the same characteristics as the previous one but with a new view of the vm.  Note not legal to call this function with anything except an IOGeneralMemoryDescriptor that was created with the kIOMemoryPersistent option.
    @param originalMD The memory descriptor to be duplicated.
    @result Either the original memory descriptor with an additional retain or a new memory descriptor, 0 for a bad original memory descriptor or some other resource shortage. */
    static IOMemoryDescriptor *
	withPersistentMemoryDescriptor(IOMemoryDescriptor *originalMD);

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

    virtual bool initWithRanges(IOVirtualRange * ranges,
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
				void * bytes, IOByteCount withLength);

/*! @function writeBytes
    @abstract Copy data to the memory descriptor's buffer from the specified buffer.
    @discussion This method copies data to the memory descriptor's memory at the given offset, from the caller's buffer.
    @param offset A byte offset into the memory descriptor's memory.
    @param bytes The caller supplied buffer to copy the data from.
    @param withLength The length of the data to copy.
    @result The number of bytes copied, zero will be returned if the specified offset is beyond the length of the descriptor. */

    virtual IOByteCount writeBytes(IOByteCount offset,
				const void * bytes, IOByteCount withLength);

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

    /* inline */ IOPhysicalAddress getPhysicalAddress();
        /* { return( getPhysicalSegment( 0, 0 )); } */

    /* DEPRECATED */ /* USE INSTEAD: map(), readBytes(), writeBytes() */
    /* DEPRECATED */ virtual void * getVirtualSegment(IOByteCount offset,
    /* DEPRECATED */					IOByteCount * length) = 0;
    /* DEPRECATED */ /* USE INSTEAD: map(), readBytes(), writeBytes() */

/*! @function prepare
    @abstract Prepare the memory for an I/O transfer.
    @discussion This involves paging in the memory, if necessary, and wiring it down for the duration of the transfer.  The complete() method completes the processing of the memory after the I/O transfer finishes.  Note that the prepare call is not thread safe and it is expected that the client will more easily be able to guarantee single threading a particular memory descriptor.
    @param forDirection The direction of the I/O just completed, or kIODirectionNone for the direction specified by the memory descriptor.
    @result An IOReturn code. */

    virtual IOReturn prepare(IODirection forDirection = kIODirectionNone) = 0;

/*! @function complete
    @abstract Complete processing of the memory after an I/O transfer finishes.
    @discussion This method should not be called unless a prepare was previously issued; the prepare() and complete() must occur in pairs, before and after an I/O transfer involving pageable memory.  In 10.3 or greater systems the direction argument to complete is not longer respected.  The direction is totally determined at prepare() time.
    @param forDirection DEPRECATED The direction of the I/O just completed, or kIODirectionNone for the direction specified by the memory descriptor.
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
	kIOMapUnique allows a special kind of mapping to be created that may be used with the IOMemoryMap::redirect() API. These mappings will not be shared as is the default - there will always be a unique mapping created for the caller, not an existing mapping with an extra reference.<br>
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

    IOReturn handleFault(
        void *			pager,
	vm_map_t		addressMap,
	IOVirtualAddress	address,
	IOByteCount		sourceOffset,
	IOByteCount		length,
        IOOptionBits		options );

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

    /* inline */ IOPhysicalAddress getPhysicalAddress();
        /* { return( getPhysicalSegment( 0, 0 )); } */

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

    virtual void		taskDied() = 0;

/*! @function redirect
    @abstract Replace the memory mapped in a process with new backing memory.
    @discussion An IOMemoryMap created with the kIOMapUnique option to IOMemoryDescriptor::map() can remapped to a new IOMemoryDescriptor backing object. If the new IOMemoryDescriptor is specified as NULL, client access to the memory map is blocked until a new backing object has been set. By blocking access and copying data, the caller can create atomic copies of the memory while the client is potentially reading or writing the memory. 
    @param newBackingMemory The IOMemoryDescriptor that represents the physical memory that is to be now mapped in the virtual range the IOMemoryMap represents. If newBackingMemory is NULL, any access to the mapping will hang (in vm_fault()) until access has been restored by a new call to redirect() with non-NULL newBackingMemory argument.
    @param options Mapping options are defined in IOTypes.h, and are documented in IOMemoryDescriptor::map()
    @param offset As with IOMemoryDescriptor::map(), a beginning offset into the IOMemoryDescriptor's memory where the mapping starts. Zero is the default.
    @result An IOReturn code. */

    virtual IOReturn		redirect(IOMemoryDescriptor * newBackingMemory,
					 IOOptionBits         options,
					 IOByteCount          offset = 0) = 0;
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// The following classes are private implementation of IOMemoryDescriptor - they
// should not be referenced directly, just through the public API's in the 
// IOMemoryDescriptor class. For example, an IOGeneralMemoryDescriptor instance
// might be created by IOMemoryDescriptor::withAddress(), but there should be 
// no need to reference as anything but a generic IOMemoryDescriptor *.

// Also these flags should not overlap with the options to
//	IOMemoryDescriptor::initWithRanges(... IOOptionsBits options);

enum {
    kIOMemoryPreparedReadOnly	= 0x00008000,
};

class IOGeneralMemoryDescriptor : public IOMemoryDescriptor
{
    OSDeclareDefaultStructors(IOGeneralMemoryDescriptor);

public:
    union Ranges {
        IOVirtualRange *  v;
        IOPhysicalRange * p;
	void 		 *uio;
    };
protected:
    Ranges		_ranges;
    unsigned		_rangesCount;       /* number of address ranges in list */
    bool		_rangesIsAllocated; /* is list allocated by us? */

    task_t		_task;               /* task where all ranges are mapped to */

    union {
        IOVirtualRange	v;
        IOPhysicalRange	p;
    }			_singleRange;	   /* storage space for a single range */

    unsigned		_wireCount;        /* number of outstanding wires */

    /* DEPRECATED */ vm_address_t _cachedVirtualAddress;  /* a cached virtual-to-physical */

    /* DEPRECATED */ IOPhysicalAddress	_cachedPhysicalAddress;

    bool		_initialized;      /* has superclass been initialized? */

    virtual void free();


private:
    // Internal APIs may be made virtual at some time in the future.
    IOReturn wireVirtual(IODirection forDirection);
    void *createNamedEntry();	


    /* DEPRECATED */ IOByteCount _position; /* absolute position over all ranges */
    /* DEPRECATED */ virtual void setPosition(IOByteCount position);

/*
 * DEPRECATED IOByteCount _positionAtIndex; // relative position within range #n
 *
 * Re-use the _positionAtIndex as a count of the number of pages in
 * this memory descriptor.  Convieniently vm_address_t is an unsigned integer
 * type so I can get away without having to change the type.
 */
    unsigned int		_pages;

/* DEPRECATED */ unsigned    _positionAtOffset;  //range #n in which position is now

    OSData *_memoryEntries;

    /* DEPRECATED */ vm_offset_t _kernPtrAligned;
    /* DEPRECATED */ unsigned    _kernPtrAtIndex;
    /* DEPRECATED */ IOByteCount  _kernSize;

    /* DEPRECATED */ virtual void mapIntoKernel(unsigned rangeIndex);
    /* DEPRECATED */ virtual void unmapFromKernel();

public:
    /*
     * IOMemoryDescriptor required methods
     */

    // Master initaliser
    virtual bool initWithOptions(void *		buffers,
                                 UInt32		count,
                                 UInt32		offset,
                                 task_t		task,
                                 IOOptionBits	options,
                                 IOMapper *	mapper = 0);

    // Secondary initialisers
    virtual bool initWithAddress(void *		address,
                                 IOByteCount	withLength,
                                 IODirection	withDirection);

    virtual bool initWithAddress(vm_address_t	address,
                                 IOByteCount    withLength,
                                 IODirection	withDirection,
                                 task_t		withTask);

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

    virtual IOPhysicalAddress getPhysicalSegment(IOByteCount offset,
						 IOByteCount * length);

    virtual IOPhysicalAddress getSourceSegment(IOByteCount offset,
                                               IOByteCount * length);

    /* DEPRECATED */ virtual void * getVirtualSegment(IOByteCount offset,
    /* DEPRECATED */					IOByteCount * length);

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
    virtual bool serialize(OSSerialize *s) const;

    // Factory method for cloning a persistent IOMD, see IOMemoryDescriptor
    static IOMemoryDescriptor *
	withPersistentMemoryDescriptor(IOGeneralMemoryDescriptor *originalMD);
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOSubMemoryDescriptor : public IOMemoryDescriptor
{
    friend class IOMemoryDescriptor;

    OSDeclareDefaultStructors(IOSubMemoryDescriptor);

protected:
    IOMemoryDescriptor * _parent;
    IOByteCount 	 _start;

    virtual void free();

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
     * Initialize or reinitialize an IOSubMemoryDescriptor to describe
     * a subrange of an existing descriptor.
     *
     * An IOSubMemoryDescriptor can be re-used by calling initSubRange
     * again on an existing instance -- note that this behavior is not
     * commonly supported in other IOKit classes, although it is here.
     */
    virtual bool initSubRange( IOMemoryDescriptor * parent,
				IOByteCount offset, IOByteCount length,
				IODirection withDirection );

    /*
     * IOMemoryDescriptor required methods
     */

    virtual IOPhysicalAddress getPhysicalSegment(IOByteCount offset,
						 IOByteCount * length);

    virtual IOPhysicalAddress getSourceSegment(IOByteCount offset,
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

    virtual bool serialize(OSSerialize *s) const;

    virtual IOReturn setPurgeable( IOOptionBits newState,
                                    IOOptionBits * oldState );
    virtual IOReturn performOperation( IOOptionBits options,
                                        IOByteCount offset, IOByteCount length );

protected:
    virtual IOMemoryMap * 	makeMapping(
	IOMemoryDescriptor *	owner,
	task_t		intoTask,
	IOVirtualAddress	atAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length );

    virtual IOReturn doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset = 0,
	IOByteCount		length = 0 );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#endif /* !_IOMEMORYDESCRIPTOR_H */
